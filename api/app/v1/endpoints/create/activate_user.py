# Copyright 2025 SUPSI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""POST /Users/{id}/activate  — Admin activation of pending OIDC users.

Flow
----
1. Verify caller is an ``administrator``.
2. Load the target user row; confirm it is currently in the ``pending`` state.
3. Resolve the target role: the request body's ``role`` if given, else the
   ``requested_role`` the applicant stated at ``/auth/{provider}/login``
   (see oidc_login.py); validate whichever one wins via
   ``validate_rbac_role``.
4. Within a single transaction:
   a. UPDATE sensorthings."User".role  → target role.
   b. Apply the appropriate RLS policy function for the target role.

Architecture note
-----------------
istSOS users are application-level entities; they do NOT have individual
PostgreSQL login roles.  Activation is therefore a pure application-state
mutation: an UPDATE on the role column plus an RLS policy call.  No
``CREATE ROLE``, ``GRANT``, or other DDL is issued.
"""

import logging

from app import NETWORK, POSTGRES_PORT_WRITE
from app.db.asyncpg_db import get_pool, get_pool_w
from app.db.audit_crud import AUDIT_ACTION_ADMIN_APPROVAL, log_audit_event
from app.models.error import MessageError
from app.oauth import get_current_user
from app.rbac_roles import PENDING_ROLE, validate_rbac_role
from app.v1.endpoints.openapi_responses import (
    DB_TIMEOUT,
    DB_UNAVAILABLE,
    INTERNAL,
    MSG_FORBIDDEN_DB,
    MSG_UNAUTHORIZED,
    merge,
    response,
)
from asyncpg.exceptions import (
    InsufficientPrivilegeError,
    PostgresConnectionError,
    QueryCanceledError,
    TooManyConnectionsError,
)
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse

v1 = APIRouter()
logger = logging.getLogger(__name__)

ACTIVATE_PAYLOAD_EXAMPLE = {
    # role: one of viewer, editor, obs_manager, sensor, qc, custom.
    #   Omit to use whatever the applicant requested at
    #   /auth/{provider}/login.
    # dataset: optional Network name to scope the user to. Omit to keep the
    #   applicant's requested value; "" to clear any scope.
    "role": "viewer",
    "dataset": "IDROLOGIA",
}


@v1.api_route(
    "/Users/{user_id}/activate",
    methods=["POST"],
    tags=["Registration & Approval"],
    summary="Activate a pending OIDC user",
    description=(
        "Promote a user from the 'pending' waiting room to a fully active "
        "role. `role` is optional -- omit it to activate with the role the "
        "applicant requested at login; supply it to override. "
        "Applies Row-Level Security policies for the assigned role. "
        "Only accessible by an administrator.  No PostgreSQL DDL is issued."
    ),
    status_code=status.HTTP_200_OK,
    responses=merge(
        {
            200: response(
                MessageError,
                "Activated with the requested role.",
                {"message": "User 'jdoe' has been activated with role 'viewer'."},
            ),
            # Two distinct causes share 400: an unrecognised role string, or
            # a rejected applicant (role stays 'pending' by design, so the
            # pending/404 checks alone wouldn't catch this).
            400: response(
                MessageError,
                "Either the requested role isn't one of the assignable "
                "roles, or the user's registration was rejected and must "
                "be re-applied via POST /Register instead.",
                {
                    "message": "Role 'foo' is not one of the assignable "
                    "roles."
                },
            ),
        },
        MSG_UNAUTHORIZED,
        MSG_FORBIDDEN_DB,
        {
            404: response(
                MessageError,
                "No user exists with that id.",
                {"message": "User with id=42 not found."},
            ),
            409: response(
                MessageError,
                "The target user is not currently 'pending' -- already "
                "activated, or otherwise not eligible.",
                {"message": "User 'jdoe' is not pending (current role: 'viewer')."},
            ),
        },
        DB_UNAVAILABLE,
        DB_TIMEOUT,
        INTERNAL,
    ),
)
async def activate_user(
    user_id: int,
    payload: dict = Body(examples=[ACTIVATE_PAYLOAD_EXAMPLE]),
    current_user=Depends(get_current_user),
    pgpool=Depends(get_pool_w) if POSTGRES_PORT_WRITE else Depends(get_pool),
):
    # ------------------------------------------------------------------
    # 1. Authorization: only administrators may activate users.
    # ------------------------------------------------------------------
    if current_user["role"] != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can activate pending users.",
        )

    try:
        async with pgpool.acquire() as conn:
            # ----------------------------------------------------------
            # 2. Fetch the target user and assert they are 'pending'.
            #    Fetched before role validation, not after, because
            #    resolving the target role needs requested_role off this
            #    same row -- see step 3.
            # ----------------------------------------------------------
            user_row = await conn.fetchrow(
                """
                SELECT id, username, role, status, dataset_id, requested_role,
                    auth_provider
                FROM sensorthings."User"
                WHERE id = $1
                """,
                user_id,
            )

            if user_row is None:
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content={"message": f"User with id={user_id} not found."},
                )

            if user_row["role"] != PENDING_ROLE:
                return JSONResponse(
                    status_code=status.HTTP_409_CONFLICT,
                    content={
                        "message": (
                            f"User '{user_row['username']}' is not pending "
                            f"(current role: '{user_row['role']}')."
                        )
                    },
                )

            # Rejection is a status transition, not a role change — a
            # rejected user still has role='pending' by design, so the
            # guard above alone wouldn't catch this. See the identical
            # guard in update/admin_approval.py.
            if user_row["status"] == "rejected":
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "message": (
                            f"User '{user_row['username']}'s registration "
                            "was rejected and cannot be activated directly. "
                            "They must re-apply via POST /Register first."
                        )
                    },
                )

            username = user_row["username"]

            # ----------------------------------------------------------
            # 3. Resolve and validate the target role. payload["role"] is
            #    the administrator's explicit choice and always wins;
            #    omitting it falls back to what the applicant asked for
            #    at /auth/{provider}/login (see oidc_login.py).
            # ----------------------------------------------------------
            target_role_raw = payload.get("role") or user_row["requested_role"]
            if not target_role_raw:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "message": (
                            f"User '{username}' did not request a role at "
                            "login, so 'role' must be specified explicitly "
                            "in the request body."
                        )
                    },
                )
            try:
                target_role = validate_rbac_role(target_role_raw)
            except ValueError as exc:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"message": str(exc)},
                )

            # ----------------------------------------------------------
            # 4. All mutations inside a single transaction so any
            #    failure leaves the user still 'pending' (no half-state).
            # ----------------------------------------------------------
            async with conn.transaction():

                # 4a. Promote the application-layer role in the User table.
                #     Pure parameterised UPDATE — no DDL.
                #
                #     No per-activation RLS call: every assignable role's
                #     access is enforced by the static policies created
                #     once by 006_session_scoped_rls_policies.sql, keyed on
                #     the app.current_user_id session claim. A 'custom'
                #     user gets standard group access; any narrower rule is
                #     added later via POST /Policies.
                await conn.execute(
                    """
                    UPDATE sensorthings."User"
                    SET role   = $1,
                        status = 'active'
                    WHERE id  = $2
                    """,
                    target_role,
                    user_id,
                )

                # 4b. Optional network scope. `dataset` in the body
                #     overrides what the applicant requested at login;
                #     "" clears it, absent leaves it unchanged. Must match
                #     an existing Network.
                granted_dataset_id = user_row["dataset_id"]
                dataset_raw = payload.get("dataset")
                if dataset_raw is not None:
                    new_scope = str(dataset_raw).strip() or None
                    if new_scope is not None and NETWORK:
                        exists = await conn.fetchval(
                            'SELECT 1 FROM sensorthings."Network" WHERE name = $1',
                            new_scope,
                        )
                        if not exists:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=(
                                    f"No Network named '{new_scope}'. "
                                    "dataset must match an existing Network."
                                ),
                            )
                    await conn.execute(
                        'UPDATE sensorthings."User" SET dataset_id = $1 WHERE id = $2',
                        new_scope,
                        user_id,
                    )
                    granted_dataset_id = new_scope

                # 4c. Record the activation in the AuditLog — same
                #     transaction as the role UPDATE above, so a logging
                #     failure rolls back the activation too (no
                #     unaudited role grant left behind). Mirrors
                #     update/admin_approval.py's ADMIN_APPROVAL write;
                #     this endpoint was the one path into an active role
                #     that never wrote one (create_pending_oidc_user()
                #     already logs RESTRICTED_REQUEST on signup — see
                #     app/db/oidc_user_crud.py).
                await log_audit_event(
                    conn=conn,
                    action_type=AUDIT_ACTION_ADMIN_APPROVAL,
                    actor_id=current_user["id"],
                    dataset_id=granted_dataset_id,
                    payload={
                        "activated_user_id": user_id,
                        "activated_username": username,
                        "granted_role": target_role,
                        "auth_provider": user_row["auth_provider"],
                    },
                )

        logger.info(
            "User '%s' (id=%d) activated to role '%s' by admin '%s'.",
            username,
            user_id,
            target_role,
            current_user["username"],
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": (
                    f"User '{username}' has been activated with role '{target_role}'."
                )
            },
        )

    except HTTPException:
        # Deliberate 4xx raised inside the transaction (e.g. unknown
        # Network) — let it through rather than masking it as a 500.
        raise
    except InsufficientPrivilegeError:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"message": "Insufficient database privileges."},
        )
    except (PostgresConnectionError, TooManyConnectionsError):
        logger.exception("Database unavailable during user activation")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"message": "Database temporarily unavailable."},
        )
    except QueryCanceledError:
        logger.exception("Database timeout during user activation")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"message": "Database request timed out."},
        )
    except Exception:
        logger.exception("Unexpected error during user activation")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error."},
        )
