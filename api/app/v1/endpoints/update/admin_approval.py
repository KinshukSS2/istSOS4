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

"""PATCH /Users/{user_id}/policy-approval — Admin approval of pending users.

Flow
----
1.  Verify caller is an ``administrator`` (HTTP 403 otherwise).
2.  Within a single DB transaction (write pool):
    a.  Lock and fetch the target user; it must still be ``pending`` (and
        not rejected).
    b.  Take the grants to give from the request: either the explicit
        ``networks`` list, or -- when the administrator sends
        ``approve_as_requested: true`` -- the applicant's own
        ``requested_networks``. The request is only a hint: the administrator's
        list replaces it.
    c.  Validate and resolve them (Network names -> ids, policy names -> ids,
        ambiguity, overlaps) and replace the user's grants.
    d.  Mark the account ``active`` (``role='member'``).
    e.  Insert an ADMIN_APPROVAL audit event.
3.  Return HTTP 200 with the requested, granted and effective access.

Architecture note
-----------------
This is the single approval path for both local sign-ups (POST /Register)
and OIDC JIT-provisioned accounts. Access is entirely grant-based: there is
no per-approval RLS call, and the static policies created by migration
017_network_grants.sql evaluate each user's grants on every query.

The whole mutation runs inside one ``conn.transaction()`` block, so a failure
leaves the user still pending with no partial grants.
"""

import json
import logging

from app import POSTGRES_PORT_WRITE
from app.db.asyncpg_db import get_pool, get_pool_w
from app.db.audit_crud import AUDIT_ACTION_ADMIN_APPROVAL, log_audit_event
from app.db.network_grant_crud import (
    effective_permissions,
    grant_warnings,
    render_grants,
    replace_user_grants,
    resolve_grants,
)
from app.models.approval_request import AdminApprovalRequest, ApprovalResponse
from app.models.networks import GrantList
from app.oauth import get_current_user
from app.rbac_roles import MEMBER_ROLE
from app.v1.endpoints.openapi_responses import (
    BAD_REQUEST_REJECTED,
    DB_TIMEOUT,
    DB_UNAVAILABLE,
    FORBIDDEN_ADMIN,
    INTERNAL,
    NOT_FOUND_PENDING_USER,
    UNAUTHORIZED,
    merge,
    response,
)
from asyncpg.exceptions import (
    InsufficientPrivilegeError,
    PostgresConnectionError,
    QueryCanceledError,
    TooManyConnectionsError,
)
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter, ValidationError

v1 = APIRouter()
logger = logging.getLogger(__name__)

_GRANT_LIST = TypeAdapter(GrantList)


@v1.api_route(
    "/Users/{user_id}/policy-approval",
    methods=["PATCH"],
    tags=["Registration & Approval"],
    summary="Admin approval: activate a pending user",
    description=(
        "Approve a pending account and give it its access. Covers both local "
        "self-registration (POST /Register) and OIDC sign-ups.\n\n"
        "Send **either** `networks` -- the final list of grants "
        "(`network_name` list, `role`, `policy`), replacing whatever the "
        "applicant requested -- **or** `approve_as_requested: true` to grant "
        "exactly the request. `network_name: []` grants all Networks. "
        "Grants add up: where several cover a Network the user holds the "
        "union. Everything is saved in one transaction, with an "
        "ADMIN_APPROVAL audit event. Restricted to administrators; the "
        "target must be in the 'pending' state."
    ),
    status_code=status.HTTP_200_OK,
    responses=merge(
        {
            200: response(
                ApprovalResponse,
                "Approved. The grants, the account activation and the "
                "ADMIN_APPROVAL audit event are written in one transaction.",
                {
                    "message": "User 'jdoe' (id=42) has been approved.",
                    "user_id": 42,
                    "username": "jdoe",
                    "status": "active",
                    "requested": [{"network_name": ["psos"], "role": "viewer"}],
                    "granted": [
                        {"network_name": ["psos"], "role": "viewer", "policy": ""}
                    ],
                    "effective": [{"network_name": "psos", "roles": ["viewer"]}],
                    "warnings": [],
                },
            ),
            400: {
                "description": (
                    "A grant is invalid: unknown or ambiguous Network name, "
                    "unknown policy, overlapping grants of the same role, or "
                    "`approve_as_requested` with nothing requested."
                ),
                "content": {
                    "application/json": {
                        "example": {"detail": "No Network named: 'nowhere'."}
                    }
                },
            },
        },
        UNAUTHORIZED,
        {
            # A second, differently-shaped 403 exists deeper in this
            # handler for a PostgreSQL-privilege failure
            # ({"message": "Insufficient database privileges."}) -- far
            # rarer than this one, so it's not the documented example, but
            # be aware both are possible on this code.
            403: FORBIDDEN_ADMIN[403],
        },
        NOT_FOUND_PENDING_USER,
        BAD_REQUEST_REJECTED,
        DB_UNAVAILABLE,
        DB_TIMEOUT,
        INTERNAL,
    ),
)
async def patch_policy_approval(
    user_id: int,
    request: AdminApprovalRequest,
    current_user=Depends(get_current_user),
):
    # ------------------------------------------------------------------
    # 1. Authorization: only administrators may approve pending users.
    # ------------------------------------------------------------------
    if current_user["role"] != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrator access required",
        )

    # ------------------------------------------------------------------
    # 2. Acquire write pool connection and run all mutations atomically.
    # ------------------------------------------------------------------
    try:
        write_pool = await get_pool_w() if POSTGRES_PORT_WRITE else await get_pool()

        async with write_pool.acquire() as conn:
            async with conn.transaction():

                # 2a. Lock the target. A rejected user still has
                #     role='pending' (rejection is a status transition), so
                #     status is checked separately.
                target = await conn.fetchrow(
                    """
                    SELECT username, status, role, requested_networks, auth_provider
                    FROM sensorthings."User"
                    WHERE id = $1
                    FOR UPDATE
                    """,
                    user_id,
                )

                if target is None or target["role"] != "pending":
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found or not in pending state",
                    )

                if target["status"] == "rejected":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            "This user's registration was rejected and "
                            "cannot be approved directly. They must "
                            "re-apply via POST /Register first."
                        ),
                    )

                username: str = target["username"]
                requested_raw = target["requested_networks"]
                requested = (
                    json.loads(requested_raw)
                    if isinstance(requested_raw, str)
                    else (requested_raw or [])
                )

                # 2b. The grants to give.
                if request.networks is not None:
                    grants = request.networks
                else:
                    if not requested:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=(
                                f"User '{username}' requested no access, so "
                                "'networks' must be specified explicitly."
                            ),
                        )
                    try:
                        grants = _GRANT_LIST.validate_python(requested)
                    except ValidationError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=(
                                "The stored request is not a valid grant "
                                "list; specify 'networks' explicitly."
                            ),
                        )

                # 2c. Resolve + save. admin=True: this is the administrator's
                #     own decision, so a grant covering all Networks is fine.
                resolved = await resolve_grants(conn, grants, admin=True)
                await replace_user_grants(conn, user_id, resolved)

                # 2d. Activate.
                await conn.execute(
                    """
                    UPDATE sensorthings."User"
                    SET role = $1, status = 'active'
                    WHERE id = $2
                    """,
                    MEMBER_ROLE,
                    user_id,
                )

                granted = render_grants(resolved)

                # 2e. Audit, same transaction.
                await log_audit_event(
                    conn=conn,
                    action_type=AUDIT_ACTION_ADMIN_APPROVAL,
                    actor_id=current_user["id"],
                    network_name=granted,
                    payload={
                        "approved_user_id": user_id,
                        "auth_provider": target["auth_provider"],
                        "requested_networks": requested,
                        "granted_networks": granted,
                    },
                )

        logger.info(
            "Admin approval: user '%s' (id=%d) granted %s by admin id=%d.",
            username,
            user_id,
            granted,
            current_user["id"],
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"User '{username}' (id={user_id}) has been approved.",
                "user_id": user_id,
                "username": username,
                "status": "active",
                "requested": requested,
                "granted": granted,
                "effective": effective_permissions(resolved),
                "warnings": grant_warnings(resolved),
            },
        )

    except HTTPException:
        # Re-raise HTTPExceptions raised inside the transaction block
        # (404s, 400s) without wrapping them in a 500.
        raise
    except InsufficientPrivilegeError:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"message": "Insufficient database privileges."},
        )
    except (PostgresConnectionError, TooManyConnectionsError):
        logger.exception("Database unavailable during admin approval")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"message": "Database temporarily unavailable."},
        )
    except QueryCanceledError:
        logger.exception("Database timeout during admin approval")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"message": "Database request timed out."},
        )
    except Exception:
        logger.exception("Unexpected error during admin approval")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error."},
        )
