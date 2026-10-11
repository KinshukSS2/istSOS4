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

import asyncio
import json
import logging

from app import HOSTNAME, POSTGRES_PORT_WRITE, SUBPATH, VERSION
from app.db.asyncpg_db import get_pool, get_pool_w
from app.db.audit_crud import AUDIT_ACTION_USER_CREATED, log_audit_event
from app.db.network_grant_crud import (
    effective_permissions,
    grant_warnings,
    render_grants,
    replace_user_grants,
    resolve_grants,
)
from app.db.password_crud import pwd_context
from app.models.networks import GrantList
from app.oauth import get_current_user
from app.rbac_roles import MEMBER_ROLE
from app.utils.utils import validate_username
from app.validators import validate_password_strength
from app.v1.endpoints.functions import set_role
from app.v1.endpoints.openapi_responses import (
    DB_TIMEOUT,
    DB_UNAVAILABLE,
    STA_BAD_REQUEST,
    merge,
)
from asyncpg.exceptions import (
    InsufficientPrivilegeError,
    PostgresConnectionError,
    QueryCanceledError,
    TooManyConnectionsError,
    UniqueViolationError,
)
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse, Response
from pydantic import TypeAdapter, ValidationError

v1 = APIRouter()
logger = logging.getLogger(__name__)

PAYLOAD_EXAMPLE = {
    "username": "cp1",
    "password": "Str0ng!Pass",
    "uri": "https://orcid.org/0000-0004-3456-7890",
    # the user's access: one grant per entry; network_name [] = all Networks
    "networks": [
        {"network_name": [], "role": "viewer", "policy": ""},
        {"network_name": ["psos", "acsot"], "role": "custom", "policy": "policyname1"},
    ],
}

_GRANT_LIST = TypeAdapter(GrantList)
_ALLOWED_KEYS = {"username", "password", "networks", "uri", "contact"}

@v1.api_route(
    "/Users",
    methods=["POST"],
    tags=["Users"],
    summary="Create a new User",
    description=(
        "Create a new, already-active User directly, bypassing the "
        "registration/approval lifecycle. `networks` is the user's access: "
        "a list of grants `{network_name: [...], role, policy}` "
        "(`network_name: []` = all Networks; `policy` only for `custom`). "
        "Administrator-only."
    ),
    status_code=status.HTTP_201_CREATED,
    responses=merge(
        {201: {"description": "Created. Response body is empty."}},
        STA_BAD_REQUEST,
        {
            403: {
                "description": "The caller is not an administrator.",
                "content": {
                    "application/json": {"example": {"message": "Insufficient privileges."}}
                },
            },
            409: {
                "description": "A user with that username already exists.",
                "content": {
                    "application/json": {"example": {"message": "User already exists."}}
                },
            },
        },
        DB_UNAVAILABLE,
        DB_TIMEOUT,
        {
            500: {
                "description": "Unexpected server error.",
                "content": {
                    "application/json": {"example": {"message": "Internal server error."}}
                },
            }
        },
    ),
)
async def create_user(
    payload: dict = Body(examples=[PAYLOAD_EXAMPLE]),
    current_user=Depends(get_current_user),
    pgpool=Depends(get_pool_w) if POSTGRES_PORT_WRITE else Depends(get_pool),
):
    try:
        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "code": 400,
                    "type": "error",
                    "message": "Invalid payload format. Expected a dictionary.",
                },
            )

        async with pgpool.acquire() as connection:
            async with connection.transaction():
                if (
                    "username" not in payload
                    or "password" not in payload
                    or "networks" not in payload
                ):
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "code": 400,
                            "type": "error",
                            "message": "Missing required properties: 'username' or 'password' or 'networks'.",
                        },
                    )

                if not validate_username(payload["username"]):
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "code": 400,
                            "type": "error",
                            "message": "Invalid username: only letters, digits and underscores allowed (3\u201363 characters).",
                        },
                    )

                unknown = sorted(set(payload) - _ALLOWED_KEYS)
                if unknown:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "code": 400,
                            "type": "error",
                            "message": "Unrecognized key(s): " + ", ".join(unknown),
                        },
                    )

                try:
                    grants = _GRANT_LIST.validate_python(payload.pop("networks"))
                except ValidationError as exc:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "code": 400,
                            "type": "error",
                            "message": "Invalid 'networks': "
                            + str(exc.errors()[0].get("msg", "invalid")),
                        },
                    )
                payload["role"] = MEMBER_ROLE  # account kind; access = grants

                if current_user is not None:
                    if current_user["role"] != "administrator":
                        raise InsufficientPrivilegeError

                    await set_role(connection, current_user)

                # Hash the password and put it back as a bcrypt hash so the
                # dynamic INSERT below writes it to "User".password. istSOS
                # users are not PostgreSQL roles -- there is no CREATE USER
                # / WITH ENCRYPTED PASSWORD; /Login verifies against this
                # column (same as the /Register path in
                # create/register_request.py).
                raw_password = payload.pop("password", None)
                if not isinstance(raw_password, str):
                    raise ValueError("Password must be a string.")
                validate_password_strength(raw_password)
                payload["password"] = await asyncio.to_thread(
                    pwd_context.hash, raw_password
                )

                for key in list(payload.keys()):
                    if isinstance(payload[key], dict):
                        payload[key] = json.dumps(payload[key])

                keys = ", ".join(f'"{key}"' for key in payload.keys())
                values_placeholders = ", ".join(
                    (f"${i+1}") for i in range(len(payload))
                )
                query = f"""
                    INSERT INTO sensorthings."User" ({keys})
                    VALUES ({values_placeholders})
                    RETURNING id, username, uri;
                """
                user = await connection.fetchrow(query, *payload.values())

                if not payload.get("uri"):
                    query = """
                        UPDATE sensorthings."User"
                        SET uri = $1 || $2 || $3 ||  '/Users(' || sensorthings."User".id || ')'
                        WHERE sensorthings."User".id = $4
                        RETURNING uri;
                    """
                    generated_uri = await connection.fetchval(
                        query, HOSTNAME, SUBPATH, VERSION, user["id"]
                    )
                    user = {**user, "uri": generated_uri}

                # Validate + save the grants (also creates the fixed commit
                # rows a sensor / qc grant needs).
                resolved = await resolve_grants(connection, grants, admin=True)
                await replace_user_grants(connection, user["id"], resolved)
                granted = render_grants(resolved)

                if current_user is not None:
                    await log_audit_event(
                        conn=connection,
                        action_type=AUDIT_ACTION_USER_CREATED,
                        actor_id=current_user["id"],
                        network_name=granted,
                        payload={
                            "created_user_id": user["id"],
                            "username": user["username"],
                            "networks": granted,
                        },
                    )

                # No RLS DDL needed here: access is the list of grants just
                # saved, evaluated by the static policies of
                # 017_network_grants.sql.

        return Response(status_code=status.HTTP_201_CREATED)

    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code, content={"message": exc.detail}
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": str(exc)},
        )
    except UniqueViolationError:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"message": "User already exists."},
        )
    except InsufficientPrivilegeError:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"message": "Insufficient privileges."},
        )
    except (PostgresConnectionError, TooManyConnectionsError):
        logger.exception(
            "Database temporarily unavailable during user creation"
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"message": "Database temporarily unavailable."},
        )
    except QueryCanceledError:
        logger.exception("Database timeout during user creation")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"message": "Database request timed out."},
        )
    except Exception:
        logger.exception("Unexpected error during user creation")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error."},
        )
