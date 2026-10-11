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

from app import AUTHORIZATION, POSTGRES_PORT_WRITE
from app.db.asyncpg_db import get_pool, get_pool_w
from app.utils.utils import pg_quote_ident
from app.v1.endpoints.create.policy import policy_object_names
from app.v1.endpoints.functions import set_role
from asyncpg.exceptions import InsufficientPrivilegeError, UndefinedObjectError
from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse, Response

v1 = APIRouter()
user = Depends(lambda: None)
if AUTHORIZATION:
    from app.oauth import get_current_user

    user = Depends(get_current_user)


@v1.api_route(
    "/Policies",
    methods=["DELETE"],
    tags=["Policies"],
    summary="Delete a Policy",
    description=(
        "Delete a named policy (rule set) and every row-level-security "
        "policy it created. Refused with 409 while any user still holds a "
        "`custom` grant that uses it. Administrator-only."
    ),
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Deleted. Response body is empty."},
        400: {
            "description": "Catch-all for any unexpected failure during deletion.",
            "content": {"application/json": {"example": {"message": "..."}}},
        },
        401: {
            "description": (
                "The caller is not an administrator. 401 here, not 403 -- "
                "same inconsistency as update/user.py and update/policy.py."
            ),
            "content": {"application/json": {"example": {"message": "Insufficient privileges"}}},
        },
        404: {
            "description": "No policy exists with that name.",
            "content": {"application/json": {"example": {"message": "Policy not found"}}},
        },
        409: {
            "description": "A user still holds a custom grant that uses this policy.",
            "content": {
                "application/json": {
                    "example": {"message": "Policy 'x' is used by 2 grant(s)."}
                }
            },
        },
    },
)
async def delete_policy(
    policy: str = Query(
        alias="policy",
        description="The name of the policy to delete",
    ),
    current_user=user,
    pool=Depends(get_pool_w) if POSTGRES_PORT_WRITE else Depends(get_pool),
):
    try:
        async with pool.acquire() as connection:
            async with connection.transaction():
                if current_user is not None:
                    if current_user["role"] != "administrator":
                        raise InsufficientPrivilegeError

                    await set_role(connection, current_user)

                policy_id = await connection.fetchval(
                    'SELECT "id" FROM sensorthings."CustomPolicy" '
                    'WHERE "name" = $1 FOR UPDATE',
                    policy,
                )
                if policy_id is None:
                    raise UndefinedObjectError()

                in_use = await connection.fetchval(
                    'SELECT count(*) FROM sensorthings."UserGrant" '
                    'WHERE "policy_id" = $1',
                    policy_id,
                )
                if in_use:
                    return JSONResponse(
                        status_code=status.HTTP_409_CONFLICT,
                        content={
                            "message": (
                                f"Policy '{policy}' is used by {in_use} "
                                "grant(s). Change those users' grants first."
                            )
                        },
                    )

                for table, policy_name in policy_object_names(policy):
                    await connection.execute(
                        f"DROP POLICY IF EXISTS {pg_quote_ident(policy_name)} "
                        f"ON sensorthings.{pg_quote_ident(table)};"
                    )
                await connection.execute(
                    'DELETE FROM sensorthings."CustomPolicy" WHERE "id" = $1',
                    policy_id,
                )

        return Response(status_code=status.HTTP_200_OK)

    except UndefinedObjectError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"message": "Policy not found"},
        )
    except InsufficientPrivilegeError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Insufficient privileges"},
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": str(e)},
        )
