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

import re

from app import NETWORK, POSTGRES_PORT_WRITE
from app.db.asyncpg_db import get_pool, get_pool_w
from app.oauth import get_current_user
from app.v1.endpoints.exceptions import BadRequest
from app.v1.endpoints.functions import set_role
from app.v1.endpoints.openapi_responses import merge
from asyncpg.exceptions import (
    DuplicateObjectError,
    InsufficientPrivilegeError,
    UniqueViolationError,
)
from fastapi import APIRouter, Body, Depends, status
from fastapi.responses import JSONResponse, Response

v1 = APIRouter()

_UNSAFE_POLICY_TOKENS_RE = re.compile(r";|--|/\*|\*/|\x00")
_VALID_OPERATION_KEYS = {"select", "insert", "update", "delete"}
# Policy name -> prefix of the PostgreSQL policy names (<name>_<table>_<op>,
# max 63 chars). 'rbac_' is reserved for the built-in policies.
_POLICY_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,29}$")

# Tables a custom rule can target -> does the table hang off a Network?
POLICY_TABLES = {
    "location": "Location",
    "thing": "Thing",
    "historicallocation": "HistoricalLocation",
    "observedproperty": "ObservedProperty",
    "sensor": "Sensor",
    "datastream": "Datastream",
    "observation": "Observation",
    "featuresofinterest": "FeaturesOfInterest",
}


def policy_object_names(name: str):
    """Every PostgreSQL policy name POST /Policies may have created."""
    for table in POLICY_TABLES.values():
        for operation in sorted(_VALID_OPERATION_KEYS):
            yield table, f"{name}_{table.lower()}_{operation}"

# A policy is a named rule set. It does not name users or Networks: a user
# gets it through a `custom` grant (`{network_name: [...], role: "custom",
# policy: "<name>"}`), and the rules only ever apply inside that grant's
# Networks.
PAYLOAD_EXAMPLE = {
    "name": "test",
    "permissions": {
        "type": "custom",
        "policy": {
            "datastream": {
                "select": "name LIKE 'meteo_%'",
            },
        },
    },
}


@v1.api_route(
    "/Policies",
    methods=["POST"],
    tags=["Policies"],
    summary="Create a Policy",
    description=(
        "Create a named rule set for `custom` grants.\n\n"
        "A policy is a set of SQL conditions per table and operation. It "
        "does nothing by itself: an administrator gives it to a user with a "
        "grant `{network_name: [...], role: \"custom\", policy: \"<name>\"}` "
        "(POST /Users, PATCH /Users/{id}/networks or PATCH "
        ".../policy-approval), and the rules then apply only inside that "
        "grant's Networks. The rules add to, never remove from, what the "
        "user's other grants allow.\n\n"
        "`viewer` / `editor` / `obs_manager` / `sensor` / `qc` are built in; "
        "`permissions.type` must be `custom`, any other type returns 400."
    ),
    status_code=status.HTTP_201_CREATED,
    responses=merge(
        {
            201: {"description": "Custom policy created. Response body is empty."},
            400: {
                "description": (
                    "Malformed payload (including the removed `users` "
                    "field), invalid `name`, unknown `permissions.type`, or "
                    "`permissions.type` is one of the five built-in role "
                    "types (nothing to create for those)."
                )
            },
            403: {"description": "The caller is not an administrator."},
            409: {"description": "A policy of that name already exists."},
        }
    ),
)
async def create_policy(
    payload: dict = Body(examples=[PAYLOAD_EXAMPLE]),
    current_user=Depends(get_current_user),
    pgpool=Depends(get_pool_w) if POSTGRES_PORT_WRITE else Depends(get_pool),
):
    try:
        if not isinstance(payload, dict):
            raise BadRequest("Payload must be a dictionary.")

        async with pgpool.acquire() as connection:
            async with connection.transaction():
                if "name" not in payload or "permissions" not in payload:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "message": "Missing required properties: 'name' or 'permissions'."
                        },
                    )
                if "users" in payload:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "message": (
                                "'users' is no longer accepted. A policy is "
                                "a named rule set: give it to a user with a "
                                "custom grant (role 'custom', policy "
                                "'<name>') instead."
                            )
                        },
                    )
                unknown = sorted(set(payload) - {"name", "permissions"})
                if unknown:
                    raise BadRequest(
                        "Unrecognized key(s): " + ", ".join(unknown)
                    )
                if not isinstance(payload["permissions"], dict):
                    raise BadRequest("'permissions' must be an object.")

                if current_user is not None:
                    if current_user["role"] != "administrator":
                        raise InsufficientPrivilegeError

                    await set_role(connection, current_user)

                permission_type = payload["permissions"].get("type")

                # The five role types are already enforced by the static
                # per-role policies from 006_session_scoped_rls_policies.sql,
                # which apply the moment set_role() runs -- there is nothing
                # for this endpoint to create for them. Previously this
                # returned 200 with an explanatory message so the caller
                # would have to read the body to learn nothing happened;
                # 400 makes that failure visible in the status code itself,
                # matching every other "you asked for something invalid"
                # response in this API.
                STATIC_ROLE_TYPES = {
                    "viewer",
                    "editor",
                    "obs_manager",
                    "sensor",
                    "qc",
                }
                if permission_type in STATIC_ROLE_TYPES:
                    raise BadRequest(
                        f"Role '{permission_type}' is covered by a static "
                        "RLS policy already -- there is nothing for "
                        "POST /Policies to create. Only permissions.type "
                        "'custom' creates a policy through this endpoint."
                    )

                if permission_type != "custom":
                    raise BadRequest(
                        "permissions.type must be one of: viewer, editor, "
                        "obs_manager, sensor, qc, custom."
                    )

                await create_policies(
                    connection,
                    payload["permissions"].get("policy"),
                    payload["name"],
                )

        return Response(status_code=status.HTTP_201_CREATED)

    except (DuplicateObjectError, UniqueViolationError):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"message": "Policy already exists."},
        )
    except InsufficientPrivilegeError:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"message": "Insufficient privileges."},
        )
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": str(e)},
        )


async def create_policies(connection, policies, name):
    """Store the rule set ``name`` and create its PostgreSQL policies.

    The rules are only ever true for a user holding a ``custom`` grant that
    names this policy -- and, with Networks on, only for rows inside that
    grant's Networks. The grant lookups are wrapped as ``(SELECT fn(..))`` so
    PostgreSQL evaluates them once per query instead of once per row, and
    the id lists are matched as ``col IN (SELECT unnest(..))`` -- a hashed
    sub-plan -- because ``col = ANY (array_param)`` is a linear scan of the
    array for every row (9 s vs 0.6 s counting 2M Observations).
    """

    def quote_identifier(value: str) -> str:
        if not isinstance(value, str) or value.strip() == "":
            raise ValueError("Invalid SQL identifier")
        return '"' + value.replace('"', '""') + '"'

    def validate_policy_expression(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Policy condition must be a string")
        expression = value.strip()
        if expression == "":
            raise ValueError("Policy condition must not be empty")
        if _UNSAFE_POLICY_TOKENS_RE.search(expression):
            raise ValueError("Unsafe policy condition")
        return expression

    if not isinstance(name, str) or not _POLICY_NAME_RE.match(name):
        raise ValueError(
            "Policy 'name' must start with a letter and contain only "
            "letters, digits and '_' (max 30 characters)."
        )
    if name.lower().startswith("rbac_"):
        raise ValueError("Policy names starting with 'rbac_' are reserved.")

    if not isinstance(policies, dict) or len(policies) == 0:
        raise ValueError("Policies must not be empty")

    # Validate everything before touching the database.
    parsed = []
    for table_key, operations in policies.items():
        table = POLICY_TABLES.get(table_key)
        if table is None:
            raise ValueError(f"Unsupported table key: {table_key}")
        if not isinstance(operations, dict) or len(operations) == 0:
            raise ValueError(f"No operations provided for table: {table_key}")
        for operation, condition in operations.items():
            operation_lc = str(operation).lower()
            if operation_lc not in _VALID_OPERATION_KEYS:
                raise ValueError(f"Unsupported operation: {operation}")
            parsed.append(
                (table, operation_lc, validate_policy_expression(condition))
            )

    # A rule is evaluated for *every* member's query (policies are OR-ed), so
    # one that cannot run as the `user` role (a table the group may not read,
    # a bad column, a function it may not call) would break reads for all of
    # them. Try each condition once, as that role, before storing anything.
    # Permission checks happen when the statement starts, so this fails even
    # though no row is visible to an anonymous caller.
    admin_role = await connection.fetchval("SELECT current_user")
    for table, _op, condition in parsed:
        try:
            async with connection.transaction():
                await connection.execute('SET LOCAL ROLE "user"')
                await connection.fetchval(
                    f'SELECT 1 FROM sensorthings.{quote_identifier(table)} '
                    f"WHERE ({condition}) LIMIT 1"
                )
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"The condition for {table} cannot be evaluated by regular "
                f"users: {str(exc).splitlines()[0]}"
            ) from exc
        finally:
            await connection.execute(
                f"SET LOCAL ROLE {quote_identifier(str(admin_role))}"
            )

    # UNIQUE(name) -> 409 on a duplicate.
    policy_id = await connection.fetchval(
        'INSERT INTO sensorthings."CustomPolicy" ("name") VALUES ($1) '
        'RETURNING "id"',
        name,
    )
    pid = int(policy_id)

    for table, operation_lc, condition in parsed:
        safe_table = quote_identifier(table)
        safe_name = quote_identifier(f"{name}_{table.lower()}_{operation_lc}")

        # Who the rule applies to: holders of a custom grant naming this
        # policy, limited to that grant's Networks where the table has them.
        if NETWORK and table == "Datastream":
            scope = (
                f"((SELECT sensorthings.app_policy_all({pid})) OR "
                f"network_id IN (SELECT unnest((SELECT sensorthings.app_policy_nets({pid})))))"
            )
        elif NETWORK and table == "Observation":
            scope = (
                f"((SELECT sensorthings.app_policy_all({pid})) OR "
                f"datastream_id IN (SELECT unnest((SELECT sensorthings.app_policy_ds_ids({pid})))))"
            )
        else:
            scope = f"(SELECT sensorthings.app_policy_any({pid}))"
        predicate = f"{scope} AND ({condition})"

        if operation_lc in {"select", "delete"}:
            query = f"""
                CREATE POLICY {safe_name}
                ON sensorthings.{safe_table}
                FOR {operation_lc.upper()}
                TO "user"
                USING ({predicate});
            """
        elif operation_lc == "insert":
            query = f"""
                CREATE POLICY {safe_name}
                ON sensorthings.{safe_table}
                FOR INSERT
                TO "user"
                WITH CHECK ({predicate});
            """
        else:
            query = f"""
                CREATE POLICY {safe_name}
                ON sensorthings.{safe_table}
                FOR {operation_lc.upper()}
                TO "user"
                USING ({predicate})
                WITH CHECK ({predicate});
            """

        await connection.execute(query)
