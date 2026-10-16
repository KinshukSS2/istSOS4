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

"""Database logic for the PATCH /Users/{id}/networks endpoint.

Design decisions
----------------
* All mutations run inside a single asyncpg transaction so a failure
  reverts atomically.
* The user row is locked FOR UPDATE: concurrent edits of the same account
  serialise, and the last-administrator count is safe under load.
* A user's access is their list of grants. Saving replaces the whole list;
  no PostgreSQL DDL is issued -- members run as the shared "user" group and
  the RLS policies read the grants (migration 017_network_grants.sql).
* Saving grants on an administrator account is a demotion: the account
  becomes a member, with the last-administrator guard applied.
"""

import json
import logging

from app import POSTGRES_PORT_WRITE
from app.db.asyncpg_db import get_pool, get_pool_w
from app.db.audit_crud import AUDIT_ACTION_ROLE_CHANGED, log_audit_event
from app.db.network_grant_crud import (
    load_grants,
    render_grants,
    replace_user_grants,
    resolve_grants,
)
from app.rbac_roles import MEMBER_ROLE, PENDING_ROLE
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


async def update_user_networks(
    user_id: int,
    grants,
    actor_id: int | None = None,
) -> None:
    """Atomically replace an active user's grants.

    All within a single transaction:
        1. SELECT ... FOR UPDATE -- fetch the user row; 404 if missing.
        2. Guard: pending users cannot be changed here (400).
        3. Validate and resolve ``grants`` (400 on unknown / ambiguous
           Networks, unknown policies, overlaps).
        4. If the target is an administrator: last-admin guard (409), then
           the account becomes a member.
        5. Replace the grants; if the list actually changed, write a
           ROLE_CHANGED AuditLog row in the same transaction.

    Raises:
        HTTPException 404: User not found.
        HTTPException 400: User is pending, or a grant is invalid.
        HTTPException 409: Would demote the last administrator.
    """
    try:
        pool = await get_pool_w() if POSTGRES_PORT_WRITE else await get_pool()
    except Exception:
        pool = await get_pool()

    async with pool.acquire() as conn:
        async with conn.transaction():

            row = await conn.fetchrow(
                """
                SELECT id, username, role
                FROM sensorthings."User"
                WHERE id = $1
                FOR UPDATE
                """,
                user_id,
            )

            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"User with id={user_id} not found.",
                )

            current_role = row["role"]
            username = row["username"]

            if current_role == PENDING_ROLE:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Cannot change a pending user here. Approve the "
                        "account first via PATCH /Users/{id}/policy-approval."
                    ),
                )

            resolved = await resolve_grants(conn, grants, admin=True)
            old = render_grants((await load_grants(conn, [user_id]))[user_id])
            new = render_grants(resolved)

            demoted = current_role == "administrator"
            if demoted:
                admin_count = await conn.fetchval(
                    'SELECT COUNT(*) FROM sensorthings."User" '
                    "WHERE role = 'administrator'"
                )
                if admin_count <= 1:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "Cannot demote the last administrator. "
                            "Promote another user first."
                        ),
                    )

            if not demoted and old == new:
                return

            await replace_user_grants(conn, user_id, resolved)
            if current_role != MEMBER_ROLE:
                await conn.execute(
                    'UPDATE sensorthings."User" SET role = $1 WHERE id = $2',
                    MEMBER_ROLE,
                    user_id,
                )

            await log_audit_event(
                conn=conn,
                action_type=AUDIT_ACTION_ROLE_CHANGED,
                actor_id=actor_id,
                network_name=new,
                payload={
                    "target_user_id": user_id,
                    "username": username,
                    "old_networks": old,
                    "new_networks": new,
                    "demoted_administrator": demoted,
                },
            )

    logger.info(
        "User %r (id=%d): grants %s -> %s",
        username,
        user_id,
        json.dumps(old),
        json.dumps(new),
    )
