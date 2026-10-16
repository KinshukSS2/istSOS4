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

"""Regression coverage for the grant-based RLS policies
(017_network_grants.sql; the session-variable design is from
006_session_scoped_rls_policies.sql).

Every other RLS-adjacent test in this suite mocks the database connection
entirely, so none of them can actually prove row-level security enforces
anything -- they can only prove which SQL string gets sent. That gap is
exactly how the bug this migration fixes went unnoticed: the old
``TO <username>`` policies looked correct at the SQL-authoring level and
simply never matched a real session, for any user, ever.

test_datastream_rls_filters_by_network_per_user connects to a real
database and proves enforcement itself: that two sessions sharing the
same PostgreSQL group role ("user") but different individual identities
see different, correctly filtered rows. That per-user differentiation
*without* an individual login role is the entire point of the fix (see
the migration's own header comment), and it is precisely what the
previous design could never achieve. If a future change reintroduces
per-username policies, or breaks the session-variable plumbing in
set_role(), this test fails.

test_static_policies_are_group_scoped_not_per_user asserts the same thing
more directly and much more cheaply: every RLS policy on Datastream must
be scoped TO a shared group role, never TO an individual username.

Both skip cleanly (not a failure) if no database is reachable.

Each test opens its own asyncpg connection rather than reusing the app's
module-level get_pool() singleton. That pool is bound to whichever event
loop first created it; since each test here calls asyncio.run() (matching
the plain-function style the rest of this suite already uses -- no
pytest-asyncio fixtures), every test gets a fresh event loop, and a pool
opened on one loop cannot be reused once that loop closes. Confirmed
live: sharing get_pool() across two such tests raised
"cannot perform operation: another operation is in progress" on the
second test, purely from loop reuse -- unrelated to RLS itself.

Everything this module writes lives inside one transaction per test that
is always rolled back, never committed -- deliberately, not just for
hygiene. A real cleanup DELETE on sensorthings."User" was tried first and
found to be impossible for *any* row: AuditLog_actor_id_fkey is
ON DELETE SET NULL, and Postgres runs that enforcement trigger with the
referenced table's *owner* privileges (confirmed: both User and AuditLog
are owned by "administrator"), not the caller's -- and administrator was
deliberately never granted UPDATE on AuditLog, since it is meant to be
genuinely append-only. That makes DELETE FROM sensorthings."User" fail
for every caller, unconditionally, including the real DELETE /Users
endpoint -- a separate, real bug, logged in UNFINISHED_WORK.md rather
than fixed here. Rollback-only setup sidesteps it entirely for this
test's purposes without papering over it.
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest

API_DIR = str(Path(__file__).resolve().parents[1])
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

os.environ.setdefault("ISTSOS_ADMIN", "admin")
os.environ.setdefault("ISTSOS_ADMIN_PASSWORD", "admin")
os.environ.setdefault("POSTGRES_HOST", "database")
os.environ.setdefault("POSTGRES_DB", "istsos")
os.environ.setdefault("SECRET_KEY", "test_secret_key_1234567890")
os.environ.setdefault("ALGORITHM", "HS256")

import asyncpg  # noqa: E402

from app import (  # noqa: E402
    ISTSOS_ADMIN,
    ISTSOS_ADMIN_PASSWORD,
    POSTGRES_DB,
    POSTGRES_HOST,
    POSTGRES_PORT,
)
from app.v1.endpoints.functions import set_role  # noqa: E402

_MARKER = f"_rls_test_{uuid.uuid4().hex[:8]}"


async def _connect_or_skip():
    """A single connection scoped to this test's own asyncio.run() call --
    not the app's shared get_pool(), which is bound to whatever event loop
    created it. Same DSN shape as app.db.asyncpg_db.get_pool().
    """
    try:
        return await asyncpg.connect(
            dsn=f"postgresql://{ISTSOS_ADMIN}:{ISTSOS_ADMIN_PASSWORD}"
            f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )
    except (OSError, asyncpg.PostgresError) as exc:
        pytest.skip(f"no reachable database for RLS enforcement test: {exc}")


async def _networks(connection):
    """Two Networks that each have a Datastream: [(network_id, name, ds_id)]."""
    nets = await connection.fetch(
        """
        SELECT n.id, n.name, min(d.id) AS ds_id
        FROM sensorthings."Network" n
        JOIN sensorthings."Datastream" d ON d.network_id = n.id
        GROUP BY n.id, n.name
        ORDER BY n.id
        LIMIT 2;
        """
    )
    if len(nets) < 2:
        pytest.skip(
            "need two Networks that each have a Datastream -- run dummy_data "
            "with NETWORK=1"
        )
    return [(r["id"], r["name"], r["ds_id"]) for r in nets]


async def _member(connection, label, grants):
    """An active member holding ``grants``: a list of
    (role, [network_id, ...]) -- an empty id list means ALL Networks."""
    user_id = await connection.fetchval(
        """
        INSERT INTO sensorthings."User" (username, role, status)
        VALUES ($1, 'member', 'active') RETURNING id;
        """,
        f"{_MARKER}_{label}",
    )
    for role, network_ids in grants:
        grant_id = await connection.fetchval(
            """
            INSERT INTO sensorthings."UserGrant" ("user_id", "role", "all_networks")
            VALUES ($1, $2, $3) RETURNING id;
            """,
            user_id,
            role,
            not network_ids,
        )
        for network_id in network_ids:
            await connection.execute(
                """
                INSERT INTO sensorthings."UserGrantNetwork" ("grant_id", "network_id")
                VALUES ($1, $2);
                """,
                grant_id,
                network_id,
            )
    return user_id


async def _visible_datastreams(connection, user_id, ids):
    """Datastream ids from ``ids`` the member can SELECT -- in its own
    nested transaction, like set_role() once per real request."""
    async with connection.transaction():
        await set_role(connection, {"role": "member", "id": user_id})
        rows = await connection.fetch(
            'SELECT id FROM sensorthings."Datastream" '
            "WHERE id = ANY($1::bigint[]);",
            list(ids),
        )
    return {r["id"] for r in rows}


async def _can_update_datastream(connection, user_id, ds_id):
    async with connection.transaction():
        await set_role(connection, {"role": "member", "id": user_id})
        updated = await connection.fetch(
            'UPDATE sensorthings."Datastream" SET description = description || \'.\' '
            "WHERE id = $1 RETURNING id;",
            ds_id,
        )
    return bool(updated)


def _in_rollback_only_transaction(coro_fn):
    async def _run():
        connection = await _connect_or_skip()
        try:
            transaction = connection.transaction()
            await transaction.start()
            try:
                await set_role(connection, {"role": "administrator"})
                await coro_fn(connection)
            finally:
                await transaction.rollback()
        finally:
            await connection.close()

    asyncio.run(_run())


def test_datastream_rls_filters_by_network_per_user():
    """Two members share the PostgreSQL group role "user" but hold grants on
    different Networks, so each sees only their own Network's rows."""

    async def _body(connection):
        (net_a, _, ds_a), (net_b, _, ds_b) = await _networks(connection)
        user_a = await _member(connection, "alice", [("viewer", [net_a])])
        user_b = await _member(connection, "bob", [("viewer", [net_b])])

        assert await _visible_datastreams(connection, user_a, [ds_a, ds_b]) == {ds_a}
        assert await _visible_datastreams(connection, user_b, [ds_a, ds_b]) == {ds_b}

    _in_rollback_only_transaction(_body)


def test_one_user_viewer_on_a_editor_on_b():
    """Roles are per Network: viewer of A + editor of B reads both but may
    write only B."""

    async def _body(connection):
        (net_a, _, ds_a), (net_b, _, ds_b) = await _networks(connection)
        user = await _member(
            connection, "mixed", [("viewer", [net_a]), ("editor", [net_b])]
        )

        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == {ds_a, ds_b}
        assert not await _can_update_datastream(connection, user, ds_a)
        assert await _can_update_datastream(connection, user, ds_b)

    _in_rollback_only_transaction(_body)


def test_empty_network_list_means_all_networks():
    async def _body(connection):
        (_, _, ds_a), (_, _, ds_b) = await _networks(connection)
        user = await _member(connection, "everywhere", [("viewer", [])])

        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == {ds_a, ds_b}
        assert not await _can_update_datastream(connection, user, ds_a)

    _in_rollback_only_transaction(_body)


def test_same_network_two_roles_add_up():
    """viewer + editor on the same Network -> the union (can write)."""

    async def _body(connection):
        (net_a, _, ds_a), (_, _, ds_b) = await _networks(connection)
        user = await _member(
            connection, "union", [("viewer", [net_a]), ("editor", [net_a])]
        )

        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == {ds_a}
        assert await _can_update_datastream(connection, user, ds_a)

    _in_rollback_only_transaction(_body)


def test_user_without_grants_sees_nothing():
    async def _body(connection):
        (_, _, ds_a), (_, _, ds_b) = await _networks(connection)
        user = await _member(connection, "nobody", [])

        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == set()

    _in_rollback_only_transaction(_body)


def test_removing_a_grant_removes_access():
    async def _body(connection):
        (net_a, _, ds_a), (_, _, ds_b) = await _networks(connection)
        user = await _member(connection, "revoked", [("viewer", [net_a])])
        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == {ds_a}

        # SET LOCAL ROLE outlives the nested transaction; switch back.
        await set_role(connection, {"role": "administrator"})
        await connection.execute(
            'DELETE FROM sensorthings."UserGrant" WHERE "user_id" = $1', user
        )
        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == set()

    _in_rollback_only_transaction(_body)


def test_deleting_a_network_never_widens_to_all():
    """A grant whose only Network is deleted must not turn into an
    all-Networks grant."""

    async def _body(connection):
        (net_a, _, ds_a), (net_b, _, ds_b) = await _networks(connection)
        user = await _member(connection, "pruned", [("viewer", [net_a])])
        await connection.execute(
            'DELETE FROM sensorthings."UserGrantNetwork" WHERE "network_id" = $1',
            net_a,
        )
        assert await _visible_datastreams(connection, user, [ds_a, ds_b]) == set()

    _in_rollback_only_transaction(_body)


def test_static_policies_are_group_scoped_not_per_user():
    """Direct assertion against the exact shape of the original bug: every
    RLS policy on Datastream must be scoped TO a shared PostgreSQL group
    role ('user', 'sensor', 'qc', ...), never TO an individual username.
    A regression back to per-user policies would pass every mocked SQL-
    dispatch test in this suite while silently reintroducing a policy that
    can never match a real session -- this is the one check that would
    actually catch that. Read-only; needs no setup or cleanup.
    """

    async def _run():
        connection = await _connect_or_skip()
        try:
            rows = await connection.fetch(
                """
                SELECT policyname, roles AS role_names
                FROM pg_policies
                WHERE schemaname = 'sensorthings' AND tablename = 'Datastream';
                """
            )
        finally:
            await connection.close()

        assert rows, "expected at least one RLS policy on sensorthings.Datastream"

        # The complete, real set of PostgreSQL group roles this schema
        # defines (confirmed against pg_roles) that could legitimately
        # back an RLS policy. Application-layer role names like "custom"
        # are deliberately absent -- DB_ROLE_BY_RBAC_ROLE maps them onto a
        # shared PG group role, they have no PG role of their own
        # (see rbac_roles.py).
        known_group_roles = {"user", "sensor", "qc", "administrator", "guest", "public"}
        for row in rows:
            for role_name in row["role_names"]:
                assert role_name in known_group_roles, (
                    f"policy {row['policyname']!r} is scoped TO {role_name!r}, "
                    "which is not one of the known shared group roles -- "
                    "this looks like a per-username policy, the exact "
                    "pattern that never matched a real session before "
                    "006_session_scoped_rls_policies.sql."
                )

    asyncio.run(_run())
