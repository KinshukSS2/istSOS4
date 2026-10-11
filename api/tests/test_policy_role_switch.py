"""Tests for DB role switching in policy admin endpoints."""

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock

# Ensure api/ is on sys.path so 'app' resolves to api/app
API_DIR = str(Path(__file__).resolve().parents[1])
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

os.environ.setdefault("SECRET_KEY", "test_secret_key")

import asyncpg  # noqa: E402
import pytest  # noqa: E402

import app.v1.endpoints.create.policy as create_policy_endpoint  # noqa: E402


def mock_pgpool(connection):
    @asynccontextmanager
    async def acquire_cm():
        yield connection

    class _Pool:
        def acquire(self):
            return acquire_cm()

    return _Pool()


def attach_transaction_cm(connection):
    @asynccontextmanager
    async def tx():
        yield

    connection.transaction = tx


def _call_create_policy(payload, connection=None):
    connection = connection or AsyncMock()
    connection.execute = AsyncMock()
    connection.fetchval = getattr(connection, "fetchval", AsyncMock(return_value=7))
    attach_transaction_cm(connection)
    current_user = {"username": "admin_user", "role": "administrator"}
    response = asyncio.run(
        create_policy_endpoint.create_policy(
            payload=payload,
            current_user=current_user,
            pgpool=mock_pgpool(connection),
        )
    )
    return response, connection


def test_create_policy_rejects_role_types_covered_by_static_policies():
    """viewer/editor/obs_manager/sensor/qc are built in -- POST /Policies has
    nothing to create for them, and returns 400 rather than a 200 the caller
    would have to read the body of to learn nothing happened. It issues no
    DDL."""
    response, connection = _call_create_policy(
        {"name": "p1", "permissions": {"type": "viewer"}}
    )

    sql_calls = [c.args[0] for c in connection.execute.await_args_list]
    assert any('SET LOCAL ROLE "administrator";' in sql for sql in sql_calls)
    assert not any("RESET ROLE" in sql for sql in sql_calls)
    assert not any("CREATE POLICY" in sql for sql in sql_calls)
    assert response.status_code == 400
    assert "static RLS policy" in response.body.decode()


def test_create_policy_rejects_users_field():
    """A policy is a named rule set now; who gets it is decided by a custom
    grant, so the old `users` list is refused loudly, not ignored."""
    response, connection = _call_create_policy(
        {
            "users": ["alice"],
            "name": "p1",
            "permissions": {
                "type": "custom",
                "policy": {"datastream": {"select": "id = 1"}},
            },
        }
    )
    assert response.status_code == 400
    assert "users" in response.body.decode()
    assert not any(
        "CREATE POLICY" in c.args[0] for c in connection.execute.await_args_list
    )


def test_create_policy_rejects_unknown_top_level_key():
    response, _ = _call_create_policy(
        {
            "name": "p1",
            "dataset_id": "x",
            "permissions": {
                "type": "custom",
                "policy": {"datastream": {"select": "id = 1"}},
            },
        }
    )
    assert response.status_code == 400
    assert "dataset_id" in response.body.decode()


def test_custom_policy_rules_apply_only_through_a_grant_naming_the_policy():
    """Every generated policy must be gated on a custom grant that names this
    policy (by its id), evaluated once per query -- never on a user id baked
    into the SQL, and never per row."""
    connection = AsyncMock()
    connection.execute = AsyncMock()
    connection.fetchval = AsyncMock(return_value=7)
    attach_transaction_cm(connection)

    asyncio.run(
        create_policy_endpoint.create_policies(
            connection,
            {
                "datastream": {"select": "id IN (1, 2)", "update": "id = 2"},
                "thing": {"select": "true"},
            },
            "p1",
        )
    )

    created = [
        c.args[0]
        for c in connection.execute.await_args_list
        if "CREATE POLICY" in c.args[0]
    ]
    assert len(created) == 3
    for sql in created:
        assert "current_app_user_id() = ANY" not in sql
        assert "current_app_user_role" not in sql
        assert "(SELECT sensorthings.app_policy_" in sql
        assert "(7)" in sql
    ds = [sql for sql in created if "sensorthings.\"Datastream\"" in sql]
    thing = [sql for sql in created if "sensorthings.\"Thing\"" in sql]
    assert len(ds) == 2 and len(thing) == 1
    assert all("app_policy_nets(7)" in sql for sql in ds)
    assert "app_policy_any(7)" in thing[0]
    # id lists are matched with a hashed IN-subquery, not `= ANY (array)`
    # (a linear array scan per row: 9 s vs 0.6 s counting 2M Observations).
    assert all("IN (SELECT unnest(" in sql for sql in ds)
    assert not any("= ANY" in sql for sql in created)


@pytest.mark.parametrize(
    "name",
    ["rbac_hack", "RBAC_x", "bad name", "1abc", "", "a" * 31, 'q"uote'],
)
def test_create_policies_rejects_bad_names(name):
    connection = AsyncMock()
    connection.execute = AsyncMock()
    connection.fetchval = AsyncMock(return_value=7)
    with pytest.raises(ValueError):
        asyncio.run(
            create_policy_endpoint.create_policies(
                connection, {"datastream": {"select": "true"}}, name
            )
        )
    connection.execute.assert_not_awaited()
    connection.fetchval.assert_not_awaited()


def test_create_policies_rejects_unsafe_condition_before_any_write():
    connection = AsyncMock()
    connection.execute = AsyncMock()
    connection.fetchval = AsyncMock(return_value=7)
    with pytest.raises(ValueError):
        asyncio.run(
            create_policy_endpoint.create_policies(
                connection,
                {"datastream": {"select": "true; DROP TABLE x"}},
                "p1",
            )
        )
    # Validation happens first: no CustomPolicy row, no DDL.
    connection.fetchval.assert_not_awaited()
    connection.execute.assert_not_awaited()


def test_duplicate_policy_name_is_409():
    connection = AsyncMock()
    connection.fetchval = AsyncMock(
        side_effect=asyncpg.exceptions.UniqueViolationError("dup")
    )
    response, _ = _call_create_policy(
        {
            "name": "p1",
            "permissions": {
                "type": "custom",
                "policy": {"datastream": {"select": "id = 1"}},
            },
        },
        connection,
    )
    assert response.status_code == 409


def test_condition_that_regular_users_cannot_run_is_refused_before_anything_is_stored():
    """A rule is evaluated for every member's query, so one that fails as the
    `user` role (e.g. it reads the User table) would break reads for all of
    them. It must be refused at creation, with nothing written."""
    connection = AsyncMock()
    connection.execute = AsyncMock()
    # 1st fetchval: current_user; 2nd: the trial query as the user role
    connection.fetchval = AsyncMock(
        side_effect=["administrator", asyncpg.exceptions.InsufficientPrivilegeError("permission denied for table User")]
    )
    attach_transaction_cm(connection)

    with pytest.raises(ValueError) as exc:
        asyncio.run(
            create_policy_endpoint.create_policies(
                connection,
                {"datastream": {"select": 'id IN (SELECT id FROM sensorthings."User")'}},
                "peek",
            )
        )
    assert "cannot be evaluated by regular users" in str(exc.value)
    sql_calls = [c.args[0] for c in connection.execute.await_args_list]
    assert not any("CREATE POLICY" in sql for sql in sql_calls)
    # only current_user and the failed trial -- no CustomPolicy INSERT
    assert connection.fetchval.await_count == 2
    # and the administrator role is restored afterwards
    assert any('SET LOCAL ROLE "administrator"' in sql for sql in sql_calls)
