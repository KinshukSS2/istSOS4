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


def test_create_policy_noops_for_role_types_covered_by_static_policies():
    """viewer/editor/obs_manager/sensor/qc get RLS access automatically from
    006_session_scoped_rls_policies.sql's static policies the moment their
    role is set. That migration DROPs viewer_policy()/.../qc_policy(), so the
    endpoint accepts these types for API compatibility but creates nothing
    and returns 200.
    """
    connection = AsyncMock()
    connection.execute = AsyncMock()
    connection.fetchval = AsyncMock(return_value=0)
    attach_transaction_cm(connection)

    payload = {
        "users": ["alice"],
        "name": "p1",
        "permissions": {"type": "viewer"},
    }
    current_user = {"username": "admin_user", "role": "administrator"}

    response = asyncio.run(
        create_policy_endpoint.create_policy(
            payload=payload,
            current_user=current_user,
            pgpool=mock_pgpool(connection),
        )
    )

    sql_calls = [c.args[0] for c in connection.execute.await_args_list]
    assert any('SET LOCAL ROLE "administrator";' in sql for sql in sql_calls)
    assert not any("RESET ROLE" in sql for sql in sql_calls)
    assert not any("_policy(" in sql for sql in sql_calls)
    assert not any("CREATE POLICY" in sql for sql in sql_calls)
    assert response.status_code == 200


# PATCH /Policies was removed: in-place policy editing depended on the
# per-PG-role model. Policy changes are now DELETE + POST.
