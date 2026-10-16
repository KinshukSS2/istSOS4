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

"""Tests for PATCH /Users/{id}/networks (replace a user's grants).

Coverage
--------
1. Schema validation (NetworkGrant / NetworksUpdateRequest):
   - Valid grants pass; ``network_name: []`` (all Networks) passes.
   - 'administrator' / 'pending' / unknown roles blocked.
   - Unknown fields (e.g. the removed ``dataset_id``) rejected.
   - ``policy`` only on a 'custom' grant; duplicate Network names rejected.
   - Empty list and over-long lists rejected.

2. CRUD-layer unit tests (DB fully mocked -- no live database):
   - User not found -> 404.
   - Pending user -> 400.
   - No-op: same grants -> no write, no audit.
   - Last-admin lockout -> 409; demoting a non-last admin makes a member.
   - A real change -> grants replaced, ROLE_CHANGED audit with old/new.
   - No PostgreSQL DDL is ever issued.

3. Endpoint authorization:
   - Non-admin caller -> 403 (before any DB contact).
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
API_DIR = str(Path(__file__).resolve().parents[1])
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

os.environ.setdefault("ISTSOS_ADMIN", "admin")
os.environ.setdefault("ISTSOS_ADMIN_PASSWORD", "secret")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "istsos")
os.environ.setdefault("POSTGRES_USER", "admin")
os.environ.setdefault("SECRET_KEY", "test_secret_key_1234567890_abcdef")
os.environ.setdefault("ALGORITHM", "HS256")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user_row(role="member", username="alice", user_id=10):
    """A minimal asyncpg-like Record stub with the columns
    update_user_networks() selects."""
    row = MagicMock()
    row.__getitem__ = lambda self, key: {
        "id": user_id,
        "username": username,
        "role": role,
    }[key]
    return row


def _grant(role="viewer", names=("psos",), policy="", all_networks=False):
    """A resolved/loaded grant in the shape network_grant_crud produces."""
    return {
        "role": role,
        "all_networks": all_networks,
        "network_ids": list(range(1, len(names) + 1)),
        "network_names": list(names),
        "policy_id": None,
        "policy": policy,
    }


def _make_pool(fetchrow_result, fetchval_result=None):
    pool = MagicMock()
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=fetchrow_result)
    conn.fetchval = AsyncMock(return_value=fetchval_result)
    conn.execute = AsyncMock()

    tx = AsyncMock()
    tx.__aenter__ = AsyncMock(return_value=tx)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)

    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool, conn


def _run(coro):
    return asyncio.run(coro)


def _patched(role_crud, pool, *, resolved, old):
    """Context managers replacing the pool and the grant helpers."""
    import contextlib

    stack = contextlib.ExitStack()
    stack.enter_context(
        patch.object(role_crud, "get_pool", AsyncMock(return_value=pool))
    )
    stack.enter_context(patch("app.db.role_crud.POSTGRES_PORT_WRITE", None))
    resolve = stack.enter_context(
        patch.object(role_crud, "resolve_grants", AsyncMock(return_value=resolved))
    )
    stack.enter_context(
        patch.object(
            role_crud, "load_grants", AsyncMock(return_value={10: old})
        )
    )
    replace = stack.enter_context(
        patch.object(role_crud, "replace_user_grants", AsyncMock())
    )
    return stack, resolve, replace


# ===========================================================================
# 1. Pydantic schema validation
# ===========================================================================

class TestNetworksSchema:

    def _req(self):
        from app.models.networks import NetworksUpdateRequest
        return NetworksUpdateRequest

    def test_valid_grant_passes(self):
        r = self._req()(
            networks=[{"network_name": ["psos"], "role": "viewer"}]
        )
        assert r.networks[0].role == "viewer"
        assert r.networks[0].policy == ""

    def test_empty_network_list_means_all_and_passes(self):
        r = self._req()(networks=[{"network_name": [], "role": "viewer"}])
        assert r.networks[0].network_name == []

    def test_custom_grant_with_policy_passes(self):
        r = self._req()(
            networks=[
                {"network_name": ["psos"], "role": "custom", "policy": "p1"}
            ]
        )
        assert r.networks[0].policy == "p1"

    @pytest.mark.parametrize("role", ["administrator", "pending", "superadmin"])
    def test_invalid_role_blocked(self, role):
        from pydantic import ValidationError
        with pytest.raises(ValidationError) as exc:
            self._req()(networks=[{"network_name": ["psos"], "role": role}])
        assert any("Invalid role" in str(e["msg"]) for e in exc.value.errors())

    def test_unknown_field_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._req()(
                networks=[
                    {"network_name": ["psos"], "role": "viewer", "dataset_id": "x"}
                ]
            )

    def test_removed_top_level_role_field_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._req()(role="viewer")

    def test_policy_only_on_custom(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._req()(
                networks=[
                    {"network_name": ["psos"], "role": "viewer", "policy": "p1"}
                ]
            )

    def test_duplicate_network_names_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._req()(
                networks=[{"network_name": ["psos", "psos"], "role": "viewer"}]
            )

    def test_empty_grant_list_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._req()(networks=[])

    @pytest.mark.parametrize("bad", ["a\x00b", "line\nbreak", "tab\there"])
    def test_control_characters_rejected(self, bad):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._req()(networks=[{"network_name": [bad], "role": "viewer"}])
        with pytest.raises(ValidationError):
            self._req()(
                networks=[{"network_name": ["psos"], "role": "custom", "policy": bad}]
            )

    def test_too_many_grants_rejected(self):
        from pydantic import ValidationError
        from app.models.networks import MAX_GRANTS
        grants = [
            {"network_name": [f"n{i}"], "role": "viewer"}
            for i in range(MAX_GRANTS + 1)
        ]
        with pytest.raises(ValidationError):
            self._req()(networks=grants)


# ===========================================================================
# 2. CRUD-layer unit tests (DB mocked)
# ===========================================================================

class TestUpdateUserNetworksCRUD:

    def test_user_not_found_raises_404(self):
        from fastapi import HTTPException
        from app.db import role_crud

        pool, _ = _make_pool(fetchrow_result=None)
        stack, _, _ = _patched(role_crud, pool, resolved=[], old=[])
        with stack:
            with pytest.raises(HTTPException) as exc:
                _run(role_crud.update_user_networks(user_id=999, grants=[]))
        assert exc.value.status_code == 404

    def test_pending_user_raises_400(self):
        from fastapi import HTTPException
        from app.db import role_crud

        pool, _ = _make_pool(fetchrow_result=_make_user_row(role="pending"))
        stack, _, replace = _patched(role_crud, pool, resolved=[_grant()], old=[])
        with stack:
            with pytest.raises(HTTPException) as exc:
                _run(role_crud.update_user_networks(user_id=10, grants=[]))
        assert exc.value.status_code == 400
        assert "pending" in exc.value.detail.lower()
        replace.assert_not_awaited()

    def test_same_grants_is_noop(self):
        from app.db import role_crud

        pool, conn = _make_pool(fetchrow_result=_make_user_row(role="member"))
        same = [_grant("viewer", ("psos",))]
        stack, _, replace = _patched(role_crud, pool, resolved=same, old=same)
        with stack:
            _run(role_crud.update_user_networks(user_id=10, grants=[]))

        replace.assert_not_awaited()
        conn.execute.assert_not_called()

    def test_last_admin_lockout_raises_409(self):
        from fastapi import HTTPException
        from app.db import role_crud

        pool, _ = _make_pool(
            fetchrow_result=_make_user_row(role="administrator"),
            fetchval_result=1,  # only 1 admin in the system
        )
        stack, _, replace = _patched(role_crud, pool, resolved=[_grant()], old=[])
        with stack:
            with pytest.raises(HTTPException) as exc:
                _run(role_crud.update_user_networks(user_id=10, grants=[]))
        assert exc.value.status_code == 409
        assert "last administrator" in exc.value.detail.lower()
        replace.assert_not_awaited()

    def test_demoting_a_non_last_admin_makes_a_member(self):
        from app.db import role_crud

        pool, conn = _make_pool(
            fetchrow_result=_make_user_row(role="administrator"),
            fetchval_result=2,
        )
        executed: list[tuple] = []

        async def _capture(sql, *args):
            executed.append((sql, args))

        conn.execute = _capture
        stack, _, replace = _patched(
            role_crud, pool, resolved=[_grant("editor", ("psos",))], old=[]
        )
        with stack:
            _run(role_crud.update_user_networks(user_id=10, grants=[], actor_id=1))

        replace.assert_awaited_once()
        role_updates = [a for sql, a in executed if 'UPDATE sensorthings."User"' in sql]
        assert role_updates and role_updates[0][0] == "member"

    def test_change_replaces_grants_and_audits_old_and_new(self):
        from app.db import role_crud

        pool, conn = _make_pool(fetchrow_result=_make_user_row(role="member"))
        executed: list[tuple] = []

        async def _capture(sql, *args):
            executed.append((sql, args))

        conn.execute = _capture
        old = [_grant("viewer", ("psos",))]
        new = [_grant("editor", ("psos",)), _grant("viewer", ("acsot",))]
        stack, _, replace = _patched(role_crud, pool, resolved=new, old=old)
        with stack:
            _run(role_crud.update_user_networks(user_id=10, grants=[], actor_id=1))

        replace.assert_awaited_once()
        audit = [a for sql, a in executed if 'INTO sensorthings."AuditLog"' in sql]
        assert len(audit) == 1, "expected exactly one AuditLog INSERT"
        actor_id, action_type, network_name, payload = audit[0]
        assert actor_id == 1
        assert action_type == "ROLE_CHANGED"
        new_rendered = [
            {"network_name": ["psos"], "role": "editor", "policy": ""},
            {"network_name": ["acsot"], "role": "viewer", "policy": ""},
        ]
        assert json.loads(network_name) == new_rendered
        assert json.loads(payload) == {
            "target_user_id": 10,
            "username": "alice",
            "old_networks": [
                {"network_name": ["psos"], "role": "viewer", "policy": ""}
            ],
            "new_networks": new_rendered,
            "demoted_administrator": False,
        }

    def test_no_ddl_is_ever_issued(self):
        from app.db import role_crud

        pool, conn = _make_pool(fetchrow_result=_make_user_row(role="member"))
        executed: list[str] = []

        async def _capture(sql, *args):
            executed.append(sql)

        conn.execute = _capture
        stack, _, _ = _patched(
            role_crud,
            pool,
            resolved=[_grant("obs_manager", ("psos",))],
            old=[_grant("viewer", ("psos",))],
        )
        with stack:
            _run(role_crud.update_user_networks(user_id=10, grants=[]))

        for keyword in ("REVOKE", "GRANT", "CREATE POLICY", "CREATE ROLE"):
            assert not any(keyword in q for q in executed), (
                f"{keyword} must not be issued -- users are app-layer entities"
            )


# ===========================================================================
# 3. Endpoint authorization
# ===========================================================================

class TestPatchUserNetworksEndpoint:

    def test_non_admin_caller_raises_403(self):
        """A member trying to change grants -> 403 before any DB hit."""
        from fastapi import HTTPException
        from app.models.networks import NetworksUpdateRequest
        from app.v1.endpoints.update.role import patch_user_networks

        caller = {"id": 1, "username": "bob", "role": "member"}
        payload = NetworksUpdateRequest(
            networks=[{"network_name": ["psos"], "role": "editor"}]
        )

        with pytest.raises(HTTPException) as exc:
            _run(
                patch_user_networks(
                    user_id=5,
                    payload=payload,
                    current_user=caller,
                )
            )
        assert exc.value.status_code == 403
