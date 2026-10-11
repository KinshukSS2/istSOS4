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

"""Unit tests for app.db.network_grant_crud (database mocked).

Covers the rules every grant-writing endpoint relies on:
  * names resolve to Network ids; unknown / ambiguous names -> 400;
  * ``network_name: []`` (all Networks) is administrator-only;
  * unknown policy -> 400; policy only on a custom grant;
  * same-role grants must not overlap; different roles on the same Network
    are fine (they add up);
  * list-size caps;
  * the per-user commit rule (fixed commit only when every writing grant is
    sensor / qc).
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

API_DIR = str(Path(__file__).resolve().parents[1])
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

os.environ.setdefault("ISTSOS_ADMIN", "admin")
os.environ.setdefault("ISTSOS_ADMIN_PASSWORD", "secret")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("POSTGRES_DB", "istsos")
os.environ.setdefault("SECRET_KEY", "test_secret_key_1234567890_abcdef")
os.environ.setdefault("ALGORITHM", "HS256")

from fastapi import HTTPException  # noqa: E402

from app.db import network_grant_crud as crud  # noqa: E402
from app.models.networks import MAX_GRANTS  # noqa: E402


def _conn(networks=None, policies=None):
    """A connection whose fetch() answers the two lookups resolve_grants
    makes: Network (name, id) rows and CustomPolicy (name, id) rows."""
    networks = networks if networks is not None else [("psos", 2), ("acsot", 1)]
    policies = policies if policies is not None else [("p1", 5)]
    conn = AsyncMock()

    async def _fetch(query, names):
        source = policies if "CustomPolicy" in query else networks
        return [{"name": n, "id": i} for n, i in source if n in names]

    conn.fetch = AsyncMock(side_effect=_fetch)
    return conn


def _resolve(grants, *, admin=True, conn=None, network_on=True):
    conn = conn or _conn()
    with patch.object(crud, "NETWORK", network_on):
        return asyncio.run(crud.resolve_grants(conn, grants, admin=admin))


def _g(role="viewer", names=("psos",), policy=""):
    return {"network_name": list(names), "role": role, "policy": policy}


def _400(grants, **kw):
    with pytest.raises(HTTPException) as exc:
        _resolve(grants, **kw)
    assert exc.value.status_code == 400
    return exc.value.detail


class TestResolveGrants:
    def test_names_become_ids(self):
        out = _resolve([_g("viewer", ("psos", "acsot"))])
        assert out[0]["network_ids"] == [2, 1]
        assert out[0]["all_networks"] is False

    def test_unknown_network_is_400(self):
        assert "nope" in _400([_g("viewer", ("nope",))])

    def test_ambiguous_network_is_400(self):
        conn = _conn(networks=[("psos", 2), ("psos", 9)])
        assert "ambiguous" in _400([_g("viewer", ("psos",))], conn=conn)

    def test_empty_list_means_all_for_admin(self):
        out = _resolve([_g("viewer", ())], admin=True)
        assert out[0]["all_networks"] is True
        assert out[0]["network_ids"] == []

    def test_empty_list_refused_for_non_admin(self):
        assert "administrator" in _400([_g("viewer", ())], admin=False)

    def test_named_networks_fine_for_non_admin(self):
        out = _resolve([_g("viewer", ("psos",))], admin=False)
        assert out[0]["network_ids"] == [2]

    def test_unknown_policy_is_400(self):
        assert "missing" in _400([_g("custom", ("psos",), "missing")])

    def test_known_policy_resolves(self):
        out = _resolve([_g("custom", ("psos",), "p1")])
        assert out[0]["policy_id"] == 5

    def test_policy_on_non_custom_is_400(self):
        _400([_g("viewer", ("psos",), "p1")])

    def test_same_role_same_network_overlap_is_400(self):
        _400([_g("viewer", ("psos",)), _g("viewer", ("psos", "acsot"))])

    def test_all_networks_overlaps_named_same_role(self):
        _400([_g("viewer", ()), _g("viewer", ("psos",))])

    def test_same_role_disjoint_networks_ok(self):
        out = _resolve([_g("viewer", ("psos",)), _g("viewer", ("acsot",))])
        assert len(out) == 2

    def test_different_roles_same_network_add_up(self):
        out = _resolve([_g("viewer", ("psos",)), _g("editor", ("psos",))])
        assert [g["role"] for g in out] == ["viewer", "editor"]

    def test_custom_grants_with_different_policies_may_share_a_network(self):
        conn = _conn(policies=[("p1", 5), ("p2", 6)])
        out = _resolve(
            [_g("custom", ("psos",), "p1"), _g("custom", ("psos",), "p2")],
            conn=conn,
        )
        assert len(out) == 2

    def test_too_many_grants_is_400(self):
        names = [(f"n{i}", i + 1) for i in range(MAX_GRANTS + 1)]
        conn = _conn(networks=names)
        grants = [_g("viewer", (n,)) for n, _ in names]
        _400(grants, conn=conn)

    def test_no_grants_is_400(self):
        _400([])

    def test_network_feature_off_ignores_names(self):
        out = _resolve([_g("viewer", ("whatever",))], network_on=False)
        assert out[0]["all_networks"] is True
        assert out[0]["network_ids"] == []


class TestCommitRule:
    @staticmethod
    def _user(*roles):
        return {"id": 1, "grants": [{"role": r} for r in roles]}

    def test_sensor_only_uses_fixed_commit(self):
        assert crud.uses_fixed_commit(self._user("sensor"), "sensor")

    def test_sensor_plus_viewer_still_fixed(self):
        assert crud.uses_fixed_commit(self._user("sensor", "viewer"), "sensor")

    def test_sensor_plus_editor_commits_normally(self):
        assert not crud.uses_fixed_commit(self._user("sensor", "editor"), "sensor")

    def test_sensor_plus_obs_manager_commits_normally(self):
        assert not crud.uses_fixed_commit(
            self._user("sensor", "obs_manager"), "sensor"
        )

    def test_sensor_plus_custom_commits_normally(self):
        assert not crud.uses_fixed_commit(self._user("sensor", "custom"), "sensor")

    def test_qc_only_uses_fixed_commit(self):
        assert crud.uses_fixed_commit(self._user("qc"), "qc")

    def test_qc_and_sensor_have_both_fixed_commits(self):
        user = self._user("qc", "sensor")
        assert crud.uses_fixed_commit(user, "qc")
        assert crud.uses_fixed_commit(user, "sensor")

    def test_viewer_never_uses_fixed_commit(self):
        assert not crud.uses_fixed_commit(self._user("viewer"), "sensor")
        assert not crud.uses_fixed_commit(self._user("viewer"), "qc")

    def test_anonymous_or_no_grants(self):
        assert not crud.uses_fixed_commit(None, "sensor")
        assert not crud.uses_fixed_commit({"id": 1}, "sensor")


class TestRenderAndEffective:
    def test_render_all_networks_is_empty_list(self):
        rendered = crud.render_grants(
            [
                {
                    "role": "viewer",
                    "all_networks": True,
                    "network_names": [],
                    "policy": "",
                }
            ]
        )
        assert rendered == [{"network_name": [], "role": "viewer", "policy": ""}]

    def test_effective_adds_all_network_grants_to_named(self):
        eff = crud.effective_permissions(
            [
                {
                    "role": "viewer",
                    "all_networks": True,
                    "network_names": [],
                    "policy": "",
                },
                {
                    "role": "editor",
                    "all_networks": False,
                    "network_names": ["psos"],
                    "policy": "",
                },
            ]
        )
        by_name = {e["network_name"]: e["roles"] for e in eff}
        assert by_name["*"] == ["viewer"]
        # grants add up: psos has its own editor plus the all-Networks viewer
        assert by_name["psos"] == ["editor", "viewer"]

    def test_custom_grant_without_policy_warns(self):
        warnings = crud.grant_warnings(
            [
                {
                    "role": "custom",
                    "all_networks": False,
                    "network_names": ["psos"],
                    "policy": "",
                }
            ]
        )
        assert warnings, "a custom grant with no policy should be flagged"
