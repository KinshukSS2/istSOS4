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

"""Reading, validating and saving a user's Network grants.

A *grant* says: this user holds ``role`` in these Networks (or in all of
them), optionally with a named custom policy. A user may hold several grants;
their access is the union of all of them.

Three shapes appear here and must not be confused:

* the **API shape** -- ``{"network_name": [...], "role": ..., "policy": ...}``
  (``[]`` = all Networks), see ``app.models.networks``;
* the **resolved shape** -- Network *names* turned into Network *ids*, the
  policy turned into a policy id, ready to be written;
* the **loaded shape** -- what ``load_grants`` returns for a stored grant.

Grants reference Networks and policies by id, never by name, so renaming or
recreating a Network can never silently move a grant onto a different one.
"""

from __future__ import annotations

from app import NETWORK
from app.models.networks import MAX_GRANTS, MAX_NETWORKS_PER_GRANT
from fastapi import HTTPException, status

# Roles that let a user create or change data. A user whose only grants are
# sensor / qc keeps the fixed-commit behaviour of those roles (no commit
# message allowed); any of these makes them an ordinary writer.
WRITING_ROLES = {"editor", "obs_manager", "custom"}

SENSOR_COMMIT = ("CREATE", "Sensor data")
QC_COMMIT = ("UPDATE", "QC data")


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


# ---------------------------------------------------------------------------
# Resolving the API shape
# ---------------------------------------------------------------------------
async def resolve_grants(
    connection, grants, *, admin: bool, min_grants: int = 1
) -> list[dict]:
    """Validate ``grants`` against the database and resolve names to ids.

    ``grants`` is a list of ``NetworkGrant`` models or equivalent dicts.
    ``admin`` must be True only on administrator-initiated writes: it is the
    only way a grant covering *all* Networks (``network_name: []``) is
    accepted.

    Raises HTTPException(400) for every problem the caller can fix.
    """
    items = [g if isinstance(g, dict) else g.model_dump() for g in grants]

    if len(items) < min_grants:
        raise _bad_request(
            "At least one grant is required in 'networks'."
            if min_grants
            else "networks must be a list."
        )
    if len(items) > MAX_GRANTS:
        raise _bad_request(f"At most {MAX_GRANTS} grants are allowed per user.")

    # --- Network names -> ids (one query for the whole list)
    wanted = sorted({n for g in items for n in g["network_name"]})
    if len(wanted) > MAX_GRANTS * MAX_NETWORKS_PER_GRANT:
        raise _bad_request("Too many Networks referenced.")
    by_name: dict[str, list[int]] = {}
    if NETWORK and wanted:
        rows = await connection.fetch(
            'SELECT id, name FROM sensorthings."Network" WHERE name = ANY($1::text[])',
            wanted,
        )
        for row in rows:
            by_name.setdefault(row["name"], []).append(row["id"])
        unknown = [n for n in wanted if n not in by_name]
        if unknown:
            raise _bad_request(
                "No Network named: " + ", ".join(repr(n) for n in unknown) + "."
            )
        ambiguous = [n for n, ids in by_name.items() if len(ids) > 1]
        if ambiguous:
            raise _bad_request(
                "Network name is ambiguous (matches more than one Network): "
                + ", ".join(repr(n) for n in sorted(ambiguous))
                + ". Rename one of them first."
            )

    # --- policy names -> ids
    policy_names = sorted({g["policy"] for g in items if g.get("policy")})
    policy_ids: dict[str, int] = {}
    if policy_names:
        rows = await connection.fetch(
            'SELECT id, name FROM sensorthings."CustomPolicy" WHERE name = ANY($1::text[])',
            policy_names,
        )
        policy_ids = {r["name"]: r["id"] for r in rows}
        missing = [p for p in policy_names if p not in policy_ids]
        if missing:
            raise _bad_request(
                "No policy named: " + ", ".join(repr(p) for p in missing) + "."
            )

    resolved: list[dict] = []
    for g in items:
        names = g["network_name"]
        policy = g.get("policy") or ""
        if policy and g["role"] != "custom":
            raise _bad_request("policy is only allowed on a 'custom' grant.")
        if NETWORK:
            all_networks = len(names) == 0
            if all_networks and not admin:
                raise _bad_request(
                    "Only an administrator can grant access to all Networks."
                )
            ids = [by_name[n][0] for n in names]
        else:
            all_networks, ids, names = True, [], []
        resolved.append(
            {
                "role": g["role"],
                "all_networks": all_networks,
                "network_ids": ids,
                "network_names": names,
                "policy": policy,
                "policy_id": policy_ids.get(policy) if policy else None,
            }
        )

    _reject_overlaps(resolved)
    return resolved


def _reject_overlaps(resolved: list[dict]) -> None:
    """Two grants of the same role (and, for custom, the same policy) must not
    cover a common Network: the second adds nothing and is almost certainly a
    mistake."""
    seen: dict[tuple, list[dict]] = {}
    for g in resolved:
        key = (g["role"], g["policy_id"])
        for other in seen.get(key, []):
            if g["all_networks"] or other["all_networks"] or (
                set(g["network_ids"]) & set(other["network_ids"])
            ):
                label = g["role"] + (f" with policy '{g['policy']}'" if g["policy"] else "")
                raise _bad_request(
                    f"Two '{label}' grants cover the same Network. "
                    "Merge them into one grant."
                )
        seen.setdefault(key, []).append(g)


def normalise_requested(grants) -> list[dict]:
    """Shape an applicant's request for storage in ``requested_networks``.

    A request is only a hint and is never enforced, so Networks stay as names
    and the applicant-supplied ``policy`` is dropped (only an administrator
    assigns policies).
    """
    out = []
    for g in grants:
        d = g if isinstance(g, dict) else g.model_dump()
        out.append({"network_name": list(d["network_name"]), "role": d["role"]})
    return out


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
async def load_grants(connection, user_ids: list[int]) -> dict[int, list[dict]]:
    """Stored grants for the given users, in the *loaded* shape."""
    if not user_ids:
        return {}
    if NETWORK:
        query = """
            SELECT g.user_id, g.id, g.role, g.all_networks, g.policy_id,
                   p.name AS policy,
                   coalesce(array_agg(n.id ORDER BY n.id)
                            FILTER (WHERE n.id IS NOT NULL), ARRAY[]::bigint[]) AS network_ids,
                   coalesce(array_agg(n.name ORDER BY n.id)
                            FILTER (WHERE n.id IS NOT NULL), ARRAY[]::text[]) AS network_names
              FROM sensorthings."UserGrant" g
              LEFT JOIN sensorthings."CustomPolicy" p ON p.id = g.policy_id
              LEFT JOIN sensorthings."UserGrantNetwork" gn ON gn.grant_id = g.id
              LEFT JOIN sensorthings."Network" n ON n.id = gn.network_id
             WHERE g.user_id = ANY($1::bigint[])
             GROUP BY g.user_id, g.id, g.role, g.all_networks, g.policy_id, p.name
             ORDER BY g.id
        """
    else:
        query = """
            SELECT g.user_id, g.id, g.role, g.all_networks, g.policy_id,
                   p.name AS policy,
                   ARRAY[]::bigint[] AS network_ids, ARRAY[]::text[] AS network_names
              FROM sensorthings."UserGrant" g
              LEFT JOIN sensorthings."CustomPolicy" p ON p.id = g.policy_id
             WHERE g.user_id = ANY($1::bigint[])
             ORDER BY g.id
        """
    out: dict[int, list[dict]] = {uid: [] for uid in user_ids}
    for row in await connection.fetch(query, user_ids):
        out[row["user_id"]].append(
            {
                "id": row["id"],
                "role": row["role"],
                "all_networks": row["all_networks"],
                "network_ids": list(row["network_ids"]),
                "network_names": list(row["network_names"]),
                "policy_id": row["policy_id"],
                "policy": row["policy"] or "",
            }
        )
    return out


def render_grants(grants: list[dict]) -> list[dict]:
    """Loaded/resolved grants -> the API shape."""
    return [
        {
            "network_name": [] if g["all_networks"] else list(g["network_names"]),
            "role": g["role"],
            "policy": g.get("policy") or "",
        }
        for g in grants
    ]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
async def replace_user_grants(connection, user_id: int, resolved: list[dict]) -> None:
    """Replace every grant of ``user_id`` with ``resolved``.

    Runs inside the caller's transaction. The user row is locked first, so two
    administrators editing the same account serialise instead of interleaving.
    """
    await connection.fetchval(
        'SELECT id FROM sensorthings."User" WHERE id = $1 FOR UPDATE', user_id
    )
    await connection.execute(
        'DELETE FROM sensorthings."UserGrant" WHERE user_id = $1', user_id
    )
    for g in resolved:
        grant_id = await connection.fetchval(
            """
            INSERT INTO sensorthings."UserGrant" (user_id, role, all_networks, policy_id)
            VALUES ($1, $2, $3, $4) RETURNING id
            """,
            user_id,
            g["role"],
            g["all_networks"],
            g["policy_id"],
        )
        if NETWORK and not g["all_networks"] and g["network_ids"]:
            await connection.execute(
                """
                INSERT INTO sensorthings."UserGrantNetwork" (grant_id, network_id)
                SELECT $1, unnest($2::bigint[])
                """,
                grant_id,
                g["network_ids"],
            )
    await ensure_fixed_commits(connection, user_id, {g["role"] for g in resolved})


async def ensure_fixed_commits(connection, user_id: int, roles: set[str]) -> None:
    """Make sure the fixed commit rows exist for sensor / qc grants.

    set_commit() writes a sensor's or qc's data against one pre-created Commit
    row per user (they may not supply a commit message). Approval and grant
    changes used to leave that row out, so their writes carried no commit.
    """
    wanted = []
    if "sensor" in roles:
        wanted.append(SENSOR_COMMIT)
    if "qc" in roles:
        wanted.append(QC_COMMIT)
    if not wanted:
        return
    user = await connection.fetchrow(
        'SELECT username, uri FROM sensorthings."User" WHERE id = $1', user_id
    )
    author = (user["uri"] or user["username"]) if user else str(user_id)
    for action, message in wanted:
        await _fixed_commit_id(connection, user_id, author, action, message)


async def _fixed_commit_id(connection, user_id, author, action, message) -> int:
    commit_id = await connection.fetchval(
        'SELECT id FROM sensorthings."Commit" '
        'WHERE user_id = $1 AND "actionType" = $2 ORDER BY id LIMIT 1',
        user_id,
        action,
    )
    if commit_id is None:
        commit_id = await connection.fetchval(
            """
            INSERT INTO sensorthings."Commit"
                (author, message, "encodingType", "actionType", user_id)
            VALUES ($1, $2, 'text/plain', $3, $4) RETURNING id
            """,
            author,
            message,
            action,
            user_id,
        )
    return commit_id


async def fixed_commit_id(connection, current_user: dict, action: str) -> int:
    """The user's fixed commit for ``action`` (created on first use)."""
    message = SENSOR_COMMIT[1] if action == SENSOR_COMMIT[0] else QC_COMMIT[1]
    return await _fixed_commit_id(
        connection,
        current_user["id"],
        current_user.get("uri") or current_user.get("username"),
        action,
        message,
    )


# ---------------------------------------------------------------------------
# Commit rule helpers (used by the three set_commit() functions)
# ---------------------------------------------------------------------------
def grant_roles(current_user: dict | None) -> set[str]:
    if not current_user:
        return set()
    return {g["role"] for g in current_user.get("grants", [])}


def uses_fixed_commit(current_user: dict | None, role: str) -> bool:
    """True when ``current_user`` must use the fixed commit of ``role``
    (``"sensor"`` or ``"qc"``): they hold that grant and no grant that makes
    them an ordinary writer."""
    roles = grant_roles(current_user)
    return role in roles and not (roles & WRITING_ROLES)


# ---------------------------------------------------------------------------
# Approval response helpers
# ---------------------------------------------------------------------------
def _label(g: dict) -> str:
    return f"custom:{g['policy']}" if g["role"] == "custom" and g.get("policy") else g["role"]


def effective_permissions(resolved: list[dict]) -> list[dict]:
    """What the user ends up holding, per Network.

    ``"*"`` stands for every Network. A named Network lists its own grants plus
    those of the all-Networks grants (access adds up).
    """
    everywhere = sorted({_label(g) for g in resolved if g["all_networks"]})
    per_network: dict[str, set[str]] = {}
    for g in resolved:
        if g["all_networks"]:
            continue
        for name in g["network_names"]:
            per_network.setdefault(name, set()).add(_label(g))
    out = []
    if everywhere:
        out.append({"network_name": "*", "roles": everywhere})
    for name in sorted(per_network):
        out.append({"network_name": name, "roles": sorted(per_network[name] | set(everywhere))})
    return out


def grant_warnings(resolved: list[dict]) -> list[str]:
    warnings = []
    for i, g in enumerate(resolved, 1):
        where = "all Networks" if g["all_networks"] else ", ".join(g["network_names"])
        if g["role"] == "custom" and not g["policy"]:
            warnings.append(
                f"Grant {i} (custom on {where}) has no policy, so it gives no access."
            )
        if g["role"] == "viewer":
            for h in resolved:
                if h is g or h["role"] != "editor":
                    continue
                if h["all_networks"] or (
                    not g["all_networks"] and set(g["network_ids"]) <= set(h["network_ids"])
                ):
                    warnings.append(
                        f"Grant {i} (viewer on {where}) adds nothing: an editor grant "
                        "already covers it."
                    )
                    break
    return warnings
