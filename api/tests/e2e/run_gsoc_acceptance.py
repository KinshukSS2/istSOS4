#!/usr/bin/env python3
# Copyright 2025 SUPSI
#
# Licensed under the Apache License, Version 2.0 (the "License").
#
# Full acceptance sweep for the GSoC authentication + authorization work.
#
# Every check below is a behaviour that does NOT exist in upstream/main, or
# one that upstream has and this branch had to keep working. It runs against
# a live stack -- nothing is mocked.
#
#   docker compose up -d --build      # .env: AUTHORIZATION=1 NETWORK=1
#                                     #       ANONYMOUS_VIEWER=0
#   python api/tests/e2e/run_gsoc_acceptance.py
#
# Exits non-zero if any check fails.

import os
import subprocess
import sys
import time
import uuid

import requests

BASE = os.getenv("ISTSOS_BASE", "http://localhost:8018/istsos4/v1.1")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin")
DB = os.getenv("DB_CONTAINER", "istsos4-database")

TAG = uuid.uuid4().hex[:6]
PW = "CorrectHorseBattery1!"

_results = []
_section = ""


def section(name):
    global _section
    _section = name
    print(f"\n\033[1m{name}\033[0m")


def check(name, cond, detail=""):
    _results.append((_section, name, bool(cond)))
    mark = "\033[32mPASS\033[0m" if cond else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f"   ({detail})" if detail else ""))
    return bool(cond)


def psql(sql):
    out = subprocess.run(
        ["docker", "exec", DB, "psql", "-U", "postgres", "-d", "istsos", "-tAc", sql],
        capture_output=True, text=True,
    )
    return out.stdout.strip()


def login(u, p):
    return requests.post(f"{BASE}/Login", data={"username": u, "password": p}, timeout=10)


def tok_of(resp):
    try:
        return resp.json()["access_token"]
    except Exception:  # noqa: BLE001
        return None


def H(t):
    return {"Authorization": f"Bearer {t}"}


def count(entity, t, extra=None):
    p = {"$count": "true", "$top": 1}
    if extra:
        p.update(extra)
    r = requests.get(f"{BASE}/{entity}", params=p, headers=H(t), timeout=30)
    if r.status_code != 200:
        return None
    return r.json().get("@iot.count")


def main():
    t0 = time.time()
    print(f"istSOS: {BASE}    run tag: {TAG}")

    # ==================================================================
    section("1. Anonymous access is denied  (ANONYMOUS_VIEWER=0)")
    # upstream: same contract -- this branch broke it, then restored it.
    # ==================================================================
    r = requests.get(f"{BASE}/Datastreams", timeout=10)
    check("GET /Datastreams without a token -> 401", r.status_code == 401,
          f"HTTP {r.status_code}")
    r = requests.get(f"{BASE}/Observations", timeout=10)
    check("GET /Observations without a token -> 401", r.status_code == 401,
          f"HTTP {r.status_code}")
    r = requests.get(f"{BASE}/Users", timeout=10)
    check("GET /Users without a token -> 401", r.status_code == 401,
          f"HTTP {r.status_code}")

    # ==================================================================
    section("2. Local authentication  (bcrypt in User.password -- NEW)")
    # ==================================================================
    r = login(ADMIN_USER, ADMIN_PASS)
    admin = tok_of(r)
    check("admin login -> 200 + JWT", r.status_code == 200 and admin,
          f"HTTP {r.status_code}")
    check("wrong password -> 401", login(ADMIN_USER, "nope").status_code == 401)
    check("unknown user -> 401", login(f"ghost{TAG}", PW).status_code == 401)

    admin_ct = psql("SELECT count(*) FROM sensorthings.\"User\" "
                    "WHERE password IS NOT NULL AND password LIKE '$2%'")
    check("passwords stored as bcrypt hashes, not PG roles", admin_ct != "0",
          f"{admin_ct} bcrypt row(s)")
    # The app-layer pivot: the only PostgreSQL roles that may exist are the
    # service account + the fixed group roles. No role is ever created per
    # istSOS user.
    extra_roles = psql(
        "SELECT coalesce(string_agg(rolname, ','), '-') FROM pg_roles "
        "WHERE rolname NOT LIKE 'pg\\_%' AND rolname NOT IN "
        "('postgres','admin','administrator','guest','user','sensor','qc')")
    check("istSOS users are NOT PostgreSQL roles (no per-user CREATE ROLE)",
          extra_roles == "-", f"unexpected pg_roles: {extra_roles}")

    # ==================================================================
    section("3. GET /Users payload  (new columns, grants list, no secret leak)")
    # ==================================================================
    r = requests.get(f"{BASE}/Users", headers=H(admin), timeout=10)
    users = r.json().get("value", [])
    row = users[0] if users else {}
    check("GET /Users -> 200", r.status_code == 200)
    for col in ("auth_provider", "external_sub_id", "status", "networks",
                "requested_networks", "possible_duplicate_of"):
        check(f"exposes new column '{col}'", col in row)
    check("does NOT expose the bcrypt hash", "password" not in row,
          "upstream had no password column at all")

    net = psql('SELECT name FROM sensorthings."Network" ORDER BY id LIMIT 1')
    net2 = psql('SELECT name FROM sensorthings."Network" ORDER BY id DESC LIMIT 1')

    # ==================================================================
    section("4. POST /Users -- admin-created account can log in")
    # regression: the handler used to pop() the password and drop it.
    # ==================================================================
    du = f"direct_{TAG}"
    r = requests.post(f"{BASE}/Users", headers=H(admin),
                      json={"username": du, "password": PW,
                            "networks": [{"network_name": [net], "role": "viewer"}]},
                      timeout=15)
    check("POST /Users -> 2xx", 200 <= r.status_code < 300, f"HTTP {r.status_code}")
    check("the created user can actually authenticate",
          login(du, PW).status_code == 200)
    r = requests.post(f"{BASE}/Users", headers=H(admin),
                      json={"username": f"bad_{TAG}", "password": PW,
                            "networks": [{"network_name": [net],
                                          "role": "not_a_role"}]}, timeout=15)
    check("invalid role -> 400 (was an unhandled 500)", r.status_code == 400,
          f"HTTP {r.status_code}")
    r = requests.post(f"{BASE}/Users", headers=H(admin),
                      json={"username": f"old_{TAG}", "password": PW,
                            "role": "viewer"}, timeout=15)
    check("the removed single `role` field -> 400 (no silent fallback)",
          r.status_code == 400, f"HTTP {r.status_code}")
    r = requests.post(f"{BASE}/Users", headers=H(admin),
                      json={"username": f"ghost_{TAG}", "password": PW,
                            "networks": [{"network_name": ["NoSuchNetwork"],
                                          "role": "viewer"}]}, timeout=15)
    check("unknown Network name -> 400", r.status_code == 400,
          f"HTTP {r.status_code}")
    du_grants = psql(
        "SELECT g.role || '|' || n.name FROM sensorthings.\"UserGrant\" g "
        "JOIN sensorthings.\"UserGrantNetwork\" gn ON gn.grant_id = g.id "
        "JOIN sensorthings.\"Network\" n ON n.id = gn.network_id "
        f"JOIN sensorthings.\"User\" u ON u.id = g.user_id WHERE u.username = '{du}'")
    check("the grant was saved (viewer on the chosen Network)",
          du_grants == f"viewer|{net}", du_grants)

    # ==================================================================
    section("5. Self-registration -> pending waiting room  (NEW endpoint)")
    # ==================================================================
    ru = f"reg_{TAG}"
    body = {
        "username": ru, "password": PW,
        "contact_info": {"email": f"{ru}@example.com"},
        "explanation": "gsoc acceptance run",
        "networks": [{"network_name": [net], "role": "viewer"}],
    }
    r = requests.post(f"{BASE}/Register", json=body, timeout=15)
    check("POST /Register (public, no token) -> 201", r.status_code == 201,
          f"HTTP {r.status_code}")
    reg_id = r.json().get("id") if r.status_code == 201 else None

    st = psql(f"SELECT role || '|' || status || '|' || "
              f"coalesce(requested_networks->0->>'role','-') || '|' || "
              f"coalesce(requested_networks->0->'network_name'->>0,'-') "
              f"FROM sensorthings.\"User\" WHERE username = '{ru}'")
    check("row is role=pending status=pending, request recorded",
          st == f"pending|pending|viewer|{net}", st)
    ng = psql(f"SELECT count(*) FROM sensorthings.\"UserGrant\" "
              f"WHERE user_id = {reg_id}")
    check("a request is NOT a grant: no access rows exist yet", ng == "0", ng)

    r = login(ru, PW)
    check("pending user CANNOT log in -> 403 (no dead JWT issued)",
          r.status_code == 403, f"HTTP {r.status_code}")

    r = requests.get(f"{BASE}/Users", headers=H(admin), timeout=10)
    me = [u for u in r.json().get("value", []) if u["username"] == ru]
    check("admin queue shows status='pending', not a misleading 'active'",
          me and me[0]["status"] == "pending",
          me[0]["status"] if me else "row missing")

    check("duplicate username -> 409",
          requests.post(f"{BASE}/Register", json=body, timeout=15).status_code == 409)

    # ==================================================================
    section("6. Admin approval + network scoping  (NEW)")
    # ==================================================================
    r = requests.patch(f"{BASE}/Users/{reg_id}/policy-approval", headers=H(admin),
                       json={}, timeout=15)
    check("approval with neither `networks` nor `approve_as_requested` -> 422",
          r.status_code == 422, f"HTTP {r.status_code}")
    r = requests.patch(f"{BASE}/Users/{reg_id}/policy-approval", headers=H(admin),
                       json={"networks": [{"network_name": [net], "role": "viewer"}],
                             "dataset_id": net}, timeout=15)
    check("an unknown field in the approval body -> 422 (never silently ignored)",
          r.status_code == 422, f"HTTP {r.status_code}")
    r = requests.patch(f"{BASE}/Users/{reg_id}/policy-approval", headers=H(admin),
                       json={"networks": [{"network_name": ["NoSuchNetwork"],
                                           "role": "viewer"}]}, timeout=15)
    check("approval with an unknown Network -> 400 (validated, not silent)",
          r.status_code == 400, f"HTTP {r.status_code}")
    st = psql(f"SELECT role || '|' || status FROM sensorthings.\"User\" "
              f"WHERE username = '{ru}'")
    check("...and a refused approval leaves the user pending", st == "pending|pending", st)

    r = requests.patch(f"{BASE}/Users/{reg_id}/policy-approval", headers=H(admin),
                       json={"networks": [{"network_name": [net], "role": "viewer"}]},
                       timeout=15)
    check("PATCH /Users/{id}/policy-approval -> 200", r.status_code == 200,
          f"HTTP {r.status_code}: {r.text[:90]}")
    body_ok = r.json() if r.status_code == 200 else {}
    check("response shows requested, granted and effective access",
          all(k in body_ok for k in ("requested", "granted", "effective", "warnings")))
    st = psql(f"SELECT role || '|' || status FROM sensorthings.\"User\" "
              f"WHERE username = '{ru}'")
    check("approved row is a member, status=active", st == "member|active", st)

    r = login(ru, PW)
    viewer = tok_of(r)
    check("approved user can now log in", r.status_code == 200 and viewer)

    # ground truth straight from the database
    ds_net = int(psql('SELECT count(*) FROM sensorthings."Datastream" '
                      f"WHERE network_id = (SELECT id FROM sensorthings.\"Network\" WHERE name='{net}')"))
    ds_all = int(psql('SELECT count(*) FROM sensorthings."Datastream"'))
    obs_net = int(psql('SELECT count(*) FROM sensorthings."Observation" o '
                       'JOIN sensorthings."Datastream" d ON d.id = o.datastream_id '
                       f"WHERE d.network_id = (SELECT id FROM sensorthings.\"Network\" WHERE name='{net}')"))
    obs_all = int(psql('SELECT count(*) FROM sensorthings."Observation"'))
    print(f"    ground truth: network '{net}' = {ds_net}/{ds_all} datastreams, "
          f"{obs_net}/{obs_all} observations")

    check("admin (unscoped) sees ALL datastreams",
          count("Datastreams", admin) == ds_all, f"{count('Datastreams', admin)}")
    check("scoped viewer sees ONLY its network's datastreams (RLS)",
          count("Datastreams", viewer) == ds_net,
          f"saw {count('Datastreams', viewer)}, expected {ds_net}")
    check("scoped viewer sees ONLY its network's observations (RLS)",
          count("Observations", viewer) == obs_net,
          f"saw {count('Observations', viewer)}, expected {obs_net}")

    seen = requests.get(f"{BASE}/Datastreams",
                        params={"$top": 200, "$expand": "Network($select=name)"},
                        headers=H(viewer), timeout=30).json().get("value", [])
    names = {d.get("Network", {}).get("name") for d in seen}
    check("every row the viewer sees belongs to its network", names == {net},
          str(names))

    r = requests.patch(f"{BASE}/Datastreams({seen[0]['@iot.id']})" if seen
                       else f"{BASE}/Datastreams(1)",
                       headers={**H(viewer), "commit-message": "acceptance"},
                       json={"name": f"nope_{TAG}"}, timeout=15)
    check("viewer cannot write (read-only role enforced)", r.status_code >= 400,
          f"HTTP {r.status_code}")

    # ==================================================================
    section("7. Changing an ACTIVE user's access  (NEW -- PATCH /Users/{id}/networks)")
    # ==================================================================
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [{"network_name": [net], "role": "editor"}]},
                       timeout=15)
    check("change the role on the same Network -> 204", r.status_code == 204,
          f"HTTP {r.status_code}")
    g = psql(f"SELECT string_agg(role, ',') FROM sensorthings.\"UserGrant\" "
             f"WHERE user_id={reg_id}")
    check("the saved grant is now editor", g == "editor", g)

    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [{"network_name": [net2], "role": "editor"}]},
                       timeout=15)
    check("move the grant to the other Network -> 204", r.status_code == 204,
          f"HTTP {r.status_code}")

    ed = tok_of(login(ru, PW))
    ds_net2 = int(psql('SELECT count(*) FROM sensorthings."Datastream" '
                       f"WHERE network_id = (SELECT id FROM sensorthings.\"Network\" WHERE name='{net2}')"))
    check("re-scoped user's visibility followed the change, live",
          count("Datastreams", ed) == ds_net2,
          f"saw {count('Datastreams', ed)}, expected {ds_net2}")

    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [{"network_name": ["NoSuchNetwork"],
                                           "role": "viewer"}]}, timeout=15)
    check("unknown Network on a change -> 400", r.status_code == 400,
          f"HTTP {r.status_code}")
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={}, timeout=15)
    check("empty body -> 422 (`networks` is required)",
          r.status_code == 422, f"HTTP {r.status_code}")
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": []}, timeout=15)
    check("an empty grant list -> 422 (deactivate the user instead)",
          r.status_code == 422, f"HTTP {r.status_code}")
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [
                           {"network_name": [net], "role": "viewer"},
                           {"network_name": [net], "role": "viewer"}]}, timeout=15)
    check("two same-role grants on the same Network -> 400", r.status_code == 400,
          f"HTTP {r.status_code}")

    # network_name [] = every Network
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [{"network_name": [], "role": "viewer"}]},
                       timeout=15)
    ed = tok_of(login(ru, PW))
    check("network_name [] grants every Network -> sees everything",
          r.status_code == 204 and count("Datastreams", ed) == ds_all,
          f"saw {count('Datastreams', ed)}, expected {ds_all}")

    # one user, different roles on different Networks
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [
                           {"network_name": [net], "role": "viewer"},
                           {"network_name": [net2], "role": "editor"}]}, timeout=15)
    ed = tok_of(login(ru, PW))
    check("viewer on one Network + editor on another -> sees both",
          r.status_code == 204 and count("Datastreams", ed) == ds_all,
          f"saw {count('Datastreams', ed)}, expected {ds_all}")
    ds_a = psql('SELECT min(id) FROM sensorthings."Datastream" WHERE network_id = '
                f"(SELECT id FROM sensorthings.\"Network\" WHERE name='{net}')")
    ds_b = psql('SELECT min(id) FROM sensorthings."Datastream" WHERE network_id = '
                f"(SELECT id FROM sensorthings.\"Network\" WHERE name='{net2}')")
    if ds_a and ds_b:
        wa = requests.patch(f"{BASE}/Datastreams({ds_a})",
                            headers={**H(ed), "commit-message": "acceptance"},
                            json={"description": f"x_{TAG}"}, timeout=15)
        wb = requests.patch(f"{BASE}/Datastreams({ds_b})",
                            headers={**H(ed), "commit-message": "acceptance"},
                            json={"description": f"x_{TAG}"}, timeout=15)
        check("...it may write only where it is an editor",
              wa.status_code >= 400 and 200 <= wb.status_code < 300,
              f"viewer-side HTTP {wa.status_code}, editor-side HTTP {wb.status_code}")
    else:
        check("...it may write only where it is an editor", False,
              "could not find a datastream in each Network")

    # ==================================================================
    section("8. Rejection + re-application  (NEW)")
    # ==================================================================
    ru2 = f"rej_{TAG}"
    body2 = dict(body, username=ru2)
    body2["contact_info"] = {"email": f"{ru2}@example.com"}
    rid2 = requests.post(f"{BASE}/Register", json=body2, timeout=15).json().get("id")
    r = requests.patch(f"{BASE}/Users/{rid2}/reject", headers=H(admin),
                       json={"reason": "acceptance run"}, timeout=15)
    check("PATCH /Users/{id}/reject -> 200", r.status_code == 200,
          f"HTTP {r.status_code}")
    st = psql(f"SELECT role || '|' || status FROM sensorthings.\"User\" WHERE id={rid2}")
    check("rejected row is role=pending status=rejected", st == "pending|rejected", st)
    lr = login(ru2, PW)
    check("rejected user still cannot log in (401 + explanatory message)",
          lr.status_code in (401, 403) and "reject" in lr.text.lower(),
          f"HTTP {lr.status_code}: {lr.text[:70]}")

    r = requests.post(f"{BASE}/Register", json=body2, timeout=15)
    check("rejected user may RE-APPLY -> 201 (not 409)", r.status_code == 201,
          f"HTTP {r.status_code}")
    st = psql(f"SELECT role || '|' || status FROM sensorthings.\"User\" WHERE id={rid2}")
    check("re-application resets to role=pending status=pending",
          st == "pending|pending", st)

    # ==================================================================
    section("9. Policies  (named rule sets, used through a `custom` grant)")
    # ==================================================================
    r = requests.get(f"{BASE}/Policies", headers=H(admin), timeout=15)
    check("GET /Policies -> 200", r.status_code == 200, f"HTTP {r.status_code}")
    pol_count = len(r.json().get("value", [])) if r.status_code == 200 else 0
    check("static RLS policies exist in the database", pol_count > 0,
          f"{pol_count} policies")

    r = requests.post(f"{BASE}/Policies", headers=H(admin),
                      json={"name": f"noop_{TAG}",
                            "permissions": {"type": "viewer"}}, timeout=15)
    check("POST /Policies type=viewer -> 400 (built in, nothing to create)",
          r.status_code == 400, f"HTTP {r.status_code}: {r.text[:80]}")
    r = requests.post(f"{BASE}/Policies", headers=H(admin),
                      json={"name": f"nop_{TAG}"}, timeout=15)
    check("POST /Policies missing 'permissions' -> 400",
          r.status_code == 400, f"HTTP {r.status_code}")
    r = requests.post(f"{BASE}/Policies", headers=H(admin),
                      json={"users": [ru], "name": f"usr_{TAG}",
                            "permissions": {"type": "custom", "policy": {
                                "datastream": {"select": "true"}}}}, timeout=15)
    check("POST /Policies with the removed `users` field -> 400",
          r.status_code == 400, f"HTTP {r.status_code}: {r.text[:80]}")

    r = requests.patch(f"{BASE}/Policies", headers=H(admin), json={}, timeout=10)
    check("PATCH /Policies -> 405 (broken endpoint removed)",
          r.status_code == 405, f"HTTP {r.status_code}")

    pol_name = f"cust_{TAG}"
    r = requests.post(f"{BASE}/Policies", headers=H(admin),
                      json={"name": pol_name,
                            "permissions": {
                                "type": "custom",
                                "policy": {"datastream": {"select": "id % 2 = 0"}},
                            }}, timeout=15)
    made = 200 <= r.status_code < 300
    check("POST /Policies type=custom -> creates the rule set",
          made, f"HTTP {r.status_code}: {r.text[:100]}")
    r = requests.post(f"{BASE}/Policies", headers=H(admin),
                      json={"name": pol_name,
                            "permissions": {"type": "custom", "policy": {
                                "datastream": {"select": "true"}}}}, timeout=15)
    check("the same policy name again -> 409", r.status_code == 409,
          f"HTTP {r.status_code}")

    cu = f"cust_{TAG}"
    r = requests.post(f"{BASE}/Users", headers=H(admin),
                      json={"username": cu, "password": PW,
                            "networks": [{"network_name": [net], "role": "custom",
                                          "policy": pol_name}]}, timeout=15)
    check("POST /Users with a custom grant naming the policy -> 2xx",
          200 <= r.status_code < 300, f"HTTP {r.status_code}: {r.text[:80]}")
    r = requests.post(f"{BASE}/Users", headers=H(admin),
                      json={"username": f"nopol_{TAG}", "password": PW,
                            "networks": [{"network_name": [net], "role": "custom",
                                          "policy": "NoSuchPolicy"}]}, timeout=15)
    check("a custom grant naming an unknown policy -> 400",
          r.status_code == 400, f"HTTP {r.status_code}")
    ctok = tok_of(login(cu, PW))
    if made:
        even = int(psql('SELECT count(*) FROM sensorthings."Datastream" '
                        "WHERE id % 2 = 0 AND network_id = "
                        f"(SELECT id FROM sensorthings.\"Network\" WHERE name='{net}')"))
        got = count("Datastreams", ctok)
        check("the custom rule is enforced, and only inside the grant's Network",
              got == even, f"saw {got}, expected {even}")
        pol = psql("SELECT count(*) FROM pg_policies WHERE schemaname='sensorthings' "
                   f"AND policyname LIKE '{pol_name}%' AND qual LIKE '%app_policy_%'")
        check("policy is group-scoped + grant lookup (not a dead TO <username>)",
              pol != "0", f"{pol} grant-scoped policies")
        roles = psql("SELECT coalesce(string_agg(DISTINCT r, ','), '-') FROM "
                     "(SELECT unnest(roles) AS r FROM pg_policies "
                     "WHERE schemaname='sensorthings') s "
                     "WHERE r NOT IN ('user','sensor','qc','administrator','guest','public')")
        check("no policy targets a per-user PG role (the pivot holds)",
              roles == "-", f"unexpected policy roles: {roles}")

        r = requests.delete(f"{BASE}/Policies", headers=H(admin),
                            params={"policy": pol_name}, timeout=15)
        check("DELETE /Policies while a grant uses it -> 409",
              r.status_code == 409, f"HTTP {r.status_code}: {r.text[:80]}")

        cu_id = psql(f"SELECT id FROM sensorthings.\"User\" WHERE username='{cu}'")
        requests.patch(f"{BASE}/Users/{cu_id}/networks", headers=H(admin),
                       json={"networks": [{"network_name": [net], "role": "viewer"}]},
                       timeout=15)
        r = requests.delete(f"{BASE}/Policies", headers=H(admin),
                            params={"policy": pol_name}, timeout=15)
        check("DELETE /Policies once nothing uses it -> 2xx",
              200 <= r.status_code < 300, f"HTTP {r.status_code}: {r.text[:80]}")
        left = psql("SELECT count(*) FROM pg_policies WHERE schemaname='sensorthings' "
                    f"AND policyname LIKE '{pol_name}%'")
        check("...and every PostgreSQL policy it created is gone", left == "0", left)
        r = requests.delete(f"{BASE}/Policies", headers=H(admin),
                            params={"policy": pol_name}, timeout=15)
        check("deleting it again -> 404", r.status_code == 404,
              f"HTTP {r.status_code}")

    # ==================================================================
    section("10. Audit trail  (NEW -- append-only)")
    # ==================================================================
    n = psql("SELECT count(*) FROM sensorthings.\"AuditLog\" "
             "WHERE action_type = 'RESTRICTED_REQUEST'")
    check("registrations wrote RESTRICTED_REQUEST rows", n != "0", f"{n} rows")
    n = psql("SELECT count(*) FROM sensorthings.\"AuditLog\" "
             "WHERE action_type = 'ADMIN_APPROVAL'")
    check("approvals wrote ADMIN_APPROVAL rows", n != "0", f"{n} rows")
    upd = subprocess.run(
        ["docker", "exec", DB, "psql", "-U", "postgres", "-d", "istsos", "-c",
         'SET ROLE "administrator"; UPDATE sensorthings."AuditLog" SET action_type=\'X\';'],
        capture_output=True, text=True)
    check("AuditLog is append-only (owner cannot UPDATE)",
          "permission denied" in (upd.stderr + upd.stdout).lower(),
          (upd.stderr or upd.stdout).strip().splitlines()[-1][:70] if (upd.stderr or upd.stdout) else "")

    # ==================================================================
    section("11. Session/JWT lifecycle")
    # ==================================================================
    r = requests.post(f"{BASE}/Refresh", headers=H(admin), timeout=10)
    check("POST /Refresh -> 2xx", 200 <= r.status_code < 300, f"HTTP {r.status_code}")
    # With REDIS=1, /Refresh revokes the token it was called with, so carry on
    # with the fresh one it returns (harmless with REDIS=0).
    if r.ok and r.json().get("access_token"):
        admin = r.json()["access_token"]
    throw = tok_of(login(du, PW))
    r = requests.post(f"{BASE}/Logout", headers=H(throw), timeout=10)
    check("POST /Logout -> 2xx", 200 <= r.status_code < 300, f"HTTP {r.status_code}")
    # tokens carry no unique id: a login in the same second as the logout would
    # get the identical, now-revoked string when REDIS=1
    time.sleep(1.1)
    r = requests.get(f"{BASE}/Datastreams", params={"$top": 1}, headers=H(throw),
                     timeout=10)
    # The deny-list is a property of the running API, not of this script's
    # shell, so ask the container (fall back to the caller's env).
    api_env = subprocess.run(
        ["docker", "exec", os.getenv("API_CONTAINER", "istsos4-api"), "printenv", "REDIS"],
        capture_output=True, text=True).stdout.strip()
    redis_on = (api_env or os.getenv("REDIS", "0")) not in ("0", "", "false", "False")
    if redis_on:
        check("token is revoked after logout -> 401", r.status_code == 401,
              f"HTTP {r.status_code}")
    else:
        check("logout revocation needs REDIS=1 (config, not a defect)",
              r.status_code == 200,
              "REDIS=0 -> the deny-list is disabled, token stays valid "
              "until it expires; same as upstream")

    # Deactivation is the revocation path that works without Redis: the role
    # and status are re-read from the database on every single request.
    dead = tok_of(login(du, PW))
    du_id = psql(f"SELECT id FROM sensorthings.\"User\" WHERE username='{du}'")
    requests.delete(f"{BASE}/Users/{du_id}", headers=H(admin), timeout=15)
    r = requests.get(f"{BASE}/Datastreams", params={"$top": 1}, headers=H(dead),
                     timeout=10)
    check("an already-issued JWT dies the moment the account is deactivated",
          r.status_code in (401, 403), f"HTTP {r.status_code}")

    r = requests.get(f"{BASE}/Datastreams", params={"$top": 1},
                     headers={"Authorization": "Bearer garbage.token.here"}, timeout=10)
    check("forged/garbage token -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    # ==================================================================
    section("12. Privilege boundaries")
    # ==================================================================
    vt = tok_of(login(ru, PW))
    check("non-admin GET /Users -> 401/403",
          requests.get(f"{BASE}/Users", headers=H(vt), timeout=10).status_code in (401, 403))
    check("non-admin POST /Users -> 401/403",
          requests.post(f"{BASE}/Users", headers=H(vt),
                        json={"username": f"x{TAG}", "password": PW,
                              "networks": [{"network_name": [net],
                                            "role": "viewer"}]},
                        timeout=10).status_code in (401, 403))
    check("non-admin can't approve -> 401/403",
          requests.patch(f"{BASE}/Users/{rid2}/policy-approval", headers=H(vt),
                         json={"approve_as_requested": True},
                         timeout=10).status_code in (401, 403))
    # a *valid* body, so authorization is what rejects this, not validation
    check("non-admin can't change access -> 401/403",
          requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(vt),
                         json={"networks": [{"network_name": [net],
                                             "role": "qc"}]},
                         timeout=10).status_code in (401, 403))
    r = requests.post(f"{BASE}/Register", timeout=10, json={
        "username": f"esc_{TAG}", "password": PW,
        "contact_info": {"email": f"esc_{TAG}@example.com"},
        "explanation": "x", "networks": [{"network_name": [], "role": "viewer"}]})
    esc_id = r.json().get("id") if r.status_code == 201 else None
    esc_grants = psql(f"SELECT count(*) FROM sensorthings.\"UserGrant\" "
                      f"WHERE user_id = {esc_id}") if esc_id else "?"
    check("an applicant asking for ALL Networks (`[]`) is only a request: "
          "pending, no grant saved, cannot log in",
          r.status_code == 201 and esc_grants == "0"
          and login(f"esc_{TAG}", PW).status_code == 403,
          f"HTTP {r.status_code}, grants={esc_grants}")
    r = requests.patch(f"{BASE}/Users/{reg_id}/networks", headers=H(admin),
                       json={"networks": [{"network_name": [net],
                                           "role": "administrator"}]}, timeout=15)
    check("'administrator' is not a grantable role, even by an admin -> 4xx",
          r.status_code >= 400, f"HTTP {r.status_code}")
    check("...and the target was not silently promoted",
          psql(f"SELECT role FROM sensorthings.\"User\" WHERE id={reg_id}") != "administrator")
    admins = psql("SELECT count(*) FROM sensorthings.\"User\" "
                  "WHERE role = 'administrator'")
    r = requests.patch(f"{BASE}/Users/1/networks", headers=H(admin),
                       json={"networks": [{"network_name": [net],
                                           "role": "viewer"}]}, timeout=15)
    check("last administrator cannot be demoted (lockout guard)",
          r.status_code >= 400 if admins == "1" else True,
          f"HTTP {r.status_code}, {admins} admin(s)")

    # ==================================================================
    section("13. Upstream SensorThings contract still intact")
    # ==================================================================
    for ent in ("Things", "Sensors", "ObservedProperties", "Locations",
                "FeaturesOfInterest", "HistoricalLocations", "Datastreams",
                "Observations"):
        c = count(ent, admin)
        check(f"GET /{ent} works", c is not None, f"@iot.count={c}")
    r = requests.get(f"{BASE}/Datastreams", params={"$top": 2, "$expand": "Thing"},
                     headers=H(admin), timeout=20)
    check("$expand works", r.status_code == 200 and r.json().get("value"))
    r = requests.get(f"{BASE}/Datastreams", params={"$filter": "id gt 0", "$top": 1},
                     headers=H(admin), timeout=20)
    check("$filter works", r.status_code == 200)
    r = requests.get(f"{BASE}/Datastreams(999999)", headers=H(admin), timeout=10)
    check("missing entity -> 404", r.status_code == 404, f"HTTP {r.status_code}")
    r = requests.get(f"{BASE}/Datastreams", params={"$filter": "!!bad!!"},
                     headers=H(admin), timeout=10)
    check("malformed $filter -> 400", r.status_code == 400, f"HTTP {r.status_code}")

    # ==================================================================
    section("14. OIDC surface wired  (full round trip: run_oidc_e2e.py)")
    # ==================================================================
    r = requests.get(f"{BASE}/auth/google/login", allow_redirects=False, timeout=10)
    check("GET /auth/google/login -> 302 to the provider",
          r.status_code == 302, f"HTTP {r.status_code}")
    r = requests.get(f"{BASE}/auth/notaprovider/login", allow_redirects=False,
                     timeout=10)
    check("unknown provider -> 4xx", r.status_code >= 400, f"HTTP {r.status_code}")
    cols = psql("SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema='sensorthings' AND table_name='User' "
                "AND column_name IN ('auth_provider','external_sub_id',"
                "'possible_duplicate_of','requested_networks','status','password')")
    check("all 6 identity/lifecycle columns present in the schema",
          cols == "6", f"{cols}/6")
    gone = psql("SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema='sensorthings' AND table_name='User' "
                "AND column_name IN ('dataset_id','requested_role')")
    check("the old single-scope columns are gone", gone == "0", gone)
    check("grant tables exist",
          psql("SELECT count(*) FROM information_schema.tables WHERE "
               "table_schema='sensorthings' AND table_name IN "
               "('UserGrant','UserGrantNetwork','CustomPolicy')") == "3")

    # ------------------------------------------------------------------
    _report(time.time() - t0)


def _report(elapsed):
    print("\n" + "=" * 66)
    by_sec = {}
    for sec, _name, ok in _results:
        p, f = by_sec.get(sec, (0, 0))
        by_sec[sec] = (p + (1 if ok else 0), f + (0 if ok else 1))
    for sec, (p, f) in by_sec.items():
        flag = "\033[32mOK\033[0m" if f == 0 else f"\033[31m{f} FAILED\033[0m"
        print(f"  {sec:<62} {p}/{p + f} {flag}")
    total = len(_results)
    failed = [f"{s} :: {n}" for s, n, ok in _results if not ok]
    print("=" * 66)
    print(f"  {total - len(failed)}/{total} checks passed in {elapsed:.1f}s")
    if failed:
        print("\n  FAILURES:")
        for f in failed:
            print(f"    - {f}")
        sys.exit(1)
    print("  \033[32mALL GREEN\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
