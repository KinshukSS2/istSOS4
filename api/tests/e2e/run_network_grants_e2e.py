#!/usr/bin/env python3
# Copyright 2025 SUPSI
#
# Licensed under the Apache License, Version 2.0 (the "License").
#
# Per-Network grants: one user, a LIST of grants, each "these Networks, this
# role (and policy for `custom`)".
#
#   networks: [{"network_name": ["psos", "acsot"], "role": "custom",
#               "policy": "policyname1"},
#              {"network_name": [], "role": "viewer"}]     # [] = all Networks
#
# This script drives the real API against a live stack and checks the
# behaviour that only exists because of grants (the older scripts cover the
# single-role cases):
#
#   * several grants on one user, different roles on different Networks
#   * same Network + two roles -> permissions add up
#   * `[]` means every Network
#   * a removed grant removes access; a deleted Network never widens access
#   * validation: unknown / ambiguous Network, overlap, policy on non-custom,
#     unknown fields, unknown policy
#   * approval: approve_as_requested and the administrator's list overriding
#     the request
#   * the commit rule: sensor/qc fixed commit only when no editor / obs_manager
#     / custom grant is held
#
#   ISTSOS_BASE=... DB_CONTAINER=<db container> API_CONTAINER=<api container> \
#       python api/tests/e2e/run_network_grants_e2e.py
#
# Needs AUTHORIZATION=1 NETWORK=1 and the dummy data (two Networks).
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


def login(u, p=PW):
    r = requests.post(f"{BASE}/Login", data={"username": u, "password": p}, timeout=15)
    return r.json().get("access_token") if r.status_code == 200 else None


def H(t, commit=None):
    h = {"Authorization": f"Bearer {t}"}
    if commit:
        h["commit-message"] = commit
    return h


def count(entity, t):
    r = requests.get(f"{BASE}/{entity}", params={"$count": "true", "$top": 1},
                     headers=H(t), timeout=30)
    return r.json().get("@iot.count") if r.status_code == 200 else f"HTTP{r.status_code}"


def create_user(admin, name, networks):
    """POST /Users (administrator) -> (user_id, token)."""
    r = requests.post(f"{BASE}/Users", headers=H(admin), timeout=20,
                      json={"username": name, "password": PW, "networks": networks})
    uid = psql(f"SELECT id FROM sensorthings.\"User\" WHERE username='{name}'")
    return r, uid, login(name)


def set_grants(admin, uid, networks):
    return requests.patch(f"{BASE}/Users/{uid}/networks", headers=H(admin),
                          json={"networks": networks}, timeout=20)


def grants_of(uid):
    """Saved grants as 'role:net1,net2' strings, sorted (ground truth)."""
    rows = psql(
        "SELECT g.role || ':' || CASE WHEN g.all_networks THEN '*' ELSE "
        "coalesce((SELECT string_agg(n.name, ',' ORDER BY n.name) FROM "
        'sensorthings."UserGrantNetwork" gn JOIN sensorthings."Network" n '
        "ON n.id = gn.network_id WHERE gn.grant_id = g.id), '') END "
        f'FROM sensorthings."UserGrant" g WHERE g.user_id = {uid} ORDER BY 1')
    return rows.split("\n") if rows else []


def patch(tok, path, body, commit="e2e"):
    return requests.patch(f"{BASE}{path}", headers=H(tok, commit), json=body, timeout=30)


def post_obs(tok, ds, ptime, commit="e2e"):
    return requests.post(f"{BASE}/Observations", headers=H(tok, commit), timeout=30,
                         json={"phenomenonTime": ptime, "result": 1.0,
                               "Datastream": {"@iot.id": int(ds)}})


def main():
    t0 = time.time()
    print(f"istSOS: {BASE}    run tag: {TAG}")

    admin = login(ADMIN_USER, ADMIN_PASS)
    if not admin:
        print("cannot log in as admin")
        sys.exit(2)

    nets = psql('SELECT name FROM sensorthings."Network" ORDER BY id').split("\n")
    if len(nets) < 2:
        print("need two Networks (dummy data)")
        sys.exit(2)
    A, B = nets[0], nets[-1]

    def ds_of(net):
        return psql('SELECT min(d.id) FROM sensorthings."Datastream" d JOIN '
                    f'sensorthings."Network" n ON n.id = d.network_id WHERE n.name = \'{net}\'')

    def obs_of(net):
        return psql('SELECT min(o.id) FROM sensorthings."Observation" o JOIN '
                    'sensorthings."Datastream" d ON d.id = o.datastream_id JOIN '
                    f'sensorthings."Network" n ON n.id = d.network_id WHERE n.name = \'{net}\'')

    def ds_count(net=None):
        if net is None:
            return int(psql('SELECT count(*) FROM sensorthings."Datastream"'))
        return int(psql('SELECT count(*) FROM sensorthings."Datastream" d JOIN '
                        f'sensorthings."Network" n ON n.id = d.network_id WHERE n.name = \'{net}\''))

    dsA, dsB, obsA, obsB = ds_of(A), ds_of(B), obs_of(A), obs_of(B)
    nA, nB, nAll = ds_count(A), ds_count(B), ds_count()
    print(f"A={A} ({nA} ds, sample ds {dsA})   B={B} ({nB} ds, sample ds {dsB})   all={nAll}")

    # ==================================================================
    section("1. The mentor's shape: a custom grant on two Networks + a viewer grant on all")
    pol = f"pol_{TAG}"
    r = requests.post(f"{BASE}/Policies", headers=H(admin), timeout=20,
                      json={"name": pol, "permissions": {"type": "custom", "policy": {
                          "datastream": {"select": "id % 2 = 0"}}}})
    check("POST /Policies (named rule set, no users) -> 201", r.status_code == 201,
          f"HTTP {r.status_code}: {r.text[:70]}")
    r, uid1, t1 = create_user(admin, f"m_{TAG}", [
        {"network_name": [B, A], "role": "custom", "policy": pol},
        {"network_name": [], "role": "viewer", "policy": ""}])
    check("POST /Users with two grants -> 201", r.status_code == 201,
          f"HTTP {r.status_code}: {r.text[:70]}")
    check("both grants are saved",
          grants_of(uid1) == sorted([f"custom:{','.join(sorted([A, B]))}", "viewer:*"]),
          str(grants_of(uid1)))
    check("viewer-on-all means every Datastream is visible",
          count("Datastreams", t1) == nAll, f"{count('Datastreams', t1)} / {nAll}")
    r = patch(t1, f"/Datastreams({dsA})", {"description": f"x_{TAG}"})
    check("...and nothing is writable (viewer + a select-only custom rule)",
          r.status_code >= 400, f"HTTP {r.status_code}")
    u = requests.get(f"{BASE}/Users", headers=H(admin), timeout=20).json()["value"]
    mine = [x for x in u if x["username"] == f"m_{TAG}"]
    check("GET /Users returns the same list back",
          mine and sorted((g["role"], g["policy"]) for g in mine[0]["networks"])
          == sorted([("custom", pol), ("viewer", "")]), str(mine[0]["networks"] if mine else None))

    # ==================================================================
    section("2. Viewer on A + editor on B (one user, different roles per Network)")
    r, uid2, t2 = create_user(admin, f"ve_{TAG}", [
        {"network_name": [A], "role": "viewer"},
        {"network_name": [B], "role": "editor"}])
    check("created", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:70]}")
    check("sees both Networks", count("Datastreams", t2) == nA + nB,
          f"{count('Datastreams', t2)} / {nA + nB}")
    ra = patch(t2, f"/Datastreams({dsA})", {"description": f"va_{TAG}"})
    rb = patch(t2, f"/Datastreams({dsB})", {"description": f"eb_{TAG}"})
    check("write on A (viewer) refused, write on B (editor) accepted",
          ra.status_code >= 400 and 200 <= rb.status_code < 300,
          f"A HTTP {ra.status_code}, B HTTP {rb.status_code}")

    # ==================================================================
    section("3. Viewer on A + sensor on B (fixed commit, writes only where it is a sensor)")
    r, uid3, t3 = create_user(admin, f"vs_{TAG}", [
        {"network_name": [A], "role": "viewer"},
        {"network_name": [B], "role": "sensor"}])
    check("created", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:70]}")
    rb = post_obs(t3, dsB, "2098-01-01T00:00:00Z", commit=None)
    ra = post_obs(t3, dsA, "2098-01-01T00:00:01Z", commit=None)
    check("POST Observation on B (sensor) -> 201 with no commit message",
          rb.status_code == 201, f"HTTP {rb.status_code}: {rb.text[:70]}")
    check("POST Observation on A (viewer only) refused", ra.status_code >= 400,
          f"HTTP {ra.status_code}")
    cm = psql('SELECT c.message FROM sensorthings."Observation" o JOIN '
              'sensorthings."Commit" c ON c.id = o.commit_id WHERE '
              "o.\"phenomenonTimeStart\" = '2098-01-01T00:00:00Z' LIMIT 1")
    check("the Observation carries the sensor's fixed commit", cm == "Sensor data", repr(cm))
    r = post_obs(t3, dsB, "2098-01-01T00:00:02Z", commit="my message")
    check("a sensor may NOT send a commit message -> 4xx", r.status_code >= 400,
          f"HTTP {r.status_code}")

    # ==================================================================
    section("4. Sensor + editor on the same user commits like an editor")
    r, uid4, t4 = create_user(admin, f"se_{TAG}", [
        {"network_name": [B], "role": "sensor"},
        {"network_name": [B], "role": "editor"}])
    check("created", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:70]}")
    r1 = post_obs(t4, dsB, "2098-02-01T00:00:00Z", commit=None)
    r2 = post_obs(t4, dsB, "2098-02-01T00:00:01Z", commit="editor commit")
    check("without a message -> 400 (a normal commit is required)", r1.status_code == 400,
          f"HTTP {r1.status_code}")
    check("with a message -> 201", r2.status_code == 201, f"HTTP {r2.status_code}")
    check("same Network, two roles -> permissions add up (editor may PATCH)",
          200 <= patch(t4, f"/Datastreams({dsB})", {"description": f"u_{TAG}"}).status_code < 300)

    # ==================================================================
    section("5. QC on A + viewer on B")
    r, uid5, t5 = create_user(admin, f"qv_{TAG}", [
        {"network_name": [A], "role": "qc"},
        {"network_name": [B], "role": "viewer"}])
    check("created", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:70]}")
    ra = patch(t5, f"/Observations({obsA})", {"resultQuality": {"status": "checked"}}, commit=None)
    rb = patch(t5, f"/Observations({obsB})", {"resultQuality": {"status": "checked"}}, commit=None)
    check("QC updates an Observation on A with no commit message",
          200 <= ra.status_code < 300, f"HTTP {ra.status_code}: {ra.text[:70]}")
    check("QC cannot touch an Observation on B (viewer there)", rb.status_code >= 400,
          f"HTTP {rb.status_code}")
    check("QC can read both Networks", count("Datastreams", t5) == nA + nB)

    # ==================================================================
    section("6. Changing and removing grants")
    r = set_grants(admin, uid2, [{"network_name": [B], "role": "editor"}])
    check("PATCH /Users/{id}/networks -> 204", r.status_code == 204, f"HTTP {r.status_code}")
    check("access to A is gone, B stays", count("Datastreams", login(f"ve_{TAG}")) == nB)
    al = psql("SELECT count(*) FROM sensorthings.\"AuditLog\" WHERE action_type='ROLE_CHANGED' "
              f"AND (payload->>'target_user_id')::bigint = {uid2}")
    check("the change was audited (ROLE_CHANGED)", al == "1", al)
    r = set_grants(admin, uid2, [{"network_name": [B], "role": "editor"}])
    al2 = psql("SELECT count(*) FROM sensorthings.\"AuditLog\" WHERE action_type='ROLE_CHANGED' "
               f"AND (payload->>'target_user_id')::bigint = {uid2}")
    check("saving the same list again is a no-op (no extra audit row)",
          r.status_code == 204 and al2 == "1", al2)

    # ==================================================================
    section("7. A deleted Network never widens a grant")
    tmp = f"tmpnet_{TAG}"
    psql('INSERT INTO sensorthings."Network" (name, commit_id) '
         f"SELECT '{tmp}', min(id) FROM sensorthings.\"Commit\"")
    r, uid7, t7 = create_user(admin, f"dn_{TAG}", [{"network_name": [tmp], "role": "viewer"}])
    check("grant on a fresh Network accepted", r.status_code == 201, f"HTTP {r.status_code}")
    check("it sees nothing yet (the Network has no Datastreams)", count("Datastreams", t7) == 0)
    psql(f"DELETE FROM sensorthings.\"Network\" WHERE name='{tmp}'")
    t7 = login(f"dn_{TAG}")
    check("after the Network is deleted the user still sees NOTHING (not everything)",
          count("Datastreams", t7) == 0, str(count("Datastreams", t7)))
    check("and holds no all-Networks grant", "viewer:*" not in grants_of(uid7), str(grants_of(uid7)))

    # ==================================================================
    section("8. Validation")
    def bad(label, body, code=400):
        r = requests.post(f"{BASE}/Users", headers=H(admin), timeout=20,
                          json={"username": f"v_{label}_{TAG}", "password": PW, **body})
        return check(f"{label} -> {code}", r.status_code == code,
                     f"HTTP {r.status_code}: {r.text[:80]}")

    bad("unknown Network", {"networks": [{"network_name": ["nope"], "role": "viewer"}]})
    bad("same role twice on one Network", {"networks": [
        {"network_name": [A], "role": "viewer"}, {"network_name": [A, B], "role": "viewer"}]})
    bad("viewer on all + viewer on A overlap", {"networks": [
        {"network_name": [], "role": "viewer"}, {"network_name": [A], "role": "viewer"}]})
    bad("policy on a non-custom grant", {"networks": [
        {"network_name": [A], "role": "viewer", "policy": pol}]})
    bad("unknown policy", {"networks": [
        {"network_name": [A], "role": "custom", "policy": "no_such_policy"}]})
    bad("administrator is not a grantable role", {"networks": [
        {"network_name": [A], "role": "administrator"}]})
    bad("empty grant list", {"networks": []})
    bad("missing networks", {})
    bad("unknown grant field", {"networks": [
        {"network_name": [A], "role": "viewer", "dataset_id": A}]})

    dup = f"dupnet_{TAG}"
    psql('INSERT INTO sensorthings."Network" (name, commit_id) '
         f"SELECT '{dup}', min(id) FROM sensorthings.\"Commit\" "
         "UNION ALL "
         f"SELECT '{dup}', min(id) FROM sensorthings.\"Commit\"")
    bad("ambiguous Network name (two Networks share it)", {"networks": [
        {"network_name": [dup], "role": "viewer"}]})
    psql(f"DELETE FROM sensorthings.\"Network\" WHERE name='{dup}'")

    # ==================================================================
    section("9. Approval: as requested, or the administrator's own list")
    def apply(name, networks):
        body = {"username": name, "password": PW, "explanation": "grants e2e",
                "contact_info": {"email": f"{name}@example.org"}, "networks": networks}
        requests.post(f"{BASE}/Register", json=body, timeout=20)
        return psql(f"SELECT id FROM sensorthings.\"User\" WHERE username='{name}'")

    ap1 = apply(f"ap1_{TAG}", [{"network_name": [A], "role": "viewer"},
                               {"network_name": [B], "role": "sensor"}])
    r = requests.patch(f"{BASE}/Users/{ap1}/policy-approval", headers=H(admin),
                       json={"approve_as_requested": True}, timeout=20)
    check("approve_as_requested -> 200 and grants match the request",
          r.status_code == 200 and grants_of(ap1) == sorted([f"viewer:{A}", f"sensor:{B}"]),
          f"HTTP {r.status_code} {grants_of(ap1)}")
    body = r.json() if r.status_code == 200 else {}
    check("the response lists requested / granted / effective",
          all(k in body for k in ("requested", "granted", "effective", "warnings")))

    ap2 = apply(f"ap2_{TAG}", [{"network_name": [A], "role": "viewer"}])
    r = requests.patch(f"{BASE}/Users/{ap2}/policy-approval", headers=H(admin),
                       json={"networks": [{"network_name": [B], "role": "editor"}]}, timeout=20)
    check("the administrator's list replaces the request entirely",
          r.status_code == 200 and grants_of(ap2) == [f"editor:{B}"],
          f"HTTP {r.status_code} {grants_of(ap2)}")
    ap2_req = psql(f"SELECT requested_networks->0->>'role' FROM sensorthings.\"User\" WHERE id={ap2}")
    check("...while the original request is kept on the record", ap2_req == "viewer", ap2_req)

    ap3 = apply(f"ap3_{TAG}", [{"network_name": [A], "role": "viewer"}])
    r = requests.patch(f"{BASE}/Users/{ap3}/policy-approval", headers=H(admin),
                       json={"approve_as_requested": True,
                             "networks": [{"network_name": [A], "role": "viewer"}]}, timeout=20)
    check("both `networks` and `approve_as_requested` -> 422", r.status_code == 422,
          f"HTTP {r.status_code}")
    r = requests.patch(f"{BASE}/Users/{ap3}/policy-approval", headers=H(admin),
                       json={"networks": [{"network_name": [A], "role": "custom"}]}, timeout=20)
    check("a custom grant with no policy is accepted but warned about",
          r.status_code == 200 and r.json().get("warnings"),
          f"HTTP {r.status_code} {r.json().get('warnings') if r.status_code == 200 else r.text[:60]}")

    ap4 = apply(f"ap4_{TAG}", [{"network_name": [], "role": "viewer"}])
    r = requests.patch(f"{BASE}/Users/{ap4}/policy-approval", headers=H(admin),
                       json={"approve_as_requested": True}, timeout=20)
    check("an applicant's `[]` (all Networks) is only a request; the admin may grant it",
          r.status_code == 200 and grants_of(ap4) == ["viewer:*"],
          f"HTTP {r.status_code} {grants_of(ap4)}")

    # ==================================================================
    section("10. Non-administrators cannot change grants")
    r = set_grants(t2, uid2, [{"network_name": [], "role": "editor"}])
    check("a member PATCHing grants (own or anyone's) -> 401/403",
          r.status_code in (401, 403), f"HTTP {r.status_code}")
    check("grants unchanged", grants_of(uid2) == [f"editor:{B}"], str(grants_of(uid2)))

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
        print(f"  {sec[:62]:<62} {p}/{p + f} {flag}")
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
