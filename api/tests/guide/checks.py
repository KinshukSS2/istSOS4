#!/usr/bin/env python3
# Copyright 2025 SUPSI
#
# Licensed under the Apache License, Version 2.0 (the "License").
#
# Executable checks behind the Swagger testing guide.
#
# Each @check function is one test card of the guide (S0, A1 ... E6). It makes
# real HTTP calls against a running stack, asserts the result, and the harness
# records every request and response, so the guide can show the real traffic
# next to the code that produced it.
#
#   DB_CONTAINER=<db container> API_CONTAINER=<api container> \
#   ISTSOS_BASE=http://localhost:8018/istsos4/v1.1 FAKE_BASE=http://localhost:9000 \
#       python api/tests/guide/checks.py --out guide_run.json
#
# Needs the stack from `.env.testing` (AUTHORIZATION=1 NETWORK=1 VERSIONING=1
# DUMMY_DATA=1) plus the fake identity provider from docker-compose.e2e.yml.
# Point it at a disposable stack: it creates users, policies and Datastreams.

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import uuid
from types import SimpleNamespace

import requests

BASE = os.getenv("ISTSOS_BASE", "http://localhost:8018/istsos4/v1.1")
FAKE = os.getenv("FAKE_BASE", "http://localhost:9000")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin")
DB = os.getenv("DB_CONTAINER")
API = os.getenv("API_CONTAINER")

PW = "Str0ng!Pass1"
NEW_PW = "EvenStr0nger!2"
BROWSER = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
SECRET_FIELDS = ("password", "current_password", "new_password")
TOKEN_STUB = "eyJhbGciOiJIUzI1…"
MAX_BODY_LINES = 60

CHECKS = []


def check(tid):
    def deco(fn):
        CHECKS.append((tid, fn))
        return fn

    return deco


# ---------------------------------------------------------------- recording
class Test:
    """One test card: records exchanges, assertions and the headline result."""

    def __init__(self, tid):
        self.tid = tid
        self.exchanges = []
        self.assertions = []
        self.expected = ""
        self.actual_text = ""
        self.failed = False

    # -- http
    def call(self, method, path, token=None, json=None, data=None, params=None,
             headers=None, follow=False, record=True):
        url = path if path.startswith("http") else BASE + path
        h = dict(headers or {})
        if token:
            h["Authorization"] = f"Bearer {token}"
        t0 = time.time()
        r = requests.request(method, url, json=json, data=data, params=params,
                             headers=h, allow_redirects=follow, timeout=60)
        ms = max(1, round((time.time() - t0) * 1000))
        if record:
            shown = path if path.startswith("http") else path
            if params:
                shown += ("&" if "?" in shown else "?") + urllib.parse.urlencode(params)
            self.exchanges.append({
                "method": method,
                "url": shown,
                "status": r.status_code,
                "ms": ms,
                "request": _mask(json if json is not None else data),
                "response": _body(r),
            })
        return r

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, **kw):
        return self.call("POST", path, **kw)

    def patch(self, path, **kw):
        return self.call("PATCH", path, **kw)

    def delete(self, path, **kw):
        return self.call("DELETE", path, **kw)

    # -- assertions
    def expect(self, cond, label, detail=""):
        self.assertions.append({"ok": bool(cond), "label": label + (f" ({detail})" if detail and not cond else "")})
        if not cond:
            self.failed = True
        return bool(cond)

    def expect_status(self, r, code, label=None):
        label = label or f"{r.request.method} {_short(r.request.url)} returns {code}"
        return self.expect(r.status_code == code, label, f"got {r.status_code}: {r.text[:120]}")

    def actual(self, text):
        self.actual_text = text

    def result(self):
        return {
            "id": self.tid,
            "passed": not self.failed,
            "expected": self.expected,
            "actual": self.actual_text,
            "assertions": self.assertions,
            "exchanges": self.exchanges,
        }


def _short(url):
    return url.replace(BASE, "")


def _mask(obj):
    if isinstance(obj, dict):
        return {k: ("•••" if k in SECRET_FIELDS else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(v) for v in obj]
    return obj


def _body(r):
    if not r.content:
        return None
    try:
        data = r.json()
    except ValueError:
        return r.text[:600]
    if isinstance(data, dict) and "access_token" in data:
        data = {**data, "access_token": TOKEN_STUB}
    text = json.dumps(data, indent=2, ensure_ascii=False)
    lines = text.split("\n")
    if len(lines) > MAX_BODY_LINES:
        text = "\n".join(lines[:MAX_BODY_LINES]) + "\n  …"
    return text


# ---------------------------------------------------------------- helpers
def psql(sql):
    if not DB:
        sys.exit("set DB_CONTAINER (a disposable stack's database container)")
    out = subprocess.run(
        ["docker", "exec", DB, "psql", "-U", "postgres", "-d", "istsos", "-tAc", sql],
        capture_output=True, text=True,
    )
    return out.stdout.strip()


def login(t, username, password=PW):
    r = t.post("/Login", data={"username": username, "password": password})
    return r.json().get("access_token") if r.status_code == 200 else None


def user_row(t, token, username):
    rows = t.get("/Users", token=token).json().get("value", [])
    return next((u for u in rows if u["username"] == username), None)


def grant(names, role, policy=""):
    return {"network_name": list(names), "role": role, "policy": policy}


def make_user(t, ctx, name, networks):
    """POST /Users (administrator) -> (user_id, token)."""
    username = f"{name}_{ctx.tag}"
    r = t.post("/Users", token=ctx.admin, json={
        "username": username, "password": PW, "networks": networks})
    t.expect_status(r, 201)
    uid = int(psql(f"SELECT id FROM sensorthings.\"User\" WHERE username='{username}'"))
    tok = login(t, username)
    return username, uid, tok


def datastream_ids(t, token):
    r = t.get("/Datastreams", token=token, params={"$top": 200})
    return sorted(d["@iot.id"] for d in r.json().get("value", [])) if r.status_code == 200 else None


def oidc_signin(t, sub, email, query=None):
    """The real browser round trip against the fake provider; every hop recorded."""
    s = requests.Session()
    s.headers.update(BROWSER)
    t0 = time.time()
    path = f"/auth/google/login" + (f"?{query}" if query else "")
    r1 = s.get(BASE + path, allow_redirects=False, timeout=30)
    t.exchanges.append({"method": "GET", "url": path, "status": r1.status_code,
                        "ms": round((time.time() - t0) * 1000), "request": None, "response": None})
    loc = r1.headers["location"].replace("http://oidc-fake:9000", FAKE)
    t0 = time.time()
    r2 = s.get(loc, timeout=30)
    t.exchanges.append({"method": "GET", "url": loc, "status": r2.status_code,
                        "ms": round((time.time() - t0) * 1000), "request": None,
                        "response": r2.text[:200] + " …"})
    hidden = dict(re.findall(r'name="(\w+)" value="([^"]*)"', r2.text))
    form = {**hidden, "sub": sub, "email": email, "name": sub}
    t0 = time.time()
    r3 = s.post(f"{FAKE}/authorize", data=form, allow_redirects=False, timeout=30)
    t.exchanges.append({"method": "POST", "url": f"{FAKE}/authorize", "status": r3.status_code,
                        "ms": round((time.time() - t0) * 1000), "request": None, "response": None})
    cb = r3.headers["location"]
    parsed = urllib.parse.urlparse(cb)
    cb_path = cb.replace(f"{parsed.scheme}://{parsed.netloc}", BASE.rsplit("/istsos4", 1)[0])
    t0 = time.time()
    r4 = s.get(cb_path, allow_redirects=False, timeout=30)
    shown = cb.split("/istsos4/v1.1", 1)[-1]
    t.exchanges.append({"method": "GET", "url": shown, "status": r4.status_code,
                        "ms": round((time.time() - t0) * 1000), "request": None,
                        "response": _body(r4)})
    return r1, r4


def obs_body(ds_id, ptime):
    return {"phenomenonTime": ptime, "result": 1.0, "Datastream": {"@iot.id": int(ds_id)}}


def datastream_body(ctx, network_id, name):
    return {
        "name": name,
        "description": "editor create test",
        "observationType": "http://www.opengis.net/def/observationType/OGC-OM/2.0/OM_Measurement",
        "unitOfMeasurement": {"name": "Lumen", "symbol": "lm", "definition": "http://qudt.org/lm"},
        "Thing": {"@iot.id": ctx.first["Things"]},
        "Sensor": {"@iot.id": ctx.first["Sensors"]},
        "ObservedProperty": {"@iot.id": ctx.first["ObservedProperties"]},
        "Network": {"@iot.id": network_id},
    }


# ================================================================ S: ground truth
@check("s0")
def ground_truth(t, ctx):
    rows = psql(
        'SELECT n.id, n.name, count(DISTINCT d.id), count(o.id) FROM sensorthings."Network" n '
        'LEFT JOIN sensorthings."Datastream" d ON d.network_id = n.id '
        'LEFT JOIN sensorthings."Observation" o ON o.datastream_id = d.id '
        "GROUP BY n.id, n.name ORDER BY n.id").split("\n")
    nets = [r.split("|") for r in rows if r]
    nets = [(int(i), n, int(d), int(o)) for i, n, d, o in nets if int(d) > 0]
    t.expect(len(nets) >= 2, "at least two Networks hold Datastreams", len(nets))
    ctx.a_id, ctx.a, ctx.a_ds, ctx.a_obs = nets[0]
    ctx.b_id, ctx.b, ctx.b_ds, ctx.b_obs = nets[1]
    ctx.all_ds = int(psql('SELECT count(*) FROM sensorthings."Datastream"'))
    ctx.all_obs = int(psql('SELECT count(*) FROM sensorthings."Observation"'))
    ids = lambda nid: [int(x) for x in psql(  # noqa: E731
        f'SELECT id FROM sensorthings."Datastream" WHERE network_id = {nid} ORDER BY id').split()]
    ctx.a_ids, ctx.b_ids = ids(ctx.a_id), ids(ctx.b_id)
    flags = {}
    if API:
        for k in ("AUTHORIZATION", "NETWORK", "ANONYMOUS_VIEWER", "VERSIONING", "REDIS"):
            flags[k] = subprocess.run(["docker", "exec", API, "printenv", k],
                                      capture_output=True, text=True).stdout.strip()
    ctx.flags = flags
    t.expect(flags.get("AUTHORIZATION") == "1" and flags.get("NETWORK") == "1",
             "AUTHORIZATION=1 and NETWORK=1 on the running API", flags)
    t.expected = "Two Networks that each own Datastreams; AUTHORIZATION=1 and NETWORK=1."
    t.actual(f"{ctx.a}: {ctx.a_ds} datastreams / {ctx.a_obs} obs · {ctx.b}: {ctx.b_ds} / {ctx.b_obs} · "
             + " ".join(f"{k}={v}" for k, v in flags.items()))


# ================================================================ A: account lifecycle
@check("a1")
def register_applicant(t, ctx):
    ctx.alice_name = f"demo_alice_{ctx.tag}"
    r = t.post("/Register", json={
        "username": ctx.alice_name, "password": PW,
        "networks": [grant([ctx.a], "viewer")],
        "explanation": "Demo registration for mentor walkthrough",
        "contact_info": {"company": "SUPSI"}})
    t.expect_status(r, 201)
    t.expect(r.json().get("status") == "pending", "new account starts as pending")
    ctx.alice_id = r.json().get("id")
    t.expected = "201 — status: pending, with the new id"
    t.actual(f"{r.status_code} · status={r.json().get('status')} · id={ctx.alice_id}")


@check("a2")
def authorize_admin(t, ctx):
    r = t.post("/Login", data={"username": ADMIN_USER, "password": ADMIN_PASS})
    t.expect_status(r, 200)
    ctx.admin = r.json().get("access_token")
    t.expect(bool(ctx.admin), "a bearer token is issued")
    t.expected = "200 — access_token, token_type: bearer"
    t.actual("200 · bearer token issued for admin")


@check("a3")
def review_pending_queue(t, ctx):
    r = t.get("/Users", token=ctx.admin)
    t.expect_status(r, 200)
    rows = r.json()["value"]
    me = next((u for u in rows if u["username"] == ctx.alice_name), {})
    t.expect(me.get("role") is None, "pending account reports role: null", me.get("role"))
    t.expect(me.get("status") == "pending", "status is pending", me.get("status"))
    t.expect(me.get("requested_networks") == [{"role": "viewer", "network_name": [ctx.a]}],
             "the requested grants are stored (a request, not a grant)", me.get("requested_networks"))
    t.expect(me.get("networks") == [], "no grant exists yet", me.get("networks"))
    t.expect(all("password" not in u for u in rows), "the bcrypt hash is never returned")
    ids = [u["id"] for u in rows]
    t.expect(ids == sorted(ids), "rows are ordered by id")
    t.expected = "200 — role: null, status: pending, requested_networks stored, networks: []"
    t.actual(f"200 · role=null · status=pending · requested_networks={me.get('requested_networks')}")


@check("a4")
def approve_applicant(t, ctx):
    path = f"/Users/{ctx.alice_id}/policy-approval"
    r = t.patch(path, token=ctx.admin, json={})
    t.expect(r.status_code == 422, "an empty body is refused (422): say what to grant", r.status_code)
    r = t.patch(path, token=ctx.admin, json={"networks": [grant(["NoSuchNetwork"], "viewer")]})
    t.expect(r.status_code == 400, "an unknown Network is refused (400)", r.status_code)
    r = t.patch(path, token=ctx.admin, json={"networks": [grant([ctx.a], "viewer")]})
    t.expect_status(r, 200)
    body = r.json() if r.status_code == 200 else {}
    t.expect(body.get("granted") == [grant([ctx.a], "viewer")], "granted grants returned", body.get("granted"))
    t.expect(set(body) >= {"requested", "granted", "effective", "warnings"},
             "the response lists requested, granted and effective access")
    row = user_row(t, ctx.admin, ctx.alice_name) or {}
    t.expect(row.get("role") == "member" and row.get("status") == "active",
             "row is an active member", (row.get("role"), row.get("status")))
    t.expect(row.get("networks") == [grant([ctx.a], "viewer")], "GET /Users shows the grant", row.get("networks"))
    t.expected = "200 — requested / granted / effective listed; the user becomes an active member"
    t.actual(f"200 · granted viewer on {ctx.a} · status=active")


@check("a5")
def login_new_user(t, ctx):
    ctx.alice = login(t, ctx.alice_name)
    t.expect(bool(ctx.alice), "POST /Login returns 200 with a token")
    t.expected = "200 — a token for the approved user"
    t.actual("200 · token issued for the approved user")


@check("a6")
def rbac_boundary(t, ctx):
    r = t.get("/Users", token=ctx.alice)
    t.expect_status(r, 401)
    t.expect(r.json().get("message") == "Insufficient privileges.", "explicit privilege error")
    t.expected = '401 — {"message": "Insufficient privileges."}'
    t.actual(f'{r.status_code} · {json.dumps(r.json())}')


@check("a7")
def refresh_token(t, ctx):
    r = t.post("/Refresh", token=ctx.alice)
    t.expect_status(r, 200)
    new = r.json().get("access_token")
    r2 = t.get("/Datastreams", token=new, params={"$top": 1})
    t.expect_status(r2, 200, "the refreshed token is accepted")
    ctx.alice = new or ctx.alice
    t.expected = "200 — a new access_token"
    t.actual("200 · fresh access_token, accepted on the next call")


@check("a8")
def change_access(t, ctx):
    r = t.patch(f"/Users/{ctx.alice_id}/networks", token=ctx.admin,
                json={"networks": [grant([ctx.a], "editor")]})
    t.expect_status(r, 204)
    row = user_row(t, ctx.admin, ctx.alice_name) or {}
    t.expect(row.get("networks") == [grant([ctx.a], "editor")], "GET /Users shows the new grant", row.get("networks"))
    t.expected = "204 — GET /Users shows the editor grant"
    t.actual("204 · the grant is now editor")


@check("a9")
def change_password(t, ctx):
    r = t.patch(f"/Users/{ctx.alice_id}/password", token=ctx.alice,
                json={"current_password": PW, "new_password": NEW_PW})
    t.expect_status(r, 204)
    old = t.post("/Login", data={"username": ctx.alice_name, "password": PW})
    t.expect(old.status_code == 401, "old password is refused (401)", old.status_code)
    new = t.post("/Login", data={"username": ctx.alice_name, "password": NEW_PW})
    t.expect(new.status_code == 200, "new password logs in (200)", new.status_code)
    ctx.alice = new.json().get("access_token", ctx.alice)
    t.expected = "204 — old password refused, new password accepted"
    t.actual("204 · old password → 401 · new password → 200")


@check("a10")
def logout(t, ctx):
    r = t.post("/Logout", token=ctx.alice)
    t.expect_status(r, 200)
    t.expect("logged out" in json.dumps(r.json()), "logout acknowledged")
    r2 = t.post("/Refresh", token=ctx.alice)
    redis_on = ctx.flags.get("REDIS", "0") not in ("0", "", "false", "False")
    if redis_on:
        t.expect(r2.status_code == 401, "REDIS=1: the token is revoked", r2.status_code)
    else:
        t.expect(r2.status_code == 200, "REDIS=0: token keeps working until expiry (documented)", r2.status_code)
        ctx.alice = r2.json().get("access_token", ctx.alice)
    t.expected = '200 — {"message": "Successfully logged out"}'
    t.actual("200 · REDIS=0: acknowledged, token not revoked until it expires" if not redis_on
             else "200 · REDIS=1: token revoked")


@check("a11")
def reject_and_reapply(t, ctx):
    name = f"demo_bob_{ctx.tag}"
    body = {"username": name, "password": PW, "explanation": "demo", "contact_info": {},
            "networks": [grant([ctx.a], "viewer")]}
    r = t.post("/Register", json=body)
    t.expect_status(r, 201)
    bob = r.json().get("id")
    r = t.patch(f"/Users/{bob}/reject", token=ctx.admin, json={"reason": "demo"})
    t.expect_status(r, 200)
    row = user_row(t, ctx.admin, name) or {}
    t.expect(row.get("role") is None and row.get("status") == "rejected", "role null, status rejected")
    r = t.post("/Login", data={"username": name, "password": PW})
    t.expect(r.status_code == 401, "a rejected applicant cannot log in", r.status_code)
    r = t.post("/Register", json=body)
    t.expect(r.status_code == 201, "re-applying under the same username is allowed", r.status_code)
    row = user_row(t, ctx.admin, name) or {}
    t.expect(row.get("status") == "pending", "row resets to pending", row.get("status"))
    t.expected = "200 — status: rejected; re-registering returns 201 and resets to pending"
    t.actual("200 reject · login 401 · re-apply 201 · status back to pending")


@check("a12")
def deactivate(t, ctx):
    r = t.delete(f"/Users/{ctx.alice_id}", token=ctx.admin)
    t.expect_status(r, 200)
    row = user_row(t, ctx.admin, ctx.alice_name) or {}
    t.expect(row.get("status") == "deleted", "row kept, status=deleted", row.get("status"))
    r = t.post("/Login", data={"username": ctx.alice_name, "password": NEW_PW})
    t.expect(r.status_code == 401, "login now fails", r.status_code)
    t.expected = "200 — login with the valid password now fails"
    t.actual("200 · status=deleted · login with the valid password → 401")


# ================================================================ B: external identity
@check("b1")
def start_oidc_login(t, ctx):
    ctx.ext_networks = [{"network_name": [ctx.b], "role": "viewer"}]
    q = urllib.parse.urlencode({"networks": json.dumps(ctx.ext_networks)})
    r = t.get(f"/auth/google/login?{q}")
    t.expect_status(r, 302, "GET /auth/google/login?networks=… returns 302")
    loc = r.headers.get("location", "")
    t.expect("state=" in loc and "nonce=" in loc, "redirects to the provider with state and nonce")
    r2 = t.get("/auth/google/login?networks=not-json")
    t.expect(r2.status_code == 400, "a malformed networks value is refused (400)", r2.status_code)
    t.expected = "302 — redirect to the provider's authorize page"
    t.actual("302 → provider /authorize (state + nonce set)")


@check("b2")
def provider_consent(t, ctx):
    ctx.ext_sub = f"guide-{ctx.tag}"
    ctx.ext_email = f"guide.{ctx.tag}@example.org"
    q = urllib.parse.urlencode({"networks": json.dumps(ctx.ext_networks)})
    _, cb = oidc_signin(t, ctx.ext_sub, ctx.ext_email, q)
    t.expect(cb.status_code == 202, "the callback returns 202", cb.status_code)
    t.expect("Registration submitted via google" in cb.text, "pending message")
    t.expected = "202 — Registration submitted via google; account pending"
    t.actual("202 · Registration submitted via google · account pending")


@check("b3")
def activate_external(t, ctx):
    rows = t.get("/Users", token=ctx.admin).json()["value"]
    me = next((u for u in rows if u.get("external_sub_id") == ctx.ext_sub), {})
    ctx.ext_id = me.get("id")
    t.expect(me.get("role") is None and me.get("status") == "pending", "pending OIDC row, no role yet")
    t.expect(psql(f"SELECT password IS NULL FROM sensorthings.\"User\" WHERE id={ctx.ext_id}") == "t",
             "no local password is stored for an external identity")
    r = t.patch(f"/Users/{ctx.ext_id}/policy-approval", token=ctx.admin, json={"approve_as_requested": True})
    t.expect_status(r, 200)
    t.expect(r.json().get("granted") == [grant([ctx.b], "viewer")], "the requested grant was applied",
             r.json().get("granted"))
    _, cb = oidc_signin(t, ctx.ext_sub, ctx.ext_email)
    t.expect(cb.status_code == 200 and "access_token" in cb.text, "second sign-in returns an access_token", cb.status_code)
    ctx.ext = cb.json().get("access_token") if cb.status_code == 200 else None
    r = t.get("/Datastreams", token=ctx.ext, params={"$top": 200})
    seen = sorted(d["@iot.id"] for d in r.json().get("value", []))
    t.expect(seen == ctx.b_ids, "token sees exactly its Network's Datastreams", seen)
    t.expected = "200 — approved as requested; the next callback returns a token"
    t.actual(f"200 approve · callback 200 + token · sees {len(seen)} {ctx.b} datastreams")


@check("b4")
def provider_availability(t, ctx):
    r = t.get("/auth/eduid/login")
    t.expect_status(r, 404)
    t.expect("eduid" in json.dumps(r.json()), "names the unconfigured provider")
    t.expected = "404 — names the unconfigured provider"
    t.actual("404 for an unconfigured provider (eduid)")


# ================================================================ C: visibility and scoping
@check("c1")
def static_policy_set(t, ctx):
    names = set(psql("SELECT policyname FROM pg_policies WHERE schemaname='sensorthings'").split("\n"))
    expected = {
        "rbac_ds_select", "rbac_ds_editor", "rbac_ds_limited",
        "rbac_obs_select", "rbac_obs_all", "rbac_obs_insert", "rbac_obs_qc",
        "rbac_thing_select", "rbac_thing_editor", "rbac_sensor_select",
        "rbac_location_select", "rbac_location_limited", "rbac_foi_insert",
        "rbac_network_select", "rbac_network_editor",
    }
    missing = expected - names
    t.expect(not missing, "every grant-based policy is installed", sorted(missing))
    rls = int(psql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                   "WHERE n.nspname='sensorthings' AND c.relrowsecurity"))
    t.expect(rls >= 9, "RLS enabled on the scoped tables", rls)
    bare = psql(
        "SELECT count(*) FROM pg_policies WHERE schemaname IN ('sensorthings','sensorthings_history') "
        "AND (coalesce(qual,'')||' '||coalesce(with_check,'')) ~ "
        "'(?<!SELECT )sensorthings\\.app_(has_role|grant_all|grant_nets|grant_ds_ids|policy_any|policy_all|policy_nets|policy_ds_ids)\\('")
    t.expect(bare == "0", "every helper call is evaluated once per query, never per row", bare)
    pg_roles = psql("SELECT count(*) FROM pg_roles WHERE rolname IN "
                    "('administrator','user','sensor','qc','guest')")
    t.expected = "All rbac_* policies present; RLS enabled on the scoped tables"
    t.actual(f"{len([n for n in names if n.startswith('rbac_')])} rbac_* policies · RLS on {rls} tables"
             f" · {pg_roles} fixed group roles")


@check("c2")
def anonymous_denied(t, ctx):
    for path in ("/Datastreams", "/Things"):
        r = t.get(path, params={"$top": 1})
        t.expect_status(r, 401)
        t.expect(r.json().get("detail") == "Not authenticated", "no partial public access")
    t.expected = '401 — {"detail": "Not authenticated"}'
    t.actual('401 · {"detail": "Not authenticated"} on /Datastreams and /Things')


@check("c3")
def viewer_sees_own_network(t, ctx):
    _, ctx.viewer_id, ctx.viewer = make_user(t, ctx, "guide_viewer_a", [grant([ctx.a], "viewer")])
    seen = datastream_ids(t, ctx.viewer)
    t.expect(seen == ctx.a_ids, "exactly the Datastreams of the viewer's Network", seen)
    admin_seen = datastream_ids(t, ctx.admin)
    t.expect(len(admin_seen or []) >= ctx.a_ds + ctx.b_ds, "admin sees every Network")
    t.expected = "200 — exactly the Datastreams of the viewer's Network; admin sees all"
    t.actual(f"viewer({ctx.a}) sees {len(seen or [])} · admin sees {len(admin_seen or [])}")


@check("c4")
def viewer_cannot_write(t, ctx):
    ds = ctx.a_ids[0]
    r = t.patch(f"/Datastreams({ds})", token=ctx.viewer, json={"description": "should fail"},
                headers={"commit-message": "demo"})
    t.expect_status(r, 403)
    t.expect("Insufficient privileges" in json.dumps(r.json()), "explicit refusal")
    t.expected = "403 — Insufficient privileges to update this Datastream."
    t.actual("403 · Insufficient privileges to update this Datastream.")


@check("c5")
def reference_tables_unscoped(t, ctx):
    r = t.get("/Things", token=ctx.viewer, params={"$count": "true", "$top": 1})
    t.expect_status(r, 200)
    total = int(psql('SELECT count(*) FROM sensorthings."Thing"'))
    t.expect(r.json().get("@iot.count") == total, "viewer reads every Thing", r.json().get("@iot.count"))
    t.expected = "200 — @iot.count equals every Thing in the database"
    t.actual(f"200 · @iot.count={r.json().get('@iot.count')} (all Things, not Network-filtered)")


@check("c6")
def editor_creates_in_own_network(t, ctx):
    ctx.editor_name, ctx.editor_id, ctx.editor = make_user(t, ctx, "guide_editor_a", [grant([ctx.a], "editor")])
    ctx.first = {e: t.get(f"/{e}", token=ctx.admin, params={"$top": 1}).json()["value"][0]["@iot.id"]
                 for e in ("Things", "Sensors", "ObservedProperties")}
    r = t.post("/Datastreams", token=ctx.editor, headers={"commit-message": "editor create test"},
               json=datastream_body(ctx, ctx.a_id, f"editor_test_{ctx.tag}"))
    t.expect_status(r, 201)
    m = re.search(r"\((\d+)\)", r.headers.get("location", ""))
    ctx.created_ds = int(m.group(1)) if m else None
    t.expect(ctx.created_ds is not None, "a Location header names the new Datastream")
    t.expected = "201 — Location header with the new id"
    t.actual(f"201 · Datastream {ctx.created_ds} created in {ctx.a}")


@check("c7")
def editor_blocked_outside(t, ctx):
    r = t.post("/Datastreams", token=ctx.editor, headers={"commit-message": "editor create test"},
               json=datastream_body(ctx, ctx.b_id, f"editor_bad_{ctx.tag}"))
    t.expect_status(r, 403)
    t.expect("Insufficient privileges" in json.dumps(r.json()), "RLS WITH CHECK refusal")
    r = t.patch(f"/Datastreams({ctx.b_ids[0]})", token=ctx.editor, json={"description": "x"},
                headers={"commit-message": "demo"})
    t.expect_status(r, 404)
    t.expect("not found" in json.dumps(r.json()).lower(), "a row outside the scope looks like it does not exist")
    t.delete(f"/Datastreams({ctx.created_ds})", token=ctx.admin, headers={"commit-message": "guide cleanup"})
    t.expected = "POST → 403 Insufficient privileges. · PATCH → 404 Datastream not found."
    t.actual("POST into other Network → 403 · PATCH other Network's row → 404")


@check("c8")
def observation_counts_scoped(t, ctx):
    r = t.get("/Observations", token=ctx.viewer, params={"$count": "true", "$top": 0})
    t.expect_status(r, 200)
    got = r.json().get("@iot.count")
    t.expect(got == ctx.a_obs, "count equals the Network's observations", got)
    t.expected = "200 — @iot.count equals the viewer's Network's observations"
    t.actual(f"200 · @iot.count={got} (whole table: {ctx.all_obs}) · {t.exchanges[-1]['ms']} ms")


@check("c9")
def admin_only_metadata(t, ctx):
    for path in ("/Policies", "/Commits"):
        r = t.get(path, token=ctx.viewer, params={"$top": 1} if path == "/Commits" else None)
        t.expect(r.status_code == 401, f"viewer GET {path} → 401", r.status_code)
        r = t.get(path, token=ctx.admin, params={"$top": 1} if path == "/Commits" else None)
        t.expect(r.status_code == 200, f"admin GET {path} → 200", r.status_code)
    t.expected = "viewer 401 · admin 200 (both endpoints)"
    t.actual("Policies 401/200 · Commits 401/200 (viewer/admin)")


@check("c10")
def external_matches_local(t, ctx):
    _, _, local = make_user(t, ctx, "guide_viewer_b", [grant([ctx.b], "viewer")])
    own, other = ctx.b_ids[0], ctx.a_ids[0]
    out = {}
    for side, tok in (("local", local), ("external", ctx.ext)):
        out[side] = {
            "ds": datastream_ids(t, tok),
            "obs": t.get("/Observations", token=tok, params={"$count": "true", "$top": 0}).json().get("@iot.count"),
            "own": t.patch(f"/Datastreams({own})", token=tok, json={"description": "x"},
                           headers={"commit-message": "demo"}).status_code,
            "other": t.patch(f"/Datastreams({other})", token=tok, json={"description": "x"},
                             headers={"commit-message": "demo"}).status_code,
        }
    for k, label in (("ds", "datastreams"), ("obs", "observations"), ("own", "patch own"), ("other", "patch other")):
        t.expect(out["local"][k] == out["external"][k], f"{label}: local and external identical",
                 (out["local"][k], out["external"][k]))
    t.expected = "Identical counts, 403 on own rows, 404 on other rows"
    t.actual("identical on datastreams, observation count, 403 own, 404 other")


# ================================================================ D: the custom role
@check("d1")
def create_custom_user(t, ctx):
    ctx.cust_name, ctx.cust_id, ctx.cust = make_user(
        t, ctx, "demo_custom", [grant([ctx.a], "custom")])
    r = t.get("/Datastreams", token=ctx.cust)
    t.expect(r.status_code == 200 and r.json().get("value") == [], "custom starts with zero rows")
    t.expected = "201 — the new user's GET /Datastreams returns value: []"
    t.actual("201 · GET /Datastreams → value: []")


@check("d2")
def grant_mixed_rule(t, ctx):
    ctx.rule_a, ctx.rule_b = ctx.a_ids[0], ctx.a_ids[1]
    ctx.pol = f"demo_custom_mixed_{ctx.tag}"
    r = t.post("/Policies", token=ctx.admin, json={"name": ctx.pol, "permissions": {
        "type": "custom", "policy": {"datastream": {
            "select": f"id IN ({ctx.rule_a}, {ctx.rule_b})", "update": f"id = {ctx.rule_b}"}}}})
    t.expect_status(r, 201)
    r = t.patch(f"/Users/{ctx.cust_id}/networks", token=ctx.admin,
                json={"networks": [grant([ctx.a], "custom", ctx.pol)]})
    t.expect_status(r, 204, "PATCH /Users/{id}/networks (give the user the policy) returns 204")
    r = t.get("/Policies", token=ctx.admin, params={"table": "Datastream"})
    names = {p["policyname"] for p in r.json().get("value", [])}
    for op in ("select", "update"):
        t.expect(f"{ctx.pol}_datastream_{op}" in names, f"policy <name>_datastream_{op} exists")
    t.expected = "201 — <name>_datastream_select and _update created; then attached through a custom grant"
    t.actual(f"201 · {ctx.pol}_datastream_select + _update created · grant saved (204)")


@check("d3")
def prove_the_split(t, ctx):
    seen = datastream_ids(t, ctx.cust)
    t.expect(seen == sorted([ctx.rule_a, ctx.rule_b]), "sees exactly the two granted ids", seen)
    r = t.patch(f"/Datastreams({ctx.rule_a})", token=ctx.cust, json={"description": "should fail"},
                headers={"commit-message": "demo"})
    t.expect(r.status_code == 403, "read-only id → 403", r.status_code)
    r = t.patch(f"/Datastreams({ctx.rule_b})", token=ctx.cust, json={"description": "should succeed"},
                headers={"commit-message": "demo"})
    t.expect(r.status_code == 200, "granted id → 200", r.status_code)
    other = ctx.a_ids[2]
    r = t.get(f"/Datastreams({other})", token=ctx.cust)
    t.expect(r.status_code == 404, "a row in the Network but outside the rule → 404", r.status_code)
    t.expected = "sees [A, B] · PATCH A 403 · PATCH B 200 · other id 404"
    t.actual(f"sees {seen} · PATCH read-only 403 · granted 200 · other 404")


@check("d4")
def remove_the_grant(t, ctx):
    r = t.delete("/Policies", token=ctx.admin, params={"policy": ctx.pol})
    t.expect(r.status_code == 409, "a policy a grant still uses cannot be deleted (409)", r.status_code)
    r = t.patch(f"/Users/{ctx.cust_id}/networks", token=ctx.admin,
                json={"networks": [grant([ctx.a], "custom")]})
    t.expect_status(r, 204, "removing the policy from the grant returns 204")
    r = t.get("/Datastreams", token=ctx.cust)
    t.expect(r.json().get("value") == [], "back to zero rows")
    r = t.delete("/Policies", token=ctx.admin, params={"policy": ctx.pol})
    t.expect(r.status_code == 200, "DELETE /Policies once nothing uses it returns 200", r.status_code)
    left = psql(f"SELECT count(*) FROM pg_policies WHERE policyname LIKE '{ctx.pol}%'")
    t.expect(left == "0", "every PostgreSQL policy it created is gone", left)
    t.expected = "409 while in use · 204 grant changed · 200 deleted — back to value: []"
    t.actual("409, 204, 200 · custom user back to value: [] · policies dropped")


@check("d5")
def external_custom(t, ctx):
    sub, email = f"guide-custom-{ctx.tag}", f"guide.custom.{ctx.tag}@example.org"
    q = urllib.parse.urlencode({"networks": json.dumps([{"network_name": [ctx.a], "role": "custom"}])})
    _, cb = oidc_signin(t, sub, email, q)
    t.expect(cb.status_code == 202, "first sign-in is 202 (pending)", cb.status_code)
    rows = t.get("/Users", token=ctx.admin).json()["value"]
    me = next((u for u in rows if u.get("external_sub_id") == sub), {})
    uid = me.get("id")
    t.expect(me.get("requested_networks") == [{"role": "custom", "network_name": [ctx.a]}],
             "requested grant stored", me.get("requested_networks"))
    pol = f"demo_oidc_custom_{ctx.tag}"
    r = t.post("/Policies", token=ctx.admin, json={"name": pol, "permissions": {
        "type": "custom", "policy": {"datastream": {"select": f"id = {ctx.a_ids[0]}"}}}})
    t.expect_status(r, 201)
    r = t.patch(f"/Users/{uid}/policy-approval", token=ctx.admin,
                json={"networks": [grant([ctx.a], "custom", pol)]})
    t.expect_status(r, 200)
    _, cb = oidc_signin(t, sub, email)
    tok = cb.json().get("access_token") if cb.status_code == 200 else None
    t.expect(bool(tok), "second sign-in returns an access_token")
    seen = datastream_ids(t, tok)
    t.expect(seen == [ctx.a_ids[0]], "sees exactly the granted id", seen)
    t.patch(f"/Users/{uid}/networks", token=ctx.admin, json={"networks": [grant([ctx.a], "viewer")]})
    r = t.delete("/Policies", token=ctx.admin, params={"policy": pol})
    t.expect(r.status_code == 200, "policy deleted once unused", r.status_code)
    t.expected = "202 → approve 200 with the policy → sees the granted id"
    t.actual(f"202 → approve 200 → sees {seen}")


# ================================================================ E: per-Network grants
@check("e1")
def viewer_here_editor_there(t, ctx):
    name, uid, tok = make_user(t, ctx, "guide_mixed", [grant([ctx.a], "viewer"), grant([ctx.b], "editor")])
    seen = datastream_ids(t, tok)
    t.expect(seen == sorted(ctx.a_ids + ctx.b_ids), "sees both Networks", len(seen or []))
    ra = t.patch(f"/Datastreams({ctx.a_ids[0]})", token=tok, json={"description": f"va_{ctx.tag}"},
                 headers={"commit-message": "demo"})
    rb = t.patch(f"/Datastreams({ctx.b_ids[0]})", token=tok, json={"description": f"eb_{ctx.tag}"},
                 headers={"commit-message": "demo"})
    t.expect(ra.status_code == 403, f"write on {ctx.a} (viewer) refused", ra.status_code)
    t.expect(rb.status_code == 200, f"write on {ctx.b} (editor) accepted", rb.status_code)
    t.expected = f"sees both Networks · write on {ctx.a} → 403 · write on {ctx.b} → 200"
    t.actual(f"sees {len(seen or [])} datastreams · {ctx.a} PATCH {ra.status_code} · {ctx.b} PATCH {rb.status_code}")


@check("e2")
def empty_list_means_all(t, ctx):
    name, uid, tok = make_user(t, ctx, "guide_all", [grant([], "viewer")])
    seen = datastream_ids(t, tok)
    t.expect(len(seen or []) == ctx.all_ds, "network_name [] covers every Network", len(seen or []))
    # an applicant asking for [] only makes a request
    reg = f"guide_req_all_{ctx.tag}"
    r = t.post("/Register", json={"username": reg, "password": PW, "explanation": "demo",
                                  "contact_info": {}, "networks": [grant([], "viewer")]})
    t.expect_status(r, 201)
    row = user_row(t, ctx.admin, reg) or {}
    t.expect(row.get("networks") == [] and row.get("status") == "pending",
             "an applicant's [] is only a request: pending, no grant", row.get("networks"))
    t.expected = "[] grants every Network when an administrator saves it; an applicant's [] is only a request"
    t.actual(f"admin-created user sees {len(seen or [])}/{ctx.all_ds} datastreams · applicant stays pending with no grant")


@check("e3")
def commit_rule(t, ctx):
    name, uid, tok = make_user(t, ctx, "guide_sensor", [grant([ctx.a], "viewer"), grant([ctx.b], "sensor")])
    ds = ctx.b_ids[0]
    r = t.post("/Observations", token=tok, json=obs_body(ds, "2098-03-01T00:00:00Z"))
    t.expect(r.status_code == 201, "a sensor writes with no commit message (fixed commit)", r.status_code)
    msg = psql("SELECT c.message FROM sensorthings.\"Observation\" o JOIN sensorthings.\"Commit\" c "
               "ON c.id = o.commit_id WHERE o.\"phenomenonTimeStart\" = '2098-03-01T00:00:00Z' LIMIT 1")
    t.expect(msg == "Sensor data", "the Observation carries the sensor's fixed commit", msg)
    r = t.post("/Observations", token=tok, headers={"commit-message": "my note"},
               json=obs_body(ds, "2098-03-01T00:00:01Z"))
    t.expect(r.status_code >= 400, "a sensor may not send a commit message", r.status_code)
    r = t.patch(f"/Users/{uid}/networks", token=ctx.admin,
                json={"networks": [grant([ctx.a], "viewer"), grant([ctx.b], "sensor"), grant([ctx.b], "editor")]})
    t.expect_status(r, 204, "adding an editor grant returns 204")
    r1 = t.post("/Observations", token=tok, json=obs_body(ds, "2098-03-01T00:00:02Z"))
    t.expect(r1.status_code == 400, "sensor + editor: a commit message is now required (400)", r1.status_code)
    r2 = t.post("/Observations", token=tok, headers={"commit-message": "editor commit"},
                json=obs_body(ds, "2098-03-01T00:00:03Z"))
    t.expect(r2.status_code == 201, "…and with one it is accepted (201)", r2.status_code)
    t.expected = "sensor only: 201 without a message · adding editor: 400 without, 201 with"
    t.actual("sensor 201 (fixed commit 'Sensor data') · +editor → 400 without a message, 201 with one")


@check("e4")
def validation(t, ctx):
    def bad(label, networks, code=400, extra=None):
        body = {"username": f"guide_bad_{ctx.tag}", "password": PW, "networks": networks, **(extra or {})}
        r = t.post("/Users", token=ctx.admin, json=body)
        t.expect(r.status_code == code, f"{label} → {code}", f"{r.status_code}: {r.text[:100]}")

    bad("unknown Network", [grant(["NoSuchNetwork"], "viewer")])
    bad("the same role twice on one Network", [grant([ctx.a], "viewer"), grant([ctx.a, ctx.b], "viewer")])
    bad("a policy on a non-custom grant", [grant([ctx.a], "viewer", "anything")])
    bad("an unknown policy", [grant([ctx.a], "custom", "no_such_policy")])
    bad("an unknown grant field", [{**grant([ctx.a], "viewer"), "dataset_id": ctx.a}])
    r = t.post("/Users", token=ctx.admin, json={"username": f"guide_old_{ctx.tag}", "password": PW, "role": "viewer"})
    t.expect(r.status_code == 400, "the removed single `role` field → 400", r.status_code)
    dup = f"dupnet_{ctx.tag}"
    psql(f"INSERT INTO sensorthings.\"Network\" (name, commit_id) SELECT '{dup}', min(id) FROM "
         f"sensorthings.\"Commit\" UNION ALL SELECT '{dup}', min(id) FROM sensorthings.\"Commit\"")
    bad("a Network name two Networks share (ambiguous)", [grant([dup], "viewer")])
    psql(f"DELETE FROM sensorthings.\"Network\" WHERE name = '{dup}'")
    t.expected = "400 for each invalid list, with a message naming the problem"
    t.actual("400 · unknown / overlap / policy-on-non-custom / unknown policy / unknown field / ambiguous")


@check("e5")
def approval_decision(t, ctx):
    def apply(name, networks):
        t.post("/Register", json={"username": name, "password": PW, "explanation": "demo",
                                  "contact_info": {}, "networks": networks})
        return int(psql(f"SELECT id FROM sensorthings.\"User\" WHERE username='{name}'"))

    one = apply(f"guide_ap1_{ctx.tag}", [grant([ctx.a], "viewer"), grant([ctx.b], "sensor")])
    r = t.patch(f"/Users/{one}/policy-approval", token=ctx.admin, json={"approve_as_requested": True})
    t.expect(r.status_code == 200 and len(r.json().get("granted", [])) == 2,
             "approve_as_requested grants exactly the request", r.status_code)
    two = apply(f"guide_ap2_{ctx.tag}", [grant([ctx.a], "viewer")])
    r = t.patch(f"/Users/{two}/policy-approval", token=ctx.admin,
                json={"networks": [grant([ctx.b], "editor")]})
    body = r.json() if r.status_code == 200 else {}
    t.expect(r.status_code == 200 and body.get("granted") == [grant([ctx.b], "editor")],
             "the administrator's list replaces the request entirely", body.get("granted"))
    kept = psql(f"SELECT requested_networks->0->>'role' FROM sensorthings.\"User\" WHERE id = {two}")
    t.expect(kept == "viewer", "…while the original request stays on record", kept)
    r = t.patch(f"/Users/{two}/policy-approval", token=ctx.admin,
                json={"approve_as_requested": True, "networks": [grant([ctx.a], "viewer")]})
    t.expect(r.status_code == 422, "both `networks` and `approve_as_requested` → 422", r.status_code)
    t.expected = "approve_as_requested grants the request · an explicit list replaces it · both → 422"
    t.actual("200 as requested (2 grants) · 200 with the administrator's own list · 422 for both")


@check("e6")
def deleted_network(t, ctx):
    tmp = f"tmpnet_{ctx.tag}"
    psql(f"INSERT INTO sensorthings.\"Network\" (name, commit_id) SELECT '{tmp}', min(id) FROM sensorthings.\"Commit\"")
    name, uid, tok = make_user(t, ctx, "guide_gone", [grant([tmp], "viewer")])
    before = t.get("/Datastreams", token=tok, params={"$count": "true", "$top": 1}).json().get("@iot.count")
    psql(f"DELETE FROM sensorthings.\"Network\" WHERE name = '{tmp}'")
    after = t.get("/Datastreams", token=tok, params={"$count": "true", "$top": 1}).json().get("@iot.count")
    t.expect(before == 0 and after == 0, "the user sees nothing before and after the Network is deleted", (before, after))
    row = user_row(t, ctx.admin, name) or {}
    t.expect(all(g.get("network_name") != [] for g in row.get("networks", [])),
             "the grant did not turn into an all-Networks grant", row.get("networks"))
    t.expected = "Deleting the only Network of a grant removes access; it never widens to everything"
    t.actual(f"count {before} → {after} · grants after deletion: {row.get('networks')}")


# ================================================================ runner
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="guide_run.json")
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    ctx = SimpleNamespace(tag=uuid.uuid4().hex[:5])
    results, failed = [], 0
    only = {x.strip() for x in args.only.split(",") if x.strip()}
    for tid, fn in CHECKS:
        if only and tid not in only:
            continue
        t = Test(tid)
        try:
            fn(t, ctx)
        except Exception as exc:  # noqa: BLE001
            t.expect(False, f"unexpected error: {type(exc).__name__}: {exc}")
        res = t.result()
        res["function"] = fn.__name__
        results.append(res)
        failed += 0 if res["passed"] else 1
        print(f"  [{'PASS' if res['passed'] else 'FAIL'}] {tid.upper():<4} {fn.__name__}")
        for a in res["assertions"]:
            if not a["ok"]:
                print(f"         ✗ {a['label']}")
    with open(args.out, "w") as f:
        json.dump({"base": BASE, "tag": ctx.tag, "flags": getattr(ctx, "flags", {}),
                   "networks": {"a": getattr(ctx, "a", None), "b": getattr(ctx, "b", None)},
                   "results": results}, f, indent=1)
    print(f"{len(results) - failed}/{len(results)} passed -> {args.out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
