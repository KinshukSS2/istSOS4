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

"""The v1 Swagger UI landing description.

Kept out of api.py so a ~100-line markdown block doesn't bury the router
wiring. This is also the ONLY place several GSoC deliverables can be
represented in Swagger at all -- the append-only AuditLog and the row-level
security policies are a table and a set of stored Postgres functions, not
endpoints. There is no operation to attach a summary/description to for
any of them.
"""

V1_DESCRIPTION = """
A SensorThings API implementation in Python, extended with a full
authentication, authorization, and audit layer.

*This page documents that extension end to end: how to authenticate, how
access is staged and enforced, and where the non-endpoint parts of it —
row-level security, the audit trail — actually live.*

---

### Quick start

1. Press **Authorize** (top right) and sign in with a local account —
   username/password, e.g. the seeded `administrator` account. Swagger
   posts to `POST /Login` and stores the bearer token for you.
2. Every operation with a padlock icon then sends
   `Authorization: Bearer <token>` automatically when you run **Try it out**.
3. Anonymous read access depends on deployment config. With
   `ANONYMOUS_VIEWER=0` (the default) a request with no token is rejected
   with 401. With `ANONYMOUS_VIEWER=1` a read with no token runs as the
   PostgreSQL `guest` role (shared reference data only), a read with a
   valid token runs as that user, with their per-Network grants, and a
   read with an invalid token is rejected with 401.

---

### The trust model

Access is staged, not binary. No path skips a stage.

| State | How you get there | What you can do |
|:--|:--|:--|
| **guest** | no token at all, and only when `ANONYMOUS_VIEWER=1` | read-only, and only the shared reference data (Things, Sensors, Locations, ObservedProperties, HistoricalLocations, FeaturesOfInterest); Datastreams, Observations and Networks are not visible |
| **pending** | `POST /Register`, or a first-time login via `GET /auth/{provider}/login` | nothing — every authenticated route returns 403 |
| **approved** | an administrator calls `PATCH /Users/{id}/policy-approval` | whatever the granted per-Network roles (and custom policies) allow |
| **rejected** | an administrator calls `PATCH /Users/{id}/reject` | nothing, permanently, unless the applicant re-registers |

Registering and logging in via an external identity provider are both
**requests**, not grants — neither ever issues a usable access token by
itself. An administrator always makes the decision.

---

### Per-Network grants

A user's access is a **list of grants**. Each grant says which Networks it
covers, which role the user has there, and (for `custom` only) which named
policy applies:

```json
"networks": [
  {"network_name": ["psos", "acsot"], "role": "editor", "policy": ""},
  {"network_name": [],                "role": "viewer", "policy": ""}
]
```

* `network_name: []` means **every** Network. Only an administrator can
  save it; an applicant asking for it is only making a request.
* Roles: `viewer` &nbsp;·&nbsp; `editor` &nbsp;·&nbsp; `obs_manager` &nbsp;·&nbsp; `sensor` &nbsp;·&nbsp; `qc` &nbsp;·&nbsp; `custom`.
* The same Network under two roles **adds up**; two grants of the same role
  must not overlap (400).
* `policy` is only for `custom` — the name of a rule set created with
  `POST /Policies`. A policy cannot be deleted while a grant uses it.
* A `sensor` / `qc` user commits under a fixed commit and sends no commit
  message — unless they also hold an `editor`, `obs_manager` or `custom`
  grant, in which case every write carries a normal commit message.

Where grants are set: `POST /Register` / `GET /auth/{provider}/login?networks=`
(a *request*), `PATCH /Users/{id}/policy-approval` (the decision),
`POST /Users` and `PATCH /Users/{id}/networks` (administrator).

`administrator` is deliberately **not** a grantable role — promotion to
admin is infrastructure/DBA-only, and the last remaining administrator can
never be demoted (`PATCH /Users/{id}/networks` returns `409`). `pending` is
an internal state and can never be set directly by a caller.

---

### Row-level security

istSOS users are not PostgreSQL roles. The backend connects as one service
account; per request it runs `SET LOCAL ROLE "user"` and stamps
`app.current_user_id`. The row-level-security policies created by
`017_network_grants.sql` then look up that user's grants and filter rows
accordingly — enforcement happens **inside the database**, not in Python.

A `custom` grant has no blanket access: it only allows what the rules of
its named policy (`POST /Policies`) allow, and only inside the grant's
Networks.

---

### Audit log

There is no endpoint for this, by design. `AuditLog` is append-only at the
database level — `UPDATE`/`DELETE` are revoked from every role, including
`administrator` — and every write happens inside the same transaction as
the action it records, so an action and its audit row commit or roll back
together.

Recorded action types: `RESTRICTED_REQUEST` &nbsp;·&nbsp; `ADMIN_APPROVAL` &nbsp;·&nbsp; `ADMIN_REJECTION`

---

### External identities

Google, Microsoft, GitHub, ORCID, and SWITCH edu-ID are supported through
one provider-parameterized pair of routes rather than five separate
implementations — see **External Authentication** below, including why
those two routes can't be exercised from this page.

A provider only appears as usable if its `*_CLIENT_ID` /
`*_CLIENT_SECRET` environment variables are configured for this
deployment; an unconfigured provider name returns `404`.

---

### Error bodies

Three different shapes exist across this API, for historical reasons.
Each operation below documents the one it actually returns — check the
listed response codes rather than assuming:

| Shape | Origin |
|:--|:--|
| `{"detail": "..."}` | raised as `HTTPException` |
| `{"message": "..."}` | built inline by a handler |
| `{"code": 400, "type": "error", "message": "..."}` | the canonical SensorThings error body |

A fourth shape, `{"detail": [{"loc", "msg", "type"}]}`, is FastAPI's
standard validation error (`422`) and is generated automatically wherever
a request body or parameter is typed.
"""
