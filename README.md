# istSOS4

istSOS4 is a Python implementation of the [OGC SensorThings API](https://www.ogc.org/standards/sensorthings/)
(FastAPI, PostgreSQL and TimescaleDB). This branch adds the missing security
layer: authentication, role-based access control, row-level security and
per-Network access grants.

| | |
|---|---|
| **API base URL** | <http://localhost:8018/istsos4/v1.1> |
| **Swagger UI** | <http://localhost:8018/istsos4/v1.1/docs> |
| **Test login** | `admin` / `admin` (with `.env.testing`) |

## Contents

1. [Quick start](#quick-start)
2. [Configuration notes](#configuration-notes)
3. [Per-Network access (grants)](#per-network-access-grants)
4. [External (OIDC) login](#external-oidc-login)
5. [Automated checks](#automated-checks)
6. [Running istSOS4 (upstream instructions)](#running-istsos4-upstream-instructions)

---

## Quick start

> **Which branch?** The full auth/RBAC/RLS work, including per-Network grants,
> lives on **`feat/network-grants`**. The `docs/swagger-api-documentation`
> branch holds the earlier version, with one role per user.

```sh
git clone https://github.com/KinshukSS2/istSOS4.git
cd istSOS4
git checkout feat/network-grants
cp .env.testing .env
docker compose up -d --build
```

Then:

1. **Wait about a minute** for the database to initialise and the dummy data to
   be generated. To watch progress: `docker compose logs -f dummy_data`.
2. **Open Swagger** at <http://localhost:8018/istsos4/v1.1/docs>.
3. Click **Authorize** and log in as `admin` / `admin`.

Every image is built from this repository (nothing to pull except the base
images), so re-run `docker compose up -d --build` after changing anything under
`api/` or `database/`.

**Start again from a clean database**

```sh
docker compose down -v
docker compose up -d --build
```

Re-running `docker compose up` without `-v` is safe: the dummy-data generator
skips itself when data already exists.

---

## Configuration notes

`.env.testing` is `.env.example` with the settings the auth features need:

| Setting | `.env.testing` | `.env.example` (upstream default) |
|---|---|---|
| `AUTHORIZATION` | `1` | `0` |
| `NETWORK` | `1` | `0` |
| `VERSIONING` | `1` | `0` |
| `DUMMY_DATA` | `1` | `0` |
| `REDIS` | `0` | `0` |

Change nothing for a first run. **Do not set `AUTHORIZATION` or `NETWORK` back to
`0`**, or none of the auth features are active. `.env.example` keeps the upstream
defaults that CI and ordinary deployments use.

**Logout and Redis**

- With `REDIS=0` (the default in `.env.testing`), `POST /Logout` still answers
  "Successfully logged out", but the token keeps working until it expires,
  because the list of revoked tokens lives in Redis.
- To make logout actually revoke a token, set `REDIS=1` in `.env` and restart
  the API (`docker compose up -d api`; the Redis container is already part of
  the stack).
- Tokens carry no unique id, so logging in again within the same second as a
  logout returns the same, still-revoked token. Wait a second.

---

## Per-Network access (grants)

A user does not have one role; they have a **list of grants**. Each grant is
"these Networks, this role" (and a named policy for `custom`):

```json
"networks": [
  {"network_name": ["psos", "acsot"], "role": "editor", "policy": ""},
  {"network_name": [],                "role": "viewer", "policy": ""}
]
```

**Rules**

- `network_name: []` means every Network. Only an administrator can save it.
- Several roles on the same Network add up.
- `policy` is only for `custom` grants: the name of a rule set created with
  `POST /Policies`.

**Where the list is used**

| Call | Meaning |
|---|---|
| `POST /Register`, `GET /auth/{provider}/login?networks=<json>` | A *request* only; the applicant gets nothing yet |
| `PATCH /Users/{id}/policy-approval` | The decision: `{"networks": [...]}` or `{"approve_as_requested": true}` |
| `POST /Users` (admin) | Create an active user with grants |
| `PATCH /Users/{id}/networks` (admin) | Replace a user's grants |
| `POST /Policies`, `DELETE /Policies?policy=` | Create or delete a named rule set for `custom` grants |

**Upgrading an existing database**

The init scripts only run on an empty database. On an existing one:

1. Apply `database/migrations/017_network_grants.sql`. It copies each user's old
   role and `dataset_id` into one grant, drops legacy per-user custom policies
   and lists them in `GrantMigrationReport`.
2. Check that report.
3. Apply `database/migrations/018_drop_dataset_columns.sql`.

---

## External (OIDC) login

Supported providers: Google, Microsoft, GitHub, ORCID and SWITCH edu-ID.

| You want to | Do this |
|---|---|
| Test the whole flow without registering an app | Start the bundled **fake** OpenID Connect provider (below) |
| Use a real provider | Set that provider's `*_CLIENT_ID` and `*_CLIENT_SECRET` in `.env` |

```sh
docker compose -f docker-compose.yml -f docker-compose.e2e.yml up -d --build
```

For a real provider, register this redirect URI with it:

```text
{HOSTNAME}{SUBPATH}{VERSION}/auth/{provider}/callback
# for example: http://localhost:8018/istsos4/v1.1/auth/google/callback
```

An external sign-in only creates a *pending* account. An administrator approves
it with `PATCH /Users/{id}/policy-approval`, the same endpoint as for a local
registration.

---

## Automated checks

With the stack running (add the fake provider above for the OIDC checks):

```sh
python api/tests/e2e/run_gsoc_acceptance.py
python api/tests/e2e/run_rls_leak_audit.py
python api/tests/e2e/run_oidc_e2e.py
python api/tests/e2e/run_auth_parity.py
python api/tests/e2e/run_network_grants_e2e.py
```

| Script | What it checks |
|---|---|
| `run_gsoc_acceptance.py` | The full authentication and authorization sweep |
| `run_rls_leak_audit.py` | A user scoped to one Network cannot read or change another's data |
| `run_oidc_e2e.py` | External login, approval and scoped access (needs the fake provider) |
| `run_auth_parity.py` | A local and an external user with the same grants get identical results |
| `run_network_grants_e2e.py` | Grant behaviour: roles per Network, `[]` for all, validation, approval, commit rule |
| `run_grants_rls_audit.py` | A rolled-back SQL audit of every role and operation (needs `DB_CONTAINER`) |

These scripts read ground truth from the database container (`DB_CONTAINER`,
default `istsos4-database`). Point it at a disposable stack if you run them
against anything else. `run_grants_rls_audit.py` refuses to start without
`DB_CONTAINER`.

See [`api/tests/e2e/README.md`](api/tests/e2e/README.md) for details.

---

## Running istSOS4 (upstream instructions)

### Clone the upstream repository

```sh
git clone https://github.com/istSOS/istSOS4.git
```

### Environment setup

Before starting any environment, copy the example env file and fill in your
values:

```sh
cp .env.example .env
```

At minimum set `SECRET_KEY` (required for authentication) and the Postgres/admin
passwords before running the stack. All other variables default to sensible
development values.

### Start the Docker services

```sh
docker compose up -d --build
```

To switch off the services:

```sh
docker compose down
```

To remove all images and volumes:

```sh
docker compose down -v --rmi local
```

`dev_docker-compose.yml` is a variant of the same stack for development behind
ngrok (it trusts all forwarded headers and also builds the docs site). The
instructions above and the tests were verified with `docker-compose.yml`.

### Restore a database from backup

```sh
docker exec -i istsos4-database sh -c '
  PGPASSWORD="$POSTGRES_PASSWORD" \
  pg_restore \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    -v \
    --clean \
    --if-exists
' < istsos4.backup
```

### Use the SensorThings API

Access the SensorThings API at <http://127.0.0.1:8018/istsos4/v1.1>.

### Reference

For more information about the database and how to populate it with synthetic
data, see the [Database Documentation](https://github.com/istSOS/istsos4/blob/traveltime/database/README.md).
