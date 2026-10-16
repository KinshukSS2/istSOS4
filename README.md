# istSOS4

## Testing this branch (authentication, RBAC and RLS)

The full auth/RBAC/RLS work, including per-Network grants, lives on the
`feat/network-grants` branch of this fork. The `docs/swagger-api-documentation`
branch holds the earlier version, with one role per user.

```sh
git clone https://github.com/KinshukSS2/istSOS4.git
cd istSOS4
git checkout feat/network-grants
cp .env.testing .env
docker compose up -d --build
```

1. `.env.testing` is `.env.example` with `AUTHORIZATION=1`, `NETWORK=1`,
   `VERSIONING=1` and `DUMMY_DATA=1`. Change nothing for a first run. Do not
   set `AUTHORIZATION` or `NETWORK` back to `0`, or none of the auth features
   are active. `.env.example` keeps the upstream defaults (all `0`) that CI
   and ordinary deployments use.
2. Wait about a minute for the database to initialise and the dummy data to be
   generated (`docker compose logs -f dummy_data`).
3. Open Swagger at <http://localhost:8018/istsos4/v1.1/docs>, click
   **Authorize** and log in as `admin` / `admin`.

The compose file is `docker-compose.yml`. Every image is built from this
repository (nothing to pull except the base images), so re-run
`docker compose up -d --build` after changing anything under `api/` or
`database/`.

**Logout and Redis.** `.env.testing` ships with `REDIS=0`. With it, `POST /Logout`
still answers "Successfully logged out" but the token keeps working until it
expires, because the list of revoked tokens lives in Redis. To make logout
actually revoke a token, set `REDIS=1` in `.env` and restart the API
(`docker compose up -d api`; the Redis container is already part of the
stack). Tokens carry no unique id, so logging in again within the same second
as a logout returns the same, still-revoked token: wait a second.

Re-running `docker compose up` is safe: the dummy-data generator skips itself
when data already exists. To start again from a clean database:

```sh
docker compose down -v
docker compose up -d --build
```

### Per-Network access (grants)

A user does not have one role; they have a **list of grants**. Each grant is
"these Networks, this role" (and a named policy for `custom`):

```json
"networks": [
  {"network_name": ["psos", "acsot"], "role": "editor", "policy": ""},
  {"network_name": [],                "role": "viewer", "policy": ""}
]
```

`network_name: []` means every Network. Several roles on the same Network add
up; only an administrator can save an all-Networks grant. The list is used by

| Call | Meaning |
|---|---|
| `POST /Register`, `GET /auth/{provider}/login?networks=<json>` | a *request* |
| `PATCH /Users/{id}/policy-approval` | the decision: `{"networks": [...]}` or `{"approve_as_requested": true}` |
| `POST /Users` (admin) | create an active user with grants |
| `PATCH /Users/{id}/networks` (admin) | replace a user's grants |
| `POST /Policies` / `DELETE /Policies?policy=` | create / delete a named rule set for `custom` grants |

**Upgrading an existing database.** The init scripts only run on an empty
database. On an existing one, apply
`database/migrations/017_network_grants.sql` (copies each user's old role and
`dataset_id` into one grant, drops legacy per-user custom policies and lists
them in `GrantMigrationReport`), check the report, then apply
`018_drop_dataset_columns.sql`.

### External (OIDC) login

Real Google, GitHub, Microsoft and ORCID sign-in needs your own client id and
secret in `.env` (see the `*_CLIENT_ID` / `*_CLIENT_SECRET` entries). To test the
whole external-login flow without registering an app, use the bundled fake
OpenID Connect provider instead:

```sh
docker compose -f docker-compose.yml -f docker-compose.e2e.yml up -d --build
```

### Automated checks

With the stack running (add the fake provider above for the OIDC checks):

```sh
python api/tests/e2e/run_gsoc_acceptance.py
python api/tests/e2e/run_rls_leak_audit.py
python api/tests/e2e/run_oidc_e2e.py
python api/tests/e2e/run_auth_parity.py
python api/tests/e2e/run_network_grants_e2e.py
```

These scripts read ground truth from the database container
(`DB_CONTAINER`, default `istsos4-database`) -- point it at a disposable stack
if you run them against anything else. `run_grants_rls_audit.py` runs a
rolled-back SQL audit of every role x operation and refuses to start without
`DB_CONTAINER`.

See `api/tests/e2e/README.md` for details.

## Clone the upstream istSOS4 repository

```sh
git clone https://github.com/istSOS/istSOS4.git
```

## Environment setup

Before starting any environment, copy the example env file and fill in your values:

```sh
cp .env.example .env
```

At minimum set `SECRET_KEY` (required for authentication) and the Postgres/admin
passwords before running the stack.  All other variables default to sensible
development values.

## Start the Docker services

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


## Restore database from backup

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

## Use Sensor Things APIs

Access the SensorThings API at: http://127.0.0.1:8018/istsos4/v1.1

## Reference

For more information about the database and how populate it with synthetic data, refer to the [Database Documentation](https://github.com/istSOS/istsos4/blob/traveltime/database/README.md)
