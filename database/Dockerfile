FROM timescale/timescaledb-ha:pg18-ts2.25
COPY ./istsos_schema.sql /docker-entrypoint-initdb.d/11_init_db_istsos_schema.sql
COPY ./istsos_auth.sql /docker-entrypoint-initdb.d/12_init_auth.sql
COPY ./istsos_schema_versioning.sql /docker-entrypoint-initdb.d/13_init_db_istsos_schema_versioning.sql

# database/migrations/*.sql are applied on container init (they were
# previously only ever run by hand against a live dev database, so a fresh
# clone got a database missing the OIDC/password/audit/RBAC columns and
# policies). Each migration guards itself on custom.authorization and uses
# IF NOT EXISTS throughout, so this is safe and idempotent.
#
# Ordered by the numbering in database/migrations/.
COPY ./migrations/001_identity_linking.sql /docker-entrypoint-initdb.d/14_migration_001_identity_linking.sql
COPY ./migrations/002_add_password_status.sql /docker-entrypoint-initdb.d/15_migration_002_add_password_status.sql
COPY ./migrations/003_audit_log.sql /docker-entrypoint-initdb.d/16_migration_003_audit_log.sql
COPY ./migrations/004_admin_rejection.sql /docker-entrypoint-initdb.d/17_migration_004_admin_rejection.sql
COPY ./migrations/005_user_dataset_policy.sql /docker-entrypoint-initdb.d/18_migration_005_user_dataset_policy.sql
COPY ./migrations/006_session_scoped_rls_policies.sql /docker-entrypoint-initdb.d/19_migration_006_session_scoped_rls_policies.sql
COPY ./migrations/007_requested_role.sql /docker-entrypoint-initdb.d/20_migration_007_requested_role.sql
COPY ./migrations/008_oidc_duplicate_hint.sql /docker-entrypoint-initdb.d/21_migration_008_oidc_duplicate_hint.sql
COPY ./migrations/009_backfill_user_uri.sql /docker-entrypoint-initdb.d/22_migration_009_backfill_user_uri.sql
