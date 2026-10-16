-- Copyright 2025 SUPSI
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- =============================================================================
-- Migration: 017_network_grants
-- Description: Replaces "one role + one Network per user" (User.role +
--              User.dataset_id) with a list of grants. Each grant says which
--              Networks (all, or a named set), with which role, and -- for the
--              'custom' role only -- which named policy.
--
--              A user's access in a Network is the UNION of every grant that
--              covers it (PostgreSQL RLS policies are permissive and OR'd).
--
-- What this migration does
-- ------------------------
--   1. Adds CustomPolicy, UserGrant, UserGrantNetwork (+ GrantMigrationReport),
--      User.requested_networks, and renames AuditLog.dataset_id ->
--      network_name (DDL only; AuditLog stays append-only).
--   2. Adds the SECURITY DEFINER helpers the policies call.
--   3. Copies every existing user's role + dataset_id into one grant.
--      A user whose dataset_id names a Network that no longer exists gets NO
--      grant (fail closed) and is listed in GrantMigrationReport.
--      Pending users' requested_role + dataset_id become requested_networks.
--   4. Drops legacy per-user custom policies (predicate names
--      current_app_user_id()) and lists them in GrantMigrationReport.
--   5. Rebuilds every RLS policy of the "user" group (live + history tables)
--      on top of the grant helpers, and installs the column-limit triggers
--      that replace the sensor/qc column-level GRANTs.
--
-- Rules this file follows (proven by the Phase-0 spike)
-- -----------------------------------------------------
--   * Every helper call inside a policy is wrapped as (SELECT helper(...)) so
--     it is evaluated ONCE per query, not once per row (17 s -> 24 ms).
--   * Column-limit triggers receive the entity name as a trigger argument:
--     on a TimescaleDB hypertable TG_TABLE_NAME is the chunk name.
--   * Policies embed the numeric policy id; the "user" role cannot read the
--     grant tables.
--
-- Additive: User.role and User.dataset_id are left untouched here. 018 drops
-- them once this migration has been verified.
--
-- Idempotent: IF NOT EXISTS / CREATE OR REPLACE / DROP ... IF EXISTS, and the
-- data copy skips users that already have a grant.
-- =============================================================================

DO $BODY$
DECLARE
    net_on  boolean := coalesce(current_setting('custom.network', true)::boolean, false);
    ver_on  boolean := coalesce(current_setting('custom.versioning', true)::boolean, false);
    -- 018 drops these columns; the data copy only makes sense before that
    has_old boolean := EXISTS (SELECT 1 FROM information_schema.columns
                                WHERE table_schema = 'sensorthings' AND table_name = 'User'
                                  AND column_name = 'dataset_id');

    r_read  text := '{viewer,editor,obs_manager,sensor,qc}';
    r_ed    text := '{editor}';
    r_edom  text := '{editor,obs_manager}';
    r_sens  text := '{sensor}';
    r_qc    text := '{qc}';
    r_lim   text := '{obs_manager,sensor}';
    r_foi   text := '{editor,obs_manager,sensor}';

    ref_tables text[] := ARRAY[
        'Location', 'Thing', 'HistoricalLocation', 'ObservedProperty',
        'Sensor', 'FeaturesOfInterest'
    ];
    rec     record;
    tname   text;
    ds_sel  text;     -- predicate builders (strings)
    obs_sel text;
BEGIN
    IF NOT current_setting('custom.authorization', true)::boolean THEN
        RETURN;
    END IF;

    SET ROLE "administrator";

    -- -------------------------------------------------------------------
    -- 1. Tables
    -- -------------------------------------------------------------------
    CREATE TABLE IF NOT EXISTS sensorthings."CustomPolicy" (
        "id"   BIGSERIAL PRIMARY KEY,
        "name" VARCHAR(255) NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS sensorthings."UserGrant" (
        "id"           BIGSERIAL PRIMARY KEY,
        "user_id"      BIGINT NOT NULL
                       REFERENCES sensorthings."User"("id") ON DELETE CASCADE,
        "role"         VARCHAR(50) NOT NULL
                       CHECK ("role" IN ('viewer','editor','obs_manager','sensor','qc','custom')),
        "all_networks" BOOLEAN NOT NULL DEFAULT FALSE,
        "policy_id"    BIGINT
                       REFERENCES sensorthings."CustomPolicy"("id") ON DELETE RESTRICT,
        CHECK ("role" = 'custom' OR "policy_id" IS NULL)
    );
    CREATE INDEX IF NOT EXISTS "idx_usergrant_user" ON sensorthings."UserGrant" ("user_id");

    CREATE TABLE IF NOT EXISTS sensorthings."GrantMigrationReport" (
        "id"     BIGSERIAL PRIMARY KEY,
        "kind"   TEXT NOT NULL,
        "ref"    TEXT NOT NULL,
        "detail" TEXT
    );

    ALTER TABLE sensorthings."User"
        ADD COLUMN IF NOT EXISTS "requested_networks" JSONB NOT NULL DEFAULT '[]'::jsonb;

    -- AuditLog stays append-only: this is DDL, not an UPDATE.
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'sensorthings' AND table_name = 'AuditLog'
                  AND column_name = 'dataset_id')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'sensorthings' AND table_name = 'AuditLog'
                  AND column_name = 'network_name') THEN
        ALTER TABLE sensorthings."AuditLog" RENAME COLUMN "dataset_id" TO "network_name";
    END IF;

    IF net_on THEN
        CREATE TABLE IF NOT EXISTS sensorthings."UserGrantNetwork" (
            "grant_id"   BIGINT NOT NULL
                         REFERENCES sensorthings."UserGrant"("id") ON DELETE CASCADE,
            "network_id" BIGINT NOT NULL
                         REFERENCES sensorthings."Network"("id") ON DELETE CASCADE,
            PRIMARY KEY ("grant_id", "network_id")
        );
        CREATE INDEX IF NOT EXISTS "idx_usergrantnetwork_network"
            ON sensorthings."UserGrantNetwork" ("network_id");

        -- A grant must never turn into "all Networks" because the Networks
        -- it listed were deleted: all_networks is an explicit flag, and a
        -- non-"all" grant with no Network left is removed.
        CREATE OR REPLACE FUNCTION sensorthings.prune_empty_grant()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = sensorthings, pg_catalog, pg_temp
        AS $fn$
        BEGIN
            DELETE FROM sensorthings."UserGrant" g
             WHERE g."id" = OLD."grant_id"
               AND NOT g."all_networks"
               AND NOT EXISTS (SELECT 1 FROM sensorthings."UserGrantNetwork" n
                                WHERE n."grant_id" = g."id");
            RETURN NULL;
        END
        $fn$;

        DROP TRIGGER IF EXISTS prune_empty_grant ON sensorthings."UserGrantNetwork";
        CREATE TRIGGER prune_empty_grant
            AFTER DELETE ON sensorthings."UserGrantNetwork"
            FOR EACH ROW EXECUTE FUNCTION sensorthings.prune_empty_grant();
    END IF;

    -- -------------------------------------------------------------------
    -- 2. Helpers (all STABLE, SECURITY DEFINER, pinned search_path)
    -- -------------------------------------------------------------------
    CREATE OR REPLACE FUNCTION sensorthings.app_member_id()
    RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = sensorthings, pg_catalog, pg_temp
    AS $fn$
        SELECT u."id" FROM sensorthings."User" u
         WHERE u."id" = sensorthings.current_app_user_id()
           AND u."status" = 'active'
           AND u."role" NOT IN ('pending', 'administrator');
    $fn$;

    CREATE OR REPLACE FUNCTION sensorthings.app_has_role(roles text[])
    RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = sensorthings, pg_catalog, pg_temp
    AS $fn$
        SELECT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g
                        WHERE g."user_id" = sensorthings.app_member_id()
                          AND g."role" = ANY (roles));
    $fn$;

    CREATE OR REPLACE FUNCTION sensorthings.app_grant_all(roles text[])
    RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = sensorthings, pg_catalog, pg_temp
    AS $fn$
        SELECT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g
                        WHERE g."user_id" = sensorthings.app_member_id()
                          AND g."role" = ANY (roles)
                          AND g."all_networks");
    $fn$;

    CREATE OR REPLACE FUNCTION sensorthings.app_policy_any(pid bigint)
    RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = sensorthings, pg_catalog, pg_temp
    AS $fn$
        SELECT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g
                        WHERE g."user_id" = sensorthings.app_member_id()
                          AND g."role" = 'custom' AND g."policy_id" = pid);
    $fn$;

    CREATE OR REPLACE FUNCTION sensorthings.app_policy_all(pid bigint)
    RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = sensorthings, pg_catalog, pg_temp
    AS $fn$
        SELECT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g
                        WHERE g."user_id" = sensorthings.app_member_id()
                          AND g."role" = 'custom' AND g."policy_id" = pid
                          AND g."all_networks");
    $fn$;

    IF net_on THEN
        CREATE OR REPLACE FUNCTION sensorthings.app_grant_nets(roles text[])
        RETURNS bigint[]
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = sensorthings, pg_catalog, pg_temp
        AS $fn$
            SELECT coalesce(
                (SELECT array_agg(DISTINCT gn."network_id")
                   FROM sensorthings."UserGrant" g
                   JOIN sensorthings."UserGrantNetwork" gn ON gn."grant_id" = g."id"
                  WHERE g."user_id" = sensorthings.app_member_id()
                    AND g."role" = ANY (roles)),
                ARRAY[]::bigint[]);
        $fn$;

        CREATE OR REPLACE FUNCTION sensorthings.app_grant_ds_ids(roles text[])
        RETURNS bigint[]
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = sensorthings, pg_catalog, pg_temp
        AS $fn$
            SELECT coalesce(
                (SELECT array_agg(d."id") FROM sensorthings."Datastream" d
                  WHERE d."network_id" = ANY (sensorthings.app_grant_nets(roles))),
                ARRAY[]::bigint[]);
        $fn$;

        CREATE OR REPLACE FUNCTION sensorthings.app_policy_nets(pid bigint)
        RETURNS bigint[]
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = sensorthings, pg_catalog, pg_temp
        AS $fn$
            SELECT coalesce(
                (SELECT array_agg(DISTINCT gn."network_id")
                   FROM sensorthings."UserGrant" g
                   JOIN sensorthings."UserGrantNetwork" gn ON gn."grant_id" = g."id"
                  WHERE g."user_id" = sensorthings.app_member_id()
                    AND g."role" = 'custom' AND g."policy_id" = pid),
                ARRAY[]::bigint[]);
        $fn$;

        CREATE OR REPLACE FUNCTION sensorthings.app_policy_ds_ids(pid bigint)
        RETURNS bigint[]
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = sensorthings, pg_catalog, pg_temp
        AS $fn$
            SELECT coalesce(
                (SELECT array_agg(d."id") FROM sensorthings."Datastream" d
                  WHERE d."network_id" = ANY (sensorthings.app_policy_nets(pid))),
                ARRAY[]::bigint[]);
        $fn$;
    END IF;

    -- Nobody but the SECURITY DEFINER helpers (and the API's service
    -- account) may touch the grant tables.
    REVOKE ALL ON sensorthings."CustomPolicy", sensorthings."UserGrant",
                  sensorthings."GrantMigrationReport"
        FROM PUBLIC, "user", "sensor", "qc", "guest";
    IF net_on THEN
        REVOKE ALL ON sensorthings."UserGrantNetwork"
            FROM PUBLIC, "user", "sensor", "qc", "guest";
    END IF;

    -- -------------------------------------------------------------------
    -- 3. Data copy (skips users that already have a grant)
    -- -------------------------------------------------------------------
    IF has_old THEN
        IF net_on THEN
            INSERT INTO sensorthings."GrantMigrationReport" (kind, ref, detail)
            SELECT 'dangling_dataset', u."username",
                   'role=' || u."role" || ' dataset_id=' || u."dataset_id"
                   || ' matches no Network; user received no grant'
              FROM sensorthings."User" u
             WHERE u."role" IN ('viewer','editor','obs_manager','sensor','qc','custom')
               AND u."dataset_id" IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM sensorthings."Network" n WHERE n."name" = u."dataset_id")
               AND NOT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g WHERE g."user_id" = u."id")
               AND NOT EXISTS (SELECT 1 FROM sensorthings."GrantMigrationReport" x
                                WHERE x."kind" = 'dangling_dataset' AND x."ref" = u."username");
        END IF;

        -- Only grants created by THIS statement are linked to the old
        -- dataset_id: a user that already has grants (e.g. edited through the
        -- API after a first run) is never touched, so a re-run cannot widen
        -- anyone's access.
        IF net_on THEN
            WITH ins AS (
                INSERT INTO sensorthings."UserGrant" ("user_id", "role", "all_networks")
                SELECT u."id", u."role", u."dataset_id" IS NULL
                  FROM sensorthings."User" u
                 WHERE u."role" IN ('viewer','editor','obs_manager','sensor','qc','custom')
                   AND NOT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g WHERE g."user_id" = u."id")
                   AND (u."dataset_id" IS NULL
                        OR EXISTS (SELECT 1 FROM sensorthings."Network" n WHERE n."name" = u."dataset_id"))
                RETURNING "id", "user_id", "all_networks"
            )
            INSERT INTO sensorthings."UserGrantNetwork" ("grant_id", "network_id")
            SELECT ins."id", n."id"
              FROM ins
              JOIN sensorthings."User" u ON u."id" = ins."user_id"
              JOIN sensorthings."Network" n ON n."name" = u."dataset_id"
             WHERE NOT ins."all_networks"
            ON CONFLICT DO NOTHING;
        ELSE
            INSERT INTO sensorthings."UserGrant" ("user_id", "role", "all_networks")
            SELECT u."id", u."role", TRUE
              FROM sensorthings."User" u
             WHERE u."role" IN ('viewer','editor','obs_manager','sensor','qc','custom')
               AND NOT EXISTS (SELECT 1 FROM sensorthings."UserGrant" g WHERE g."user_id" = u."id");
        END IF;

        -- pending / rejected applicants: their request becomes requested_networks
        UPDATE sensorthings."User" u
           SET "requested_networks" = jsonb_build_array(jsonb_build_object(
                   'network_name',
                   CASE WHEN NOT net_on OR u."dataset_id" IS NULL
                        THEN '[]'::jsonb ELSE jsonb_build_array(u."dataset_id") END,
                   'role', u."requested_role"))
         WHERE u."role" = 'pending'
           AND u."requested_role" IS NOT NULL
           AND u."requested_networks" = '[]'::jsonb;
    END IF;

    -- fixed commit rows for sensor / qc grants (set_commit looks them up by
    -- (user_id, actionType))
    INSERT INTO sensorthings."Commit" ("author", "message", "encodingType", "actionType", "user_id")
    SELECT DISTINCT coalesce(u."uri", u."username"), 'Sensor data', 'text/plain', 'CREATE', u."id"
      FROM sensorthings."UserGrant" g JOIN sensorthings."User" u ON u."id" = g."user_id"
     WHERE g."role" = 'sensor'
       AND NOT EXISTS (SELECT 1 FROM sensorthings."Commit" c
                        WHERE c."user_id" = u."id" AND c."actionType" = 'CREATE');
    INSERT INTO sensorthings."Commit" ("author", "message", "encodingType", "actionType", "user_id")
    SELECT DISTINCT coalesce(u."uri", u."username"), 'QC data', 'text/plain', 'UPDATE', u."id"
      FROM sensorthings."UserGrant" g JOIN sensorthings."User" u ON u."id" = g."user_id"
     WHERE g."role" = 'qc'
       AND NOT EXISTS (SELECT 1 FROM sensorthings."Commit" c
                        WHERE c."user_id" = u."id" AND c."actionType" = 'UPDATE');

    -- -------------------------------------------------------------------
    -- 4. Legacy custom policies: report, then drop
    -- -------------------------------------------------------------------
    FOR rec IN
        SELECT p.policyname, p.tablename, p.cmd, p.qual, p.with_check
          FROM pg_policies p
         WHERE p.schemaname = 'sensorthings'
           AND p.roles = '{user}'
           AND (coalesce(p.qual, '') LIKE '%current_app_user_id()%'
                OR coalesce(p.with_check, '') LIKE '%current_app_user_id()%')
    LOOP
        INSERT INTO sensorthings."GrantMigrationReport" (kind, ref, detail)
        VALUES ('legacy_custom_policy', rec.policyname,
                rec.tablename || ' ' || rec.cmd || ': ' || coalesce(rec.qual, rec.with_check));
        EXECUTE format('DROP POLICY %I ON sensorthings.%I', rec.policyname, rec.tablename);
    END LOOP;

    -- -------------------------------------------------------------------
    -- 5. Policies of the "user" group on the live tables
    -- -------------------------------------------------------------------
    FOR rec IN
        SELECT p.policyname, p.tablename FROM pg_policies p
         WHERE p.schemaname = 'sensorthings' AND p.roles = '{user}'
           AND p.policyname LIKE 'rbac\_%'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON sensorthings.%I', rec.policyname, rec.tablename);
    END LOOP;

    IF net_on THEN
        ds_sel := format(
            '((SELECT sensorthings.app_grant_all(%L::text[])) OR network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(%L::text[])))))',
            r_read, r_read);
    ELSE
        ds_sel := format('(SELECT sensorthings.app_has_role(%L::text[]))', r_read);
    END IF;

    -- Datastream
    EXECUTE format('CREATE POLICY rbac_ds_select ON sensorthings."Datastream" FOR SELECT TO "user" USING (%s)', ds_sel);
    IF net_on THEN
        EXECUTE format(
            'CREATE POLICY rbac_ds_editor ON sensorthings."Datastream" FOR ALL TO "user"
             USING ((SELECT sensorthings.app_grant_all(%1$L::text[])) OR network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(%1$L::text[])))))
             WITH CHECK ((SELECT sensorthings.app_grant_all(%1$L::text[])) OR network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(%1$L::text[])))))',
            r_ed);
        EXECUTE format(
            'CREATE POLICY rbac_ds_limited ON sensorthings."Datastream" FOR UPDATE TO "user"
             USING ((SELECT sensorthings.app_grant_all(%1$L::text[])) OR network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(%1$L::text[])))))
             WITH CHECK ((SELECT sensorthings.app_grant_all(%1$L::text[])) OR network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(%1$L::text[])))))',
            r_lim);
    ELSE
        EXECUTE format(
            'CREATE POLICY rbac_ds_editor ON sensorthings."Datastream" FOR ALL TO "user"
             USING ((SELECT sensorthings.app_has_role(%1$L::text[]))) WITH CHECK ((SELECT sensorthings.app_has_role(%1$L::text[])))', r_ed);
        EXECUTE format(
            'CREATE POLICY rbac_ds_limited ON sensorthings."Datastream" FOR UPDATE TO "user"
             USING ((SELECT sensorthings.app_has_role(%1$L::text[]))) WITH CHECK ((SELECT sensorthings.app_has_role(%1$L::text[])))', r_lim);
    END IF;

    -- Observation
    FOR rec IN SELECT * FROM (VALUES
        ('select', r_read), ('all', r_edom), ('ins', r_sens), ('qc', r_qc)
    ) AS v(kind, roles)
    LOOP
        IF net_on THEN
            obs_sel := format(
                '((SELECT sensorthings.app_grant_all(%1$L::text[])) OR datastream_id IN (SELECT unnest((SELECT sensorthings.app_grant_ds_ids(%1$L::text[])))))',
                rec.roles);
        ELSE
            obs_sel := format('(SELECT sensorthings.app_has_role(%L::text[]))', rec.roles);
        END IF;
        IF rec.kind = 'select' THEN
            EXECUTE format('CREATE POLICY rbac_obs_select ON sensorthings."Observation" FOR SELECT TO "user" USING (%s)', obs_sel);
        ELSIF rec.kind = 'all' THEN
            EXECUTE format('CREATE POLICY rbac_obs_all ON sensorthings."Observation" FOR ALL TO "user" USING (%1$s) WITH CHECK (%1$s)', obs_sel);
        ELSIF rec.kind = 'ins' THEN
            EXECUTE format('CREATE POLICY rbac_obs_insert ON sensorthings."Observation" FOR INSERT TO "user" WITH CHECK (%s)', obs_sel);
        ELSE
            EXECUTE format('CREATE POLICY rbac_obs_qc ON sensorthings."Observation" FOR UPDATE TO "user" USING (%1$s) WITH CHECK (%1$s)', obs_sel);
        END IF;
    END LOOP;

    -- Reference tables (+ Network when the feature is on)
    FOREACH tname IN ARRAY (CASE WHEN net_on THEN ref_tables || ARRAY['Network'] ELSE ref_tables END)
    LOOP
        EXECUTE format(
            'CREATE POLICY %I ON sensorthings.%I FOR SELECT TO "user" USING ((SELECT sensorthings.app_has_role(%L::text[])))',
            'rbac_' || lower(tname) || '_select', tname, r_read);
        EXECUTE format(
            'CREATE POLICY %I ON sensorthings.%I FOR ALL TO "user"
             USING ((SELECT sensorthings.app_grant_all(%L::text[])))
             WITH CHECK ((SELECT sensorthings.app_has_role(%L::text[])))',
            'rbac_' || lower(tname) || '_editor', tname, r_ed, r_ed);
    END LOOP;
    EXECUTE format(
        'CREATE POLICY rbac_foi_insert ON sensorthings."FeaturesOfInterest" FOR INSERT TO "user"
         WITH CHECK ((SELECT sensorthings.app_has_role(%L::text[])))', r_foi);
    EXECUTE format(
        'CREATE POLICY rbac_location_limited ON sensorthings."Location" FOR UPDATE TO "user"
         USING ((SELECT sensorthings.app_grant_all(%L::text[])))
         WITH CHECK ((SELECT sensorthings.app_has_role(%L::text[])))', r_lim, r_lim);

    -- -------------------------------------------------------------------
    -- 6. History tables ($as_of): same read predicates as the live tables
    -- -------------------------------------------------------------------
    IF ver_on THEN
        FOREACH tname IN ARRAY (CASE WHEN net_on
                                     THEN ref_tables || ARRAY['Datastream','Observation','Network']
                                     ELSE ref_tables || ARRAY['Datastream','Observation'] END)
        LOOP
            IF to_regclass(format('sensorthings_history.%I', tname)) IS NULL THEN
                CONTINUE;
            END IF;
            EXECUTE format('DROP POLICY IF EXISTS %I ON sensorthings_history.%I',
                           'rbac_history_user_select_' || tname, tname);
            IF tname = 'Datastream' THEN
                EXECUTE format('CREATE POLICY %I ON sensorthings_history.%I FOR SELECT TO "user" USING (%s)',
                               'rbac_history_user_select_' || tname, tname, ds_sel);
            ELSIF tname = 'Observation' THEN
                IF net_on THEN
                    obs_sel := format(
                        '((SELECT sensorthings.app_grant_all(%1$L::text[])) OR datastream_id IN (SELECT unnest((SELECT sensorthings.app_grant_ds_ids(%1$L::text[])))))',
                        r_read);
                ELSE
                    obs_sel := format('(SELECT sensorthings.app_has_role(%L::text[]))', r_read);
                END IF;
                EXECUTE format('CREATE POLICY %I ON sensorthings_history.%I FOR SELECT TO "user" USING (%s)',
                               'rbac_history_user_select_' || tname, tname, obs_sel);
            ELSE
                EXECUTE format(
                    'CREATE POLICY %I ON sensorthings_history.%I FOR SELECT TO "user" USING ((SELECT sensorthings.app_has_role(%L::text[])))',
                    'rbac_history_user_select_' || tname, tname, r_read);
            END IF;
        END LOOP;
    END IF;

    -- -------------------------------------------------------------------
    -- 7. Column-limit triggers (replace the sensor/qc column-level GRANTs)
    -- -------------------------------------------------------------------
    CREATE OR REPLACE FUNCTION sensorthings.limit_member_columns()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $fn$
    DECLARE
        ent       text := TG_ARGV[0];  -- never TG_TABLE_NAME: on a hypertable that is the chunk
        net       boolean := coalesce(current_setting('custom.network', true)::boolean, false);
        allowed   text[];
        unlimited text[];
        limiting  text[];
        covered   boolean := false;
        col       text;
        jo        jsonb;
        jn        jsonb;
    BEGIN
        -- Only member sessions are limited; administrator/owner paths pass.
        IF current_user <> 'user' THEN
            RETURN NEW;
        END IF;

        -- A row is "covered" (every column may change) when the caller holds an
        -- unlimited role there, or a `custom` grant there and no limited role
        -- (the limited roles' own update policies are the ones that let them
        -- reach the row, and those must keep their column limits). A custom
        -- user is otherwise bounded only by the rows its policy allows.
        IF ent = 'Datastream' THEN
            unlimited := ARRAY['editor'];
            limiting  := ARRAY['obs_manager','sensor'];
            allowed := ARRAY['phenomenonTime','resultTime','last_foi_id','observedArea',
                             'commit_id','systemTimeValidity'];
            IF net THEN
                covered := (SELECT sensorthings.app_grant_all(unlimited))
                        OR OLD.network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(unlimited))))
                        OR ((  (SELECT sensorthings.app_grant_all(ARRAY['custom']))
                             OR OLD.network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(ARRAY['custom'])))))
                            AND NOT (  (SELECT sensorthings.app_grant_all(limiting))
                                    OR OLD.network_id IN (SELECT unnest((SELECT sensorthings.app_grant_nets(limiting))))));
            ELSE
                covered := (SELECT sensorthings.app_has_role(unlimited))
                        OR ((SELECT sensorthings.app_has_role(ARRAY['custom']))
                            AND NOT (SELECT sensorthings.app_has_role(limiting)));
            END IF;
        ELSIF ent = 'Location' THEN
            unlimited := ARRAY['editor'];
            limiting  := ARRAY['obs_manager','sensor'];
            allowed := ARRAY['gen_foi_id','commit_id','systemTimeValidity'];
            covered := (SELECT sensorthings.app_grant_all(unlimited))
                    OR ((SELECT sensorthings.app_grant_all(ARRAY['custom']))
                        AND NOT (SELECT sensorthings.app_grant_all(limiting)));
        ELSIF ent = 'Observation' THEN
            unlimited := ARRAY['editor','obs_manager'];
            limiting  := ARRAY['qc'];
            allowed := ARRAY['resultQuality','commit_id','systemTimeValidity'];
            IF net THEN
                covered := (SELECT sensorthings.app_grant_all(unlimited))
                        OR OLD.datastream_id IN (SELECT unnest((SELECT sensorthings.app_grant_ds_ids(unlimited))))
                        OR ((  (SELECT sensorthings.app_grant_all(ARRAY['custom']))
                             OR OLD.datastream_id IN (SELECT unnest((SELECT sensorthings.app_grant_ds_ids(ARRAY['custom'])))))
                            AND NOT (  (SELECT sensorthings.app_grant_all(limiting))
                                    OR OLD.datastream_id IN (SELECT unnest((SELECT sensorthings.app_grant_ds_ids(limiting))))));
            ELSE
                covered := (SELECT sensorthings.app_has_role(unlimited))
                        OR ((SELECT sensorthings.app_has_role(ARRAY['custom']))
                            AND NOT (SELECT sensorthings.app_has_role(limiting)));
            END IF;
        ELSE
            RAISE EXCEPTION 'limit_member_columns attached with unknown entity %', ent;
        END IF;

        IF covered THEN
            RETURN NEW;
        END IF;

        jo := to_jsonb(OLD);
        jn := to_jsonb(NEW);
        FOR col IN SELECT jsonb_object_keys(jn) LOOP
            IF NOT (col = ANY (allowed)) AND (jn -> col) IS DISTINCT FROM (jo -> col) THEN
                RAISE EXCEPTION 'column "%" may not be changed with the grants you hold', col
                    USING ERRCODE = '42501';
            END IF;
        END LOOP;
        RETURN NEW;
    END
    $fn$;

    FOREACH tname IN ARRAY ARRAY['Datastream', 'Location', 'Observation']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS aa_limit_member_columns ON sensorthings.%I', tname);
        EXECUTE format(
            'CREATE TRIGGER aa_limit_member_columns BEFORE UPDATE ON sensorthings.%I
             FOR EACH ROW EXECUTE FUNCTION sensorthings.limit_member_columns(%L)', tname, tname);
    END LOOP;

    RESET ROLE;
END $BODY$;
