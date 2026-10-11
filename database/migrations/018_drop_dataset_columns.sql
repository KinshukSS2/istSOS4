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
-- Migration: 018_drop_dataset_columns
-- Description: Cleanup after 017_network_grants has been applied and verified.
--
--              017 moved every user's access into UserGrant. Nothing reads
--              User.dataset_id / User.requested_role any more, and the
--              "sensor" and "qc" PostgreSQL group roles are no longer used for
--              member requests (every member runs as the "user" group; the
--              sensor/qc limits are enforced by RLS + column-limit triggers).
--
--              This migration:
--                * drops the old group policies of "sensor" and "qc" (and the
--                  helper functions they depend on),
--                * drops User.dataset_id and User.requested_role,
--                * normalises User.role of members to 'member' (the grants
--                  carry the access; 'administrator' and 'pending' stay).
--
--              Run it only after 017 and after the Phase-4 verification.
--              Idempotent.
-- =============================================================================

DO $BODY$
DECLARE
    rec record;
BEGIN
    IF NOT current_setting('custom.authorization', true)::boolean THEN
        RETURN;
    END IF;

    SET ROLE "administrator";

    -- the old sensor/qc group policies reference the old helper functions
    FOR rec IN
        SELECT p.schemaname, p.policyname, p.tablename
          FROM pg_policies p
         WHERE p.schemaname IN ('sensorthings', 'sensorthings_history')
           AND (p.roles = '{sensor}' OR p.roles = '{qc}')
           AND p.policyname LIKE 'rbac\_%'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                       rec.policyname, rec.schemaname, rec.tablename);
    END LOOP;

    -- the old "user" policies on history tables that still use the old
    -- helpers were rebuilt by 017; drop any that survived (e.g. Network
    -- history when NETWORK was off at 017 time)
    FOR rec IN
        SELECT p.schemaname, p.policyname, p.tablename
          FROM pg_policies p
         WHERE p.schemaname IN ('sensorthings', 'sensorthings_history')
           AND (coalesce(p.qual, '') LIKE '%current_app_user_role()%'
                OR coalesce(p.qual, '') LIKE '%current_app_user_dataset_id()%'
                OR coalesce(p.qual, '') LIKE '%current_app_user_network_id()%'
                OR coalesce(p.qual, '') LIKE '%current_app_user_datastream_ids()%'
                OR coalesce(p.with_check, '') LIKE '%current_app_user_role()%'
                OR coalesce(p.with_check, '') LIKE '%current_app_user_dataset_id()%'
                OR coalesce(p.with_check, '') LIKE '%current_app_user_network_id()%'
                OR coalesce(p.with_check, '') LIKE '%current_app_user_datastream_ids()%')
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                       rec.policyname, rec.schemaname, rec.tablename);
    END LOOP;

    DROP FUNCTION IF EXISTS sensorthings.current_app_user_datastream_ids();
    DROP FUNCTION IF EXISTS sensorthings.current_app_user_network_id();
    DROP FUNCTION IF EXISTS sensorthings.current_app_user_dataset_id();
    DROP FUNCTION IF EXISTS sensorthings.current_app_user_role();

    ALTER TABLE sensorthings."User" DROP COLUMN IF EXISTS "dataset_id";
    ALTER TABLE sensorthings."User" DROP COLUMN IF EXISTS "requested_role";

    UPDATE sensorthings."User"
       SET "role" = 'member'
     WHERE "role" NOT IN ('administrator', 'pending', 'member');

    RESET ROLE;
END $BODY$;
