-- Grants RLS audit, NETWORK=0 variant: there are no Networks, so a grant
-- covers the whole database (all_networks = true). Same contract as
-- grants_rls_audit.sql with every Network-scoped user collapsed to its
-- role-level equivalent.
--
-- Self-contained and side-effect free: one transaction, ROLLBACK. Run through
-- run_grants_rls_audit.py (which picks this file when sensorthings."Network"
-- does not exist and refuses to run without DB_CONTAINER).
--
-- Fixture assumption: dummy data loaded (>= 2 Datastreams with Observations).
\set ON_ERROR_STOP off
BEGIN;

DO $setup$
DECLARE
    pid bigint; ug bigint; g record; dmin bigint; dmax bigint;
BEGIN
    SELECT min(id), max(id) INTO dmin, dmax FROM sensorthings."Datastream";
    IF dmin IS NULL OR dmin = dmax THEN
        RAISE EXCEPTION 'fixture missing: need at least two Datastreams (load the dummy data)';
    END IF;
    INSERT INTO sensorthings."CustomPolicy"(name) VALUES ('audit_pol') RETURNING id INTO pid;

    CREATE TEMP TABLE _g(u text, role text, pol bigint) ON COMMIT DROP;
    INSERT INTO _g VALUES
      ('au_viewer','viewer',NULL),
      ('au_editor','editor',NULL),
      ('au_mixed','editor',NULL),
      ('au_sensor','sensor',NULL),
      ('au_qc','qc',NULL),
      ('au_obsmgr','obs_manager',NULL),
      ('au_vs','viewer',NULL),
      ('au_vs','sensor',NULL),
      ('au_sq','sensor',NULL),
      ('au_sq','qc',NULL),
      ('au_custom','custom',pid),
      ('au_pending','viewer',NULL);

    INSERT INTO sensorthings."User"(username, role, status, password)
      SELECT DISTINCT u, CASE WHEN u='au_pending' THEN 'pending' ELSE 'member' END,
             CASE WHEN u='au_pending' THEN 'pending' ELSE 'active' END, 'x' FROM _g;
    INSERT INTO sensorthings."User"(username, role, status, password) VALUES ('au_zero','member','active','x');

    FOR g IN SELECT * FROM _g LOOP
        INSERT INTO sensorthings."UserGrant"(user_id, role, all_networks, policy_id)
          SELECT id, g.role, true, g.pol FROM sensorthings."User" WHERE username = g.u;
    END LOOP;

    -- custom rule on two literal Datastream ids (a policy must not subquery
    -- its own table); with no Networks the rule applies wherever the grant is.
    EXECUTE format($q$CREATE POLICY audit_pol_datastream_select ON sensorthings."Datastream"
        FOR SELECT TO "user"
        USING ((SELECT sensorthings.app_policy_any(%1$s)) AND id IN (%2$s, %3$s))$q$,
        pid, dmin, dmax);
END $setup$;

DO $audit$
DECLARE
    tests jsonb; t jsonb; ids jsonb := '{}'; users text[]; who text; u record;
    d1 bigint; d2 bigint; o1 bigint; sens bigint; loc bigint;
    all_ds bigint; all_obs bigint;
    sql text; exp text; act text; n bigint; pass int := 0; fail int := 0;
BEGIN
    SELECT min(id), max(id) INTO d1, d2 FROM sensorthings."Datastream";
    SELECT count(*) INTO all_ds FROM sensorthings."Datastream";
    SELECT count(*) INTO all_obs FROM sensorthings."Observation";
    SELECT min(id) INTO o1 FROM sensorthings."Observation" WHERE datastream_id = d1;
    SELECT min(id) INTO sens FROM sensorthings."Sensor";
    SELECT min(id) INTO loc FROM sensorthings."Location";
    FOR u IN SELECT id, username FROM sensorthings."User" WHERE username LIKE 'au\_%' ORDER BY username LOOP
        ids := ids || jsonb_build_object(u.username, u.id);
        users := users || u.username::text;
    END LOOP;

    -- "@" is replaced by a double quote, __D1__/__D2__/__O1__/__S__/__L__ by ids.
    tests := $j$[
     {
     "l": "R ds count",
     "sql": "SELECT count(*) FROM sensorthings.@Datastream@",
     "d": "__ALL_DS__",
     "o": {
     "au_viewer": "__ALL_DS__",
     "au_editor": "__ALL_DS__",
     "au_mixed": "__ALL_DS__",
     "au_sensor": "__ALL_DS__",
     "au_vs": "__ALL_DS__",
     "au_custom": "2",
     "au_pending": "0",
     "au_zero": "0",
     "au_obsmgr": "__ALL_DS__",
     "au_qc": "__ALL_DS__",
     "au_sq": "__ALL_DS__"
     }
     },
     {
     "l": "R obs count",
     "sql": "SELECT count(*) FROM sensorthings.@Observation@",
     "d": "__ALL_OBS__",
     "o": {
     "au_viewer": "__ALL_OBS__",
     "au_editor": "__ALL_OBS__",
     "au_mixed": "__ALL_OBS__",
     "au_sensor": "__ALL_OBS__",
     "au_vs": "__ALL_OBS__",
     "au_custom": "0",
     "au_pending": "0",
     "au_zero": "0",
     "au_obsmgr": "__ALL_OBS__",
     "au_qc": "__ALL_OBS__",
     "au_sq": "__ALL_OBS__"
     }
     },
     {
     "l": "R sensor count",
     "sql": "SELECT count(*) FROM sensorthings.@Sensor@",
     "d": ">0",
     "o": {
     "au_custom": "0",
     "au_pending": "0",
     "au_zero": "0"
     }
     },
     {
     "l": "W ds.name N1",
     "sql": "UPDATE sensorthings.@Datastream@ SET name = name||'!' WHERE id = __D1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "ERR",
     "au_vs": "ERR",
     "au_obsmgr": "ERR",
     "au_sq": "ERR"
     }
     },
     {
     "l": "W ds.name N2",
     "sql": "UPDATE sensorthings.@Datastream@ SET name = name||'!' WHERE id = __D2__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "ERR",
     "au_vs": "ERR",
     "au_obsmgr": "ERR",
     "au_sq": "ERR"
     }
     },
     {
     "l": "W ds.observedArea N1",
     "sql": "UPDATE sensorthings.@Datastream@ SET @observedArea@ = ST_Translate(@observedArea@, 0.000001, 0) WHERE id = __D1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "1",
     "au_vs": "1",
     "au_obsmgr": "1",
     "au_sq": "1"
     }
     },
     {
     "l": "W ds.observedArea N2",
     "sql": "UPDATE sensorthings.@Datastream@ SET @observedArea@ = ST_Translate(@observedArea@, 0.000001, 0) WHERE id = __D2__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "1",
     "au_vs": "1",
     "au_obsmgr": "1",
     "au_sq": "1"
     }
     },
     {
     "l": "W ds full-row PUT-like, unchanged",
     "sql": "UPDATE sensorthings.@Datastream@ SET name = name, description = description, @observedArea@ = ST_Translate(@observedArea@, 0.000001, 0), @unitOfMeasurement@ = @unitOfMeasurement@ WHERE id = __D1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "1",
     "au_vs": "1",
     "au_obsmgr": "1",
     "au_sq": "1"
     }
     },
     {
     "l": "W ds delete N1",
     "sql": "DELETE FROM sensorthings.@Datastream@ WHERE id = __D1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1"
     }
     },
     {
     "l": "W obs.resultQuality N1",
     "sql": "UPDATE sensorthings.@Observation@ SET @resultQuality@ = '{@q@:1}' WHERE id = __O1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_obsmgr": "1",
     "au_qc": "1",
     "au_sq": "1"
     }
     },
     {
     "l": "W obs.resultNumber N1",
     "sql": "UPDATE sensorthings.@Observation@ SET @resultNumber@ = coalesce(@resultNumber@,0)+1 WHERE id = __O1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_obsmgr": "1",
     "au_qc": "ERR",
     "au_sq": "ERR"
     }
     },
     {
     "l": "W obs delete N1",
     "sql": "DELETE FROM sensorthings.@Observation@ WHERE id = __O1__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_obsmgr": "1"
     }
     },
     {
     "l": "W obs insert N1",
     "sql": "INSERT INTO sensorthings.@Observation@(@resultType@, datastream_id, featuresofinterest_id, @phenomenonTimeStart@, @phenomenonTimeEnd@, @resultTime@, @resultNumber@) SELECT @resultType@, __D1__, featuresofinterest_id, now(), now(), now(), 1 FROM sensorthings.@Observation@ WHERE id = __O1__",
     "d": "ERR",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "1",
     "au_vs": "1",
     "au_obsmgr": "1",
     "au_sq": "1",
     "au_custom": "0",
     "au_pending": "0",
     "au_zero": "0"
     }
     },
     {
     "l": "W Sensor update",
     "sql": "UPDATE sensorthings.@Sensor@ SET name = name||'.' WHERE id = __S__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1"
     }
     },
     {
     "l": "W Thing insert",
     "sql": "INSERT INTO sensorthings.@Thing@(name, description, properties, commit_id) SELECT name||'-x', description, properties, commit_id FROM sensorthings.@Thing@ LIMIT 1",
     "d": "ERR",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_custom": "0",
     "au_pending": "0",
     "au_zero": "0"
     }
     },
     {
     "l": "W FOI insert",
     "sql": "INSERT INTO sensorthings.@FeaturesOfInterest@(name, description, @encodingType@, feature, commit_id) SELECT name||'-x', description, @encodingType@, feature, commit_id FROM sensorthings.@FeaturesOfInterest@ LIMIT 1",
     "d": "ERR",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "1",
     "au_vs": "1",
     "au_obsmgr": "1",
     "au_sq": "1",
     "au_custom": "0",
     "au_pending": "0",
     "au_zero": "0"
     }
     },
     {
     "l": "W Location.gen_foi_id",
     "sql": "UPDATE sensorthings.@Location@ SET gen_foi_id = (SELECT min(id) FROM sensorthings.@FeaturesOfInterest@ WHERE id <> coalesce(gen_foi_id, -1)) WHERE id = __L__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "1",
     "au_vs": "1",
     "au_obsmgr": "1",
     "au_sq": "1"
     }
     },
     {
     "l": "W Location.name",
     "sql": "UPDATE sensorthings.@Location@ SET name = name||'!' WHERE id = __L__",
     "d": "0",
     "o": {
     "au_editor": "1",
     "au_mixed": "1",
     "au_sensor": "ERR",
     "au_vs": "ERR",
     "au_obsmgr": "ERR",
     "au_sq": "ERR"
     }
     },
     {
     "l": "R UserGrant table",
     "sql": "SELECT count(*) FROM sensorthings.@UserGrant@",
     "d": "ERR"
     },
     {
     "l": "R CustomPolicy table",
     "sql": "SELECT count(*) FROM sensorthings.@CustomPolicy@",
     "d": "ERR"
     },
     {
     "l": "R UserGrantNetwork table",
     "sql": "SELECT count(*) FROM sensorthings.@UserGrantNetwork@",
     "d": "ERR"
     },
     {
     "l": "R GrantMigrationReport table",
     "sql": "SELECT count(*) FROM sensorthings.@GrantMigrationReport@",
     "d": "ERR"
     },
     {
     "l": "R User table",
     "sql": "SELECT count(*) FROM sensorthings.@User@",
     "d": "ERR"
     },
     {
     "l": "W self-promote via User",
     "sql": "UPDATE sensorthings.@User@ SET role = 'administrator' WHERE username = 'au_zero'",
     "d": "ERR"
     },
     {
     "l": "W insert own grant",
     "sql": "INSERT INTO sensorthings.@UserGrant@(user_id, role, all_networks) VALUES (1,'editor',true)",
     "d": "ERR"
     },
     {
     "l": "W Commit update",
     "sql": "UPDATE sensorthings.@Commit@ SET message = message WHERE id = 1",
     "d": "ERR"
     }
     ]$j$::jsonb;

    EXECUTE 'SET LOCAL ROLE "user"';
    FOR t IN SELECT * FROM jsonb_array_elements(tests) LOOP
        FOREACH who IN ARRAY users LOOP
            PERFORM set_config('app.current_user_id', (ids ->> who), true);
            sql := replace(replace(replace(replace(replace(replace(t->>'sql','@','"'),
                       '__D1__', d1::text), '__D2__', d2::text), '__O1__', o1::text),
                       '__S__', sens::text), '__L__', loc::text);
            exp := coalesce(t->'o'->>who, t->>'d');
            exp := replace(replace(exp, '__ALL_DS__', all_ds::text), '__ALL_OBS__', all_obs::text);
            BEGIN
                IF sql LIKE 'SELECT count%' THEN EXECUTE sql INTO n;
                ELSE EXECUTE sql; GET DIAGNOSTICS n = ROW_COUNT; END IF;
                act := n::text;
                RAISE EXCEPTION '__undo__';          -- isolate every test
            EXCEPTION WHEN OTHERS THEN
                IF SQLERRM <> '__undo__' THEN act := 'ERR:' || left(SQLERRM, 70); END IF;
            END;
            IF (exp = 'ERR' AND act LIKE 'ERR%') OR (exp = '>0' AND act !~ '^(ERR|0$)') OR act = exp THEN
                pass := pass + 1;
            ELSE
                fail := fail + 1;
                RAISE NOTICE 'MISMATCH  % | % | expected % got %', t->>'l', who, exp, act;
            END IF;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'RESULT: % passed, % mismatched', pass, fail;
END $audit$;

-- Policies must evaluate helpers once per query: a bare helper call in a
-- policy predicate costs ~1000x on large tables.
DO $wrap$
DECLARE bad int;
BEGIN
    SELECT count(*) INTO bad
      FROM pg_policies p
     WHERE p.schemaname IN ('sensorthings','sensorthings_history')
       AND (coalesce(p.qual,'') || ' ' || coalesce(p.with_check,'')) ~
           '(?<!SELECT )sensorthings\.app_(has_role|grant_all|grant_nets|grant_ds_ids|policy_any|policy_all|policy_nets|policy_ds_ids)\(';
    IF bad > 0 THEN
        RAISE NOTICE 'MISMATCH  unwrapped helper call in % policies', bad;
    ELSE
        RAISE NOTICE 'RESULT: all helper calls in policies are evaluated once per query';
    END IF;
END $wrap$;

ROLLBACK;
