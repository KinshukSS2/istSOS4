-- Grants RLS audit: every role x every operation against the real policies.
--
-- Self-contained and side-effect free: it creates its own users and grants
-- inside one transaction and ROLLBACKs. Run through run_grants_rls_audit.py
-- (which refuses to run without an explicit DB_CONTAINER).
--
-- Fixture assumptions: dummy data loaded (two Networks that each own
-- Datastreams and Observations; the lowest and highest ids are used). Expected values are the contract of
-- migration 017; a MISMATCH line is a regression.
\set ON_ERROR_STOP off
BEGIN;

DO $setup$
DECLARE
    n1 bigint; n2 bigint; pid bigint; ug bigint;
    g record;
BEGIN
    SELECT min(network_id) INTO n1 FROM sensorthings."Datastream";
    SELECT max(network_id) INTO n2 FROM sensorthings."Datastream";
    IF n1 IS NULL OR n2 IS NULL THEN
        RAISE EXCEPTION 'fixture missing: need two Networks that own Datastreams (load the dummy data)';
    END IF;
    INSERT INTO sensorthings."CustomPolicy"(name) VALUES ('audit_pol') RETURNING id INTO pid;

    CREATE TEMP TABLE _g(u text, role text, allnet bool, nets bigint[], pol bigint) ON COMMIT DROP;
    INSERT INTO _g VALUES
      ('au_viewer_A','viewer',false,ARRAY[n1],NULL),
      ('au_editor_B','editor',false,ARRAY[n2],NULL),
      ('au_sensor_A','sensor',false,ARRAY[n1],NULL),
      ('au_qc_A','qc',false,ARRAY[n1],NULL),
      ('au_obsmgr_A','obs_manager',false,ARRAY[n1],NULL),
      ('au_viewer_all','viewer',true,'{}',NULL),
      ('au_editor_all','editor',true,'{}',NULL),
      ('au_sensor_all','sensor',true,'{}',NULL),
      ('au_mixed','viewer',false,ARRAY[n1],NULL),
      ('au_mixed','editor',false,ARRAY[n2],NULL),
      ('au_vs','viewer',true,'{}',NULL),
      ('au_vs','sensor',false,ARRAY[n2],NULL),
      ('au_sq','sensor',false,ARRAY[n1],NULL),
      ('au_sq','qc',false,ARRAY[n1],NULL),
      ('au_custom','custom',false,ARRAY[n1],pid),
      ('au_cs','custom',false,ARRAY[n1],pid),
      ('au_cs','sensor',false,ARRAY[n1],NULL),
      ('au_pending','viewer',true,'{}',NULL);

    INSERT INTO sensorthings."User"(username, role, status, password)
      SELECT DISTINCT u, CASE WHEN u='au_pending' THEN 'pending' ELSE 'member' END,
             CASE WHEN u='au_pending' THEN 'pending' ELSE 'active' END, 'x' FROM _g;
    INSERT INTO sensorthings."User"(username, role, status, password) VALUES ('au_zero','member','active','x');

    FOR g IN SELECT * FROM _g LOOP
        INSERT INTO sensorthings."UserGrant"(user_id, role, all_networks, policy_id)
          SELECT id, g.role, g.allnet, g.pol FROM sensorthings."User" WHERE username = g.u
          RETURNING id INTO ug;
        INSERT INTO sensorthings."UserGrantNetwork"(grant_id, network_id)
          SELECT ug, unnest(g.nets);
    END LOOP;

    -- custom rule: select the first Datastream of Network 1 and of Network 2
    -- (literal ids: a policy must not subquery its own table). The grant covers
    -- Network 1 only, so only the Network-1 Datastream may appear.
    EXECUTE format($q$CREATE POLICY audit_pol_datastream_select ON sensorthings."Datastream"
        FOR SELECT TO "user"
        USING (((SELECT sensorthings.app_policy_all(%1$s))
                OR network_id IN (SELECT unnest((SELECT sensorthings.app_policy_nets(%1$s)))))
               AND id IN (%2$s, %3$s))$q$, pid,
        (SELECT min(id) FROM sensorthings."Datastream" WHERE network_id = n1),
        (SELECT min(id) FROM sensorthings."Datastream" WHERE network_id = n2));

    -- the same policy may also UPDATE the first Datastream of Network 1: a custom
    -- user is bounded by its policy's rows, not by a column list ...
    EXECUTE format($q$CREATE POLICY audit_pol_datastream_update ON sensorthings."Datastream"
        FOR UPDATE TO "user"
        USING (((SELECT sensorthings.app_policy_all(%1$s))
                OR network_id IN (SELECT unnest((SELECT sensorthings.app_policy_nets(%1$s)))))
               AND id = %2$s)
        WITH CHECK (((SELECT sensorthings.app_policy_all(%1$s))
                OR network_id IN (SELECT unnest((SELECT sensorthings.app_policy_nets(%1$s)))))
               AND id = %2$s)$q$, pid,
        (SELECT min(id) FROM sensorthings."Datastream" WHERE network_id = n1));
END $setup$;

DO $audit$
DECLARE
    tests jsonb; t jsonb; ids jsonb := '{}'; users text[]; who text; u record;
    d1 bigint; d2 bigint; o1 bigint; sens bigint; loc bigint;
    na_ds bigint; nb_ds bigint; na_obs bigint; nb_obs bigint; all_ds bigint; all_obs bigint;
    sql text; exp text; act text; n bigint; pass int := 0; fail int := 0;
BEGIN
    SELECT min(id) INTO d1 FROM sensorthings."Datastream" WHERE network_id = (SELECT min(network_id) FROM sensorthings."Datastream");
    SELECT min(id) INTO d2 FROM sensorthings."Datastream" WHERE network_id = (SELECT max(network_id) FROM sensorthings."Datastream");
    SELECT count(*) INTO all_ds FROM sensorthings."Datastream";
    SELECT count(*) INTO all_obs FROM sensorthings."Observation";
    SELECT count(*) INTO na_ds FROM sensorthings."Datastream" WHERE network_id = (SELECT min(network_id) FROM sensorthings."Datastream");
    SELECT count(*) INTO nb_ds FROM sensorthings."Datastream" WHERE network_id = (SELECT max(network_id) FROM sensorthings."Datastream");
    SELECT count(*) INTO na_obs FROM sensorthings."Observation" o JOIN sensorthings."Datastream" d ON d.id = o.datastream_id
        WHERE d.network_id = (SELECT min(network_id) FROM sensorthings."Datastream");
    SELECT count(*) INTO nb_obs FROM sensorthings."Observation" o JOIN sensorthings."Datastream" d ON d.id = o.datastream_id
        WHERE d.network_id = (SELECT max(network_id) FROM sensorthings."Datastream");
    SELECT min(id) INTO o1 FROM sensorthings."Observation" WHERE datastream_id = d1;
    SELECT min(id) INTO sens FROM sensorthings."Sensor";
    SELECT min(id) INTO loc FROM sensorthings."Location";
    FOR u IN SELECT id, username FROM sensorthings."User" WHERE username LIKE 'au\_%' ORDER BY username LOOP
        ids := ids || jsonb_build_object(u.username, u.id);
        users := users || u.username::text;
    END LOOP;

    -- "@" is replaced by a double quote, __D1__/__D2__/__O1__/__S__/__L__ by ids.
    tests := $j$[
     {"l":"R ds count","sql":"SELECT count(*) FROM sensorthings.@Datastream@","d":"__NA_DS__",
      "o":{"au_editor_B":"__NB_DS__","au_viewer_all":"__ALL_DS__","au_editor_all":"__ALL_DS__","au_mixed":"__ALL_DS__","au_vs":"__ALL_DS__","au_sensor_all":"__ALL_DS__","au_zero":"0","au_pending":"0","au_custom":"1"}},
     {"l":"R obs count","sql":"SELECT count(*) FROM sensorthings.@Observation@","d":"__NA_OBS__",
      "o":{"au_editor_B":"__NB_OBS__","au_viewer_all":"__ALL_OBS__","au_editor_all":"__ALL_OBS__","au_mixed":"__ALL_OBS__","au_vs":"__ALL_OBS__","au_sensor_all":"__ALL_OBS__","au_zero":"0","au_pending":"0","au_custom":"0"}},
     {"l":"R sensor count","sql":"SELECT count(*) FROM sensorthings.@Sensor@","d":">0","o":{"au_zero":"0","au_pending":"0","au_custom":"0"}},
     {"l":"R network count","sql":"SELECT count(*) FROM sensorthings.@Network@","d":">0","o":{"au_zero":"0","au_pending":"0","au_custom":"0"}},

     {"l":"W ds.name N1","sql":"UPDATE sensorthings.@Datastream@ SET name = name||'!' WHERE id = __D1__","d":"0",
      "o":{"au_sensor_A":"ERR","au_obsmgr_A":"ERR","au_editor_all":"1","au_sensor_all":"ERR","au_sq":"ERR","au_custom":"1","au_cs":"ERR"}},
     {"l":"W ds.name N2","sql":"UPDATE sensorthings.@Datastream@ SET name = name||'!' WHERE id = __D2__","d":"0",
      "o":{"au_editor_B":"1","au_editor_all":"1","au_mixed":"1","au_vs":"ERR","au_sensor_all":"ERR"}},
     {"l":"W ds.observedArea N1","sql":"UPDATE sensorthings.@Datastream@ SET @observedArea@ = ST_Translate(@observedArea@, 0.000001, 0) WHERE id = __D1__","d":"0",
      "o":{"au_sensor_A":"1","au_obsmgr_A":"1","au_editor_all":"1","au_sensor_all":"1","au_sq":"1","au_custom":"1","au_cs":"1"}},
     {"l":"W ds.observedArea N2","sql":"UPDATE sensorthings.@Datastream@ SET @observedArea@ = ST_Translate(@observedArea@, 0.000001, 0) WHERE id = __D2__","d":"0",
      "o":{"au_editor_B":"1","au_editor_all":"1","au_mixed":"1","au_vs":"1","au_sensor_all":"1"}},
     {"l":"W ds full-row PUT-like, unchanged","sql":"UPDATE sensorthings.@Datastream@ SET name = name, description = description, @observedArea@ = ST_Translate(@observedArea@, 0.000001, 0), @unitOfMeasurement@ = @unitOfMeasurement@ WHERE id = __D1__","d":"0",
      "o":{"au_sensor_A":"1","au_obsmgr_A":"1","au_editor_all":"1","au_sensor_all":"1","au_sq":"1","au_custom":"1","au_cs":"1"}},
     {"l":"W ds delete N1","sql":"DELETE FROM sensorthings.@Datastream@ WHERE id = __D1__","d":"0","o":{"au_editor_all":"1"}},

     {"l":"W obs.resultQuality N1","sql":"UPDATE sensorthings.@Observation@ SET @resultQuality@ = '{@q@:1}' WHERE id = __O1__","d":"0",
      "o":{"au_qc_A":"1","au_obsmgr_A":"1","au_editor_all":"1","au_sq":"1"}},
     {"l":"W obs.resultNumber N1","sql":"UPDATE sensorthings.@Observation@ SET @resultNumber@ = coalesce(@resultNumber@,0)+1 WHERE id = __O1__","d":"0",
      "o":{"au_qc_A":"ERR","au_obsmgr_A":"1","au_editor_all":"1","au_sq":"ERR"}},
     {"l":"W obs delete N1","sql":"DELETE FROM sensorthings.@Observation@ WHERE id = __O1__","d":"0","o":{"au_obsmgr_A":"1","au_editor_all":"1"}},
     {"l":"W obs insert N1","sql":"INSERT INTO sensorthings.@Observation@(@resultType@, datastream_id, featuresofinterest_id, @phenomenonTimeStart@, @phenomenonTimeEnd@, @resultTime@, @resultNumber@) SELECT @resultType@, __D1__, featuresofinterest_id, now(), now(), now(), 1 FROM sensorthings.@Observation@ WHERE id = __O1__","d":"ERR",
      "o":{"au_zero":"0","au_pending":"0","au_custom":"0","au_editor_B":"0","au_sensor_A":"1","au_obsmgr_A":"1","au_editor_all":"1","au_sensor_all":"1","au_sq":"1","au_cs":"1"}},

     {"l":"W Sensor update","sql":"UPDATE sensorthings.@Sensor@ SET name = name||'.' WHERE id = __S__","d":"0","o":{"au_editor_all":"1"}},
     {"l":"W Thing insert","sql":"INSERT INTO sensorthings.@Thing@(name, description, properties, commit_id) SELECT name||'-x', description, properties, commit_id FROM sensorthings.@Thing@ LIMIT 1","d":"ERR",
      "o":{"au_zero":"0","au_pending":"0","au_custom":"0","au_editor_B":"1","au_editor_all":"1","au_mixed":"1"}},
     {"l":"W FOI insert","sql":"INSERT INTO sensorthings.@FeaturesOfInterest@(name, description, @encodingType@, feature, commit_id) SELECT name||'-x', description, @encodingType@, feature, commit_id FROM sensorthings.@FeaturesOfInterest@ LIMIT 1","d":"ERR",
      "o":{"au_zero":"0","au_pending":"0","au_custom":"0","au_editor_B":"1","au_editor_all":"1","au_mixed":"1","au_sensor_A":"1","au_sensor_all":"1","au_obsmgr_A":"1","au_sq":"1","au_vs":"1","au_cs":"1"}},
     {"l":"W Location.gen_foi_id","sql":"UPDATE sensorthings.@Location@ SET gen_foi_id = (SELECT min(id) FROM sensorthings.@FeaturesOfInterest@ WHERE id <> coalesce(gen_foi_id, -1)) WHERE id = __L__","d":"0","o":{"au_editor_all":"1","au_sensor_all":"1"}},
     {"l":"W Location.name","sql":"UPDATE sensorthings.@Location@ SET name = name||'!' WHERE id = __L__","d":"0","o":{"au_editor_all":"1","au_sensor_all":"ERR"}},

     {"l":"R UserGrant table","sql":"SELECT count(*) FROM sensorthings.@UserGrant@","d":"ERR"},
     {"l":"R CustomPolicy table","sql":"SELECT count(*) FROM sensorthings.@CustomPolicy@","d":"ERR"},
     {"l":"R UserGrantNetwork table","sql":"SELECT count(*) FROM sensorthings.@UserGrantNetwork@","d":"ERR"},
     {"l":"R GrantMigrationReport table","sql":"SELECT count(*) FROM sensorthings.@GrantMigrationReport@","d":"ERR"},
     {"l":"R User table","sql":"SELECT count(*) FROM sensorthings.@User@","d":"ERR"},
     {"l":"W self-promote via User","sql":"UPDATE sensorthings.@User@ SET role = 'administrator' WHERE username = 'au_zero'","d":"ERR"},
     {"l":"W insert own grant","sql":"INSERT INTO sensorthings.@UserGrant@(user_id, role, all_networks) VALUES (1,'editor',true)","d":"ERR"},
     {"l":"W Commit update","sql":"UPDATE sensorthings.@Commit@ SET message = message WHERE id = 1","d":"ERR"}
    ]$j$::jsonb;

    EXECUTE 'SET LOCAL ROLE "user"';
    FOR t IN SELECT * FROM jsonb_array_elements(tests) LOOP
        FOREACH who IN ARRAY users LOOP
            PERFORM set_config('app.current_user_id', (ids ->> who), true);
            sql := replace(replace(replace(replace(replace(replace(t->>'sql','@','"'),
                       '__D1__', d1::text), '__D2__', d2::text), '__O1__', o1::text),
                       '__S__', sens::text), '__L__', loc::text);
            exp := coalesce(t->'o'->>who, t->>'d');
            exp := replace(replace(replace(replace(replace(replace(exp,
                '__NA_DS__', na_ds::text), '__NB_DS__', nb_ds::text), '__NA_OBS__', na_obs::text),
                '__NB_OBS__', nb_obs::text), '__ALL_DS__', all_ds::text), '__ALL_OBS__', all_obs::text);
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
