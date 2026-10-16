#!/usr/bin/env python3
"""Run grants_rls_audit.sql against a disposable database container.

    DB_CONTAINER=fx-database python3 run_grants_rls_audit.py

Picks grants_rls_audit_nonet.sql instead when the database has no
sensorthings."Network" table (a NETWORK=0 deployment).

Refuses to run without DB_CONTAINER: the audit is rolled back, but it must never
be pointed at a real database by accident.
"""
import os
import subprocess
import sys

db = os.getenv("DB_CONTAINER")
if not db:
    sys.exit("set DB_CONTAINER (e.g. fx-database); no default on purpose")

here = os.path.dirname(os.path.abspath(__file__))
has_network = subprocess.run(
    ["docker", "exec", db, "psql", "-U", "postgres", "-d", "istsos", "-tAc",
     "SELECT to_regclass('sensorthings.\"Network\"') IS NOT NULL"],
    capture_output=True, text=True,
).stdout.strip() == "t"
audit_file = "grants_rls_audit.sql" if has_network else "grants_rls_audit_nonet.sql"
print("audit file:", audit_file)
with open(os.path.join(here, audit_file)) as f:
    script = f.read()

r = subprocess.run(
    ["docker", "exec", "-i", db, "psql", "-U", "postgres", "-d", "istsos"],
    input=script, capture_output=True, text=True,
)
out = r.stdout + r.stderr
mismatches = [l for l in out.splitlines() if "MISMATCH" in l]
results = [l for l in out.splitlines() if "RESULT:" in l]
errors = [l for l in out.splitlines() if l.startswith("ERROR:") and "__undo__" not in l]
for l in mismatches + results:
    print(l.replace("NOTICE:  ", ""))
for l in errors:
    print(l)
ok = not mismatches and not errors and len(results) >= 2
print("AUDIT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
