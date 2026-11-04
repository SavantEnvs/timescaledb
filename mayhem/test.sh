#!/usr/bin/env bash
#
# mayhem/test.sh — functional check of the TimescaleDB extension that mayhem/build.sh built (build-test/pg).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


# TimescaleDB is an extension, so the check is: start a real PostgreSQL server from the normal-flags
# build in build-test/pg, load the extension, and compare query results against known answers. Every
# case is a SQL statement whose exact result is fixed by the data it generates; a pass needs the right value.
PG="$SRC/build-test/pg/bin"
for b in postgres initdb pg_ctl psql; do
  [ -x "$PG/$b" ] || { echo "missing $PG/$b (mayhem/build.sh builds it)" >&2; emit_ctrf "timescaledb-sql" 0 1; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/tstest.XXXXXX")"
DATA="$WORK/data"
cleanup() { "$PG/pg_ctl" -D "$DATA" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

"$PG/initdb" -D "$DATA" -A trust --no-locale -E UTF8 -N >/dev/null || { emit_ctrf "timescaledb-sql" 0 1; exit 1; }
"$PG/pg_ctl" -D "$DATA" -w -l "$WORK/server.log" -o "-c listen_addresses= -c unix_socket_directories=$WORK -c port=55432 \
  -c shared_preload_libraries=timescaledb -c timescaledb.telemetry_level=off -c max_worker_processes=16" start >/dev/null \
  || { cat "$WORK/server.log" >&2; emit_ctrf "timescaledb-sql" 0 1; exit 1; }

SQL() { "$PG/psql" -X -q -At -h "$WORK" -p 55432 -U "$(id -un)" -d postgres -v ON_ERROR_STOP=1 "$@" 2>&1; }

passed=0; failed=0
# check <name> <expected output> <sql>
check() {
  local got; got="$(SQL -c "$3")"
  if [ "$got" = "$2" ]; then passed=$((passed+1)); echo "ok   $1"
  else failed=$((failed+1)); echo "FAIL $1: expected [$2] got [$got]"; fi
}

SQL -c "create extension timescaledb" >/dev/null || { cat "$WORK/server.log" >&2; emit_ctrf "timescaledb-sql" 0 1; exit 1; }

check "extension loaded" "t" "select count(*) = 1 from pg_extension where extname = 'timescaledb'"

SQL >/dev/null <<'EOSQL'
create table m (ts timestamptz not null, dev int not null, temp float8, hits int8, flag bool, tag text, uid uuid);
select create_hypertable('m', 'ts', chunk_time_interval => interval '1 day');
insert into m
select timestamptz '2024-01-01 00:00:00+00' + (g || ' minutes')::interval,
       g % 4,
       g * 0.5,
       g * 3,
       g % 3 = 0,
       'tag' || (g % 10),
       ('00000000-0000-0000-0000-' || lpad(to_hex(g), 12, '0'))::uuid
from generate_series(0, 4319) g;
alter table m set (timescaledb.compress, timescaledb.compress_segmentby = 'dev', timescaledb.compress_orderby = 'ts');
EOSQL

AGG="select count(*), sum(temp), sum(hits), count(*) filter (where flag), count(distinct tag), min(uid::text), max(uid::text) from m"
EXPECT_AGG='4320|4664520|27987120|1440|10|00000000-0000-0000-0000-000000000000|00000000-0000-0000-0000-0000000010df'
check "hypertable has 3 daily chunks" "3" "select count(*) from show_chunks('m')"
check "aggregates before compression" "$EXPECT_AGG" "$AGG"
check "time_bucket count" "1440" "select count(*) from m where time_bucket('1 day', ts) = timestamptz '2024-01-02 00:00:00+00'"
check "first_last" "0|4319" "select first(hits, ts)/3, last(hits, ts)/3 from m"

SQL >/dev/null -c "select compress_chunk(c) from show_chunks('m') c"
check "all chunks compressed" "3" "select count(*) from timescaledb_information.chunks where hypertable_name = 'm' and is_compressed"
check "aggregates after compression (decompress round trip)" "$EXPECT_AGG" "$AGG"
check "compressed row values" "0|500|3000|f|tag0|00000000-0000-0000-0000-0000000003e8" \
  "select dev, temp, hits, flag, tag, uid from m where hits = 3000"
check "segmentby filter" "1080" "select count(*) from m where dev = 2"

SQL >/dev/null -c "select decompress_chunk(c) from show_chunks('m') c"
check "aggregates after decompression" "$EXPECT_AGG" "$AGG"

SQL >/dev/null <<'EOSQL'
create materialized view m_hourly with (timescaledb.continuous) as
select time_bucket('1 hour', ts) as b, dev, sum(hits) as h from m group by 1, 2 with no data;
call refresh_continuous_aggregate('m_hourly', null, null);
EOSQL
check "continuous aggregate" "288|27987120" "select count(*), sum(h) from m_hourly"

check "drop_chunks removes the two old chunks" "2" "select count(*) from drop_chunks('m', older_than => timestamptz '2024-01-03 00:00:00+00')"
check "rows left after drop_chunks" "1440" "select count(*) from m"

emit_ctrf "timescaledb-sql" "$passed" "$failed"
