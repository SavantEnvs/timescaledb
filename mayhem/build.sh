#!/usr/bin/env bash
#
# mayhem/build.sh — build TimescaleDB's decompression fuzz targets and its functional-test build.
#
# TimescaleDB is a PostgreSQL extension. The PostgreSQL it builds against and runs in is a prebuilt,
# uninstrumented dependency of the image (/opt/toolchains/deps/postgresql-<version>, see mayhem/Dockerfile);
# this script never rebuilds it and fetches nothing.
#   build-fuzz/   TimescaleDB with the sanitizers + SanCov and upstream's COMPRESSION_FUZZING entry point;
#                 the fuzz executable (PostgreSQL's backend + mayhem/fuzz_decompression.c + libFuzzer),
#                 its run-once twin, and what the catalog targets need at run time: PostgreSQL's timezone
#                 data and an archive of an initdb'ed data directory
#   build-test/   TimescaleDB with its normal flags, installed into a private copy of the PostgreSQL
#                 installation (build-test/pg), which mayhem/test.sh starts as a real server
# Both directories match upstream's /build* .gitignore entry, so `git clean -ffdX` removes them.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=/mayhem}"
cd "$SRC"

PG="$(ls -d /opt/toolchains/deps/postgresql-* 2>/dev/null | head -n 1)"
[ -n "$PG" ] && [ -x "$PG/bin/pg_config" ] && [ -f "$PG/lib/libpgbackend.a" ] \
  || { echo "the PostgreSQL dependency is missing (mayhem/Dockerfile builds it under /opt/toolchains/deps)" >&2; exit 1; }
TS_VERSION="$(sed -n 's/^version *= *//p' version.config)"
F="$SRC/build-fuzz"

# 1) TimescaleDB, sanitized, with SanCov and the in-tree fuzz entry point (ts_fuzz_compression), in
#    upstream's own fuzzing configuration (.github/workflows/libfuzzer.yaml: RelWithDebInfo, assertions on).
#    The sanitizer and libFuzzer runtimes live in the executable that loads the modules. The modules' one
#    call into the fuzzing engine is routed to the harness (see mayhem/fuzz_decompression.c).
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
MODULE_LDFLAGS="$SANITIZER_FLAGS -Wl,--wrap=LLVMFuzzerRunDriver"
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1 -DNDEBUG" \
  -DCMAKE_MODULE_LINKER_FLAGS="$MODULE_LDFLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$MODULE_LDFLAGS" \
  -DASSERTIONS=ON -DLINTER=OFF -DWARNINGS_AS_ERRORS=0 -DCOMPRESSION_FUZZING=1 \
  -DREGRESS_CHECKS=OFF -DTAP_CHECKS=OFF -DSEND_TELEMETRY_DEFAULT=NO -DPG_PATH="$PG/bin" >/dev/null
cmake --build build-fuzz -j"$MAYHEM_JOBS"
CORE_MODULE="$F/src/timescaledb-$TS_VERSION.so"
TSL_MODULE="$F/tsl/src/timescaledb-tsl-$TS_VERSION.so"
[ -f "$CORE_MODULE" ] && [ -f "$TSL_MODULE" ] || { echo "TimescaleDB modules not built ($CORE_MODULE, $TSL_MODULE)" >&2; exit 1; }

# 2) The fuzz executable and its run-once twin: the harness + PostgreSQL's backend objects.
mkdir -p "$F/exe"
HARNESS_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -I$PG/include/server \
  -DFUZZ_CORE_MODULE=\"$CORE_MODULE\" -DFUZZ_TSL_MODULE=\"$TSL_MODULE\" \
  -DFUZZ_PG_BIN=\"$F/pg/bin/postgres\" -DFUZZ_PGDATA_ARCHIVE=\"$F/pgdata.tar.gz\""
PG_LINK="-Wl,--whole-archive $PG/lib/libpgbackend.a -Wl,--no-whole-archive \
  $PG/lib/libpgcommon_srv.a $PG/lib/libpgport_srv.a -Wl,--export-dynamic $(cat "$PG/lib/libpgbackend.libs") -lz -ldl -lpthread -lm"
$CC $HARNESS_CFLAGS -c mayhem/fuzz_decompression.c -o "$F/exe/fuzz_decompression.o"
$CC $HARNESS_CFLAGS -DFUZZ_STANDALONE -c mayhem/fuzz_decompression.c -o "$F/exe/fuzz_decompression-standalone.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$F/exe/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$F/exe/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$F/exe/fuzz_decompression.o" "$F/exe/lsan_off.o" \
    $PG_LINK -o "$F/exe/fuzz_decompression"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$F/exe/fuzz_decompression-standalone.o" "$F/exe/standalone_main.o" \
    "$F/exe/lsan_off.o" $PG_LINK -o "$F/exe/fuzz_decompression-standalone"

# One hard link per target: the executable's name selects the algorithm, the type and the mode.
for t in gorilla_float8 deltadelta_int8 aic_int8 aic_int4 aic_int2 bool_bool uuid_uuid \
         array_text dictionary_text dictionary_uuid; do
  for mode in bulk rowbyrow; do
    ln -f "$F/exe/fuzz_decompression" "$SRC/fuzz_${t}_${mode}"
    ln -f "$F/exe/fuzz_decompression-standalone" "$SRC/fuzz_${t}_${mode}-standalone"
  done
done

# 3) What the catalog targets (array, dictionary) need at run time, kept under /mayhem so that no target
#    reads /opt/toolchains: PostgreSQL's timezone data, which the backend locates relative to FUZZ_PG_BIN,
#    and an initdb'ed data directory, packed into ONE archive that each process unpacks into its own
#    scratch directory. Start-up is paid by every process, so the directory is kept small and cheap to
#    start on: --wal-segsize=1 (the WAL segment is its largest file and the fuzz backend never fills one),
#    the two template databases removed (the backend only ever connects to "postgres"; 1, 4 and 5 are
#    the fixed OIDs of template1, template0 and postgres), and one backend start at build time, which
#    leaves the catalog cache files (pg_internal.init) a later start would otherwise have to compute.
#    fsync is off and only FATAL errors are logged, since upstream's targets catch and discard the errors
#    that corrupt input raises. Dynamic shared memory is kept in the data directory rather than in
#    /dev/shm, so a target needs nothing outside its own scratch directory but one System V segment.
rm -rf "$F/pg" "$F/pgdata"
mkdir -p "$F/pg/bin" "$F/pg/share"
cp -a "$PG/share/timezone" "$PG/share/timezonesets" "$F/pg/share/"
"$PG/bin/initdb" -D "$F/pgdata" -A trust --no-locale -E UTF8 -N --wal-segsize=1 >/dev/null
cat > "$F/pgdata/postgresql.conf" <<'CONF'
shared_buffers = 16MB
max_connections = 8
fsync = off
timezone = 'GMT'
log_timezone = 'GMT'
log_min_messages = fatal
dynamic_shared_memory_type = mmap
CONF
[ -d "$F/pgdata/base/5" ] || { echo "unexpected data directory layout: no base/5 (the postgres database)" >&2; exit 1; }
rm -rf "$F/pgdata/base/1" "$F/pgdata/base/4"
echo "select count(*) from pg_type" | "$PG/bin/postgres" --single -D "$F/pgdata" postgres >/dev/null
[ -f "$F/pgdata/base/5/pg_internal.init" ] || { echo "the data directory was not started (no pg_internal.init)" >&2; exit 1; }
tar --format=ustar -C "$F/pgdata" -czf "$F/pgdata.tar.gz" .
chmod a+r "$F/pgdata.tar.gz"
rm -rf "$F/pgdata"

# 4) TimescaleDB with its normal flags, installed into a private copy of the PostgreSQL installation,
#    for the functional tests (mayhem/test.sh only runs them).
if [ ! -x build-test/pg/bin/postgres ]; then
  rm -rf build-test/pg
  mkdir -p build-test/pg
  cp -a "$PG/bin" "$PG/include" "$PG/lib" "$PG/share" build-test/pg/
  rm -f build-test/pg/lib/libpgbackend.*
fi
cmake -S . -B build-test -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DASSERTIONS=OFF -DLINTER=OFF -DWARNINGS_AS_ERRORS=0 \
  -DREGRESS_CHECKS=OFF -DTAP_CHECKS=OFF -DSEND_TELEMETRY_DEFAULT=NO -DPG_PATH="$SRC/build-test/pg/bin" >/dev/null
cmake --build build-test -j"$MAYHEM_JOBS"
cmake --install build-test >/dev/null
