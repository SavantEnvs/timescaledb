#!/usr/bin/env bash
#
# mayhem/build.sh — build TimescaleDB's decompression fuzz targets and its functional-test build.
#
# TimescaleDB is a PostgreSQL extension, so the fuzzed code only runs inside a PostgreSQL backend:
#   build-pg/        PostgreSQL 18 (pinned tarball baked into the image under /opt/pg), built once, plain flags
#   build-fuzz/      TimescaleDB with ASan+UBSan+SanCov and the in-tree COMPRESSION_FUZZING entry point,
#                    installed into its own copy of the PostgreSQL install (build-fuzz/pg)
#   build-test/      TimescaleDB with its normal flags, in another copy of the install (build-test/pg),
#                    which mayhem/test.sh starts as a real server
# The fuzz executables (/mayhem/fuzz_<algo>_<type>_<bulk|rowbyrow>) are PostgreSQL's backend re-linked
# with mayhem/pg_fuzz_main.c as its entry point; see that file. All build dirs match upstream's /build*
# gitignore entry, so `git clean -ffdX` removes them.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=/mayhem}"
cd "$SRC"

PG_VERSION=18.6
PG_TARBALL="/opt/pg/postgresql-$PG_VERSION.tar.bz2"
TS_VERSION="$(sed -n 's/^version *= *//p' version.config)"
TS_MODULE="timescaledb-tsl-$TS_VERSION"
[ -f "$PG_TARBALL" ] || { echo "missing $PG_TARBALL (baked into the image by mayhem/Dockerfile)" >&2; exit 1; }

# The extension modules are the ones carrying coverage and sanitizers; the sanitizer runtimes and the
# libFuzzer runtime live in the executable that loads them, so they are not linked into the modules.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"

# 1) PostgreSQL, once (assertions + memory-context checking on, as upstream's own fuzzing job does).
if [ ! -x build-pg/install/bin/postgres ]; then
  mkdir -p build-pg/src build-pg/obj
  tar -xjf "$PG_TARBALL" -C build-pg/src --strip-components=1
  (cd build-pg/obj && ../src/configure --prefix="$SRC/build-pg/install" CC="$CC" \
      CFLAGS="-O1 -fno-omit-frame-pointer -g -gdwarf-3" --enable-cassert \
      --with-openssl --without-icu --without-readline --without-zlib >/dev/null)
  make -C build-pg/obj -j"$MAYHEM_JOBS" -s
  make -C build-pg/obj -s install
  make -C build-pg/obj/contrib/postgres_fdw -s install >/dev/null 2>&1 || true
fi

copy_pg() { # <dest>: a private copy of the PostgreSQL install for one TimescaleDB flavour
  [ -x "$1/bin/postgres" ] || { rm -rf "$1"; mkdir -p "$(dirname "$1")"; cp -a build-pg/install "$1"; }
}

# CMake wipes its cache when the compiler's resolved path differs from the previous configure (the image
# build resolves CC through the ccache pre-fill's PATH, a later re-run does not), and then fails to find
# pg_config; start every configure from a fresh cache instead.
rm -f build-fuzz/CMakeCache.txt build-test/CMakeCache.txt

# 2) TimescaleDB, sanitized + fuzz entry point
copy_pg build-fuzz/pg
cmake -S . -B build-fuzz -G Ninja -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1 -DNDEBUG" \
  -DCMAKE_MODULE_LINKER_FLAGS="$SANITIZER_FLAGS" \
  -DASSERTIONS=ON -DLINTER=OFF -DWARNINGS_AS_ERRORS=0 -DCOMPRESSION_FUZZING=1 \
  -DREGRESS_CHECKS=OFF -DTAP_CHECKS=OFF -DSEND_TELEMETRY_DEFAULT=NO -DPG_PATH="$SRC/build-fuzz/pg/bin" >/dev/null
cmake --build build-fuzz -j"$MAYHEM_JOBS"
cmake --install build-fuzz >/dev/null

# 3) The fuzz executable: PostgreSQL's backend objects + the harness entry + the libFuzzer runtime.
FUZZ_RT="$(clang -print-file-name=libclang_rt.fuzzer_no_main-x86_64.a)"
[ -f "$FUZZ_RT" ] || { echo "libFuzzer no_main runtime not found ($FUZZ_RT)" >&2; exit 1; }
mkdir -p build-fuzz/exe
# the harness supplies LLVMFuzzerRunDriver (to forward the real command line); the runtime's own is renamed
llvm-objcopy --redefine-sym LLVMFuzzerRunDriver=real_LLVMFuzzerRunDriver "$FUZZ_RT" build-fuzz/exe/libfuzzer_no_main.a
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -DMAYHEM_PG_BIN="\"$SRC/build-fuzz/pg/bin/postgres\"" \
    -DMAYHEM_PG_TAR="\"$SRC/build-fuzz/pgdata-template.tgz\"" -c mayhem/pg_fuzz_main.c -o build-fuzz/exe/pg_fuzz_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build-fuzz/exe/lsan_off.o
rm -f build-pg/obj/src/backend/postgres
make -C build-pg/obj/src/backend -s postgres \
  LDFLAGS_EX="-Wl,--wrap=main $SANITIZER_FLAGS $SRC/build-fuzz/exe/pg_fuzz_main.o $SRC/build-fuzz/exe/lsan_off.o $SRC/build-fuzz/exe/libfuzzer_no_main.a -lstdc++"
cp build-pg/obj/src/backend/postgres build-fuzz/exe/fuzz_exe
rm -f build-pg/obj/src/backend/postgres
make -C build-pg/obj/src/backend -s postgres   # restore the stock backend

# 4) Data directory template (initdb + extension + the fuzz SQL function), unpacked per process at runtime.
# --wal-segsize=1 keeps the template at ~25MB instead of ~41MB: the 16MB WAL segment is the single largest
# file in it and the fuzz backend never fills one.
if [ ! -f build-fuzz/pgdata-template/.mayhem-ready ]; then
  rm -rf build-fuzz/pgdata-template
  build-fuzz/pg/bin/initdb -D build-fuzz/pgdata-template -A trust --no-locale -E UTF8 -N \
      --wal-segsize=1 >/dev/null
  cat > build-fuzz/exe/init.sql <<SQL
create extension timescaledb
create function fuzz(algo cstring, pgtype regtype, bulk bool, runs int) returns int as '$TS_MODULE', 'ts_fuzz_compression' language c
SQL
  PGBIN="$SRC/build-fuzz/pg/bin/postgres"
  MAYHEM_PG_PASSTHROUGH=1 bash -c 'exec -a "$0" "$@"' "$PGBIN" build-fuzz/exe/fuzz_exe --single -F \
      -D build-fuzz/pgdata-template -c shared_preload_libraries=timescaledb \
      -c timescaledb.telemetry_level=off postgres < build-fuzz/exe/init.sql
  touch build-fuzz/pgdata-template/.mayhem-ready
fi

# Pack the template into ONE archive, which is what a fuzz process unpacks at startup.
#
# Two reasons, both learned from Mayhem runs that never reached libFuzzer:
#  * SPEED. Mayhem materialises the image lazily, at a per-file cost orders of magnitude above a local
#    disk. Copying the template file by file (~1000 of them) did not finish inside the per-exec timeout,
#    while reading one compressed file sequentially does (32MB of data directory -> under 5MB to read).
#  * COMPLETENESS. initdb leaves a dozen directories EMPTY (pg_notify, pg_replslot, pg_logical/snapshots,
#    ...) and the backend refuses to start without them ("FATAL: could not open directory"). Mayhem's
#    filesystem drops empty directories; inside an archive they cannot be lost.
# The archive keeps initdb's own modes (0700/0600), so unpacking yields a data directory PostgreSQL
# accepts without a recursive chmod. Only the archive itself has to be world-readable.
tar -czf build-fuzz/pgdata-template.tgz -C build-fuzz/pgdata-template .
chmod a+r build-fuzz/pgdata-template.tgz

# One hard link per target name (the name selects the target); each also gets a -standalone reproducer.
for t in gorilla_float8_bulk gorilla_float8_rowbyrow deltadelta_int8_bulk deltadelta_int8_rowbyrow \
         aic_int8_bulk aic_int8_rowbyrow aic_int4_bulk aic_int2_bulk bool_bool_bulk bool_bool_rowbyrow \
         array_text_bulk array_text_rowbyrow dictionary_text_bulk dictionary_text_rowbyrow \
         dictionary_uuid_bulk uuid_uuid_bulk uuid_uuid_rowbyrow; do
  ln -f build-fuzz/exe/fuzz_exe "/mayhem/fuzz_$t"
  ln -f build-fuzz/exe/fuzz_exe "/mayhem/fuzz_$t-standalone"
done

# 5) TimescaleDB with its normal flags, for the functional tests (mayhem/test.sh only runs them).
copy_pg build-test/pg
cmake -S . -B build-test -G Ninja -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DASSERTIONS=OFF -DLINTER=OFF -DWARNINGS_AS_ERRORS=0 \
  -DREGRESS_CHECKS=OFF -DTAP_CHECKS=OFF -DSEND_TELEMETRY_DEFAULT=NO -DPG_PATH="$SRC/build-test/pg/bin" >/dev/null
cmake --build build-test -j"$MAYHEM_JOBS"
cmake --install build-test >/dev/null
