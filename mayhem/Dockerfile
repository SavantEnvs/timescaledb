# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form, PREFERRED) — builds ON TOP of the org C/C++ base
# image (ghcr.io/savantenvs/base). The base already provides debian + clang/llvm +
# libFuzzer/afl++ + the identities + the build-contract ENV, so this only adds the
# per-commit build (built on top of the prebuilt base, rather than building the toolchain in-image).
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

# The org base, pinned to a fixed DATE-tagged base (YYYYMMDD; shared by all integrations
# minted against it). Use the current dated tag; pin by digest in production: ...base@sha256:<digest>.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); do NOT bake it as an ENV — an
# empty value breaks clang ("must be a non-negative decimal integer") both here and for
# any in-image rebuild. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# To change it for a build (e.g. ASan-only, or add MSan): --build-arg SANITIZER_FLAGS="...".
# Declare it WITHOUT a default (no '='): an undefaulted ARG lets the base ENV flow through to
# build.sh when not passed, and an explicit --build-arg overrides it. (An empty default — `=` —
# would instead shadow the base ENV and silently wipe the sanitizers.)
ARG SANITIZER_FLAGS
# Coverage (optional, off by default): instrument the TEST build to measure how much of the project
# the suite exercises — --build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping".
# Empty by default (no effect on the normal oracle build); build.sh appends it to the test build only.
ARG COVERAGE_FLAGS=
# Build parallelism (optional). build.sh falls back to nproc when unset: --build-arg MAYHEM_JOBS=8
ARG MAYHEM_JOBS=

# If mayhem/build.sh needs EXTRA apt packages, install them as root before the build
# (re-pin to SOURCE_DATE_EPOCH first for reproducibility — repro-sources-list.sh ships
# in the base):
#   USER root
#   RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
#       apt-get update && apt-get install -yq --no-install-recommends <pkgs> \
#    && rm -rf /var/lib/apt/lists/*
#   USER mayhem

# TimescaleDB is a PostgreSQL extension: it is compiled against PostgreSQL's server headers and its code
# only runs inside PostgreSQL's backend. PostgreSQL is therefore a build dependency, built ONCE here from
# the pinned release tarball into /opt/toolchains/deps/postgresql-<version>/ (SPEC 6.2 item 19), out of
# tree, uninstrumented, with -g -gdwarf-3 so backtraces show /opt/toolchains/deps/.../src paths:
#   src/                    the PostgreSQL source
#   bin/ include/ share/    the regular installation (pg_config, initdb, server headers, timezone data)
#   lib/libpgbackend.a      every object of the `postgres` executable, with main() renamed to
#                           postgres_main(), so mayhem/build.sh can link the backend into the fuzz targets
#   lib/libpgbackend.libs   the system libraries that link needs
#   lib/libpg{common,port}_srv.a   the two static libraries `postgres` itself links
# mayhem/build.sh never rebuilds PostgreSQL; it copies what must exist at run time into /mayhem, so no
# target loads anything from /opt/toolchains. (lib/ also holds PostgreSQL's own loadable modules, e.g.
# plpgsql.so: they are part of its installation and are only ever loaded from the copy that
# mayhem/build.sh makes under /mayhem/build-test for the functional tests.)
USER root
ARG PG_VER=18.6
ARG PG_SHA256=555610c24d53e4316da5b7d3fc25c279d96856d5e0e23ee308c328c5fa881d9f
RUN set -eux; d=/opt/toolchains/deps/postgresql-${PG_VER}; b=/tmp/pg-build; \
    mkdir -p "$d/src" "$b"; \
    curl -fsSL -o /tmp/pg.tar.bz2 https://ftp.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2; \
    echo "${PG_SHA256}  /tmp/pg.tar.bz2" | sha256sum -c -; \
    tar -xjf /tmp/pg.tar.bz2 --strip-components=1 -C "$d/src"; \
    cd "$b"; \
    "$d/src/configure" --prefix="$d" CC=clang CFLAGS="-O2 -fno-omit-frame-pointer -g -gdwarf-3" \
        --enable-cassert --with-openssl --without-icu --without-readline --without-zlib >/dev/null; \
    make -s -j"${MAYHEM_JOBS:-$(nproc)}" >/dev/null; \
    make -s install >/dev/null; \
    objs="$(cat src/backend/*/objfiles.txt src/timezone/objfiles.txt | tr ' ' '\n' | grep . | sort -u)"; \
    llvm-objcopy --redefine-sym main=postgres_main src/backend/main/main.o; \
    rm -f "$d/lib/libpgbackend.a"; ar rcs "$d/lib/libpgbackend.a" $objs; \
    cp src/common/libpgcommon_srv.a src/port/libpgport_srv.a "$d/lib/"; \
    rm -f src/backend/postgres; \
    make -n -C src/backend postgres | grep -e ' -o postgres$' | tr ' ' '\n' | grep -e '^-l' | tr '\n' ' ' > "$d/lib/libpgbackend.libs"; \
    test -s "$d/lib/libpgbackend.libs"; \
    cd /; rm -rf "$b" /tmp/pg.tar.bz2; chmod -R a+rX "$d"
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git
# history) is copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Anything a Dockerfile step materializes into the tree (downloaded fixtures, generated headers,
# vendored deps) MUST be committed or (re)created by build.sh: rlenv's patch grader runs
# `git clean -ffdX` before every graded build, so a gitignored, untracked file is gone by then and
# every honest patch scores zero (SPEC §6.2 item 16; verify-repo.sh checks it).
#
# OPTIONAL compile-cache pre-fill (SPEC §6.2 item 18). Bases minted with /opt/mayhem/ccache/prefill
# run the build under rlenv's pinned ccache, so the patch grader's first (otherwise cold) rebuild is
# warm — this is what keeps large C/C++ targets inside the build time limit. Older bases fall back to
# the plain build; a missing or stale pre-fill only costs a cold cache. Never enable ccache in
# build.sh or via ENV/PATH, and keep the compiler resolving by name (CC=clang) or nothing is cached.
RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

# Run the project's functional tests at build time IF the repo ships them (mayhem/test.sh is
# optional — omit it only when the repo has no tests meaningful for RL). A failing suite fails the
# image build, so the commit image is guaranteed to build AND pass its own tests.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
