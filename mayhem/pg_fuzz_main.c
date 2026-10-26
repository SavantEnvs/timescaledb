/*
 * Process entry for the TimescaleDB decompression fuzz targets.
 *
 * The in-tree fuzz entry point (ts_fuzz_compression, tsl/test/src/compression_sql_test.c) is a SQL
 * function that must run inside a PostgreSQL backend, and it hard-codes its libFuzzer argv. This file
 * makes one executable that IS that backend: it is linked in place of PostgreSQL's own main() (via
 * -Wl,--wrap=main), boots a single-user backend on a private copy of a pre-initialised data directory
 * (unpacked per process from the archive mayhem/build.sh builds),
 * and feeds it `select fuzz(...)`. The libFuzzer driver the SQL function calls is handed the REAL
 * command line (corpus dirs, -runs=, -max_total_time=, ...) instead of upstream's fixed one.
 *
 * Which algorithm/type/mode is fuzzed is chosen by the executable's own name
 * (fuzz_<algo>_<type>_<bulk|rowbyrow>[-standalone]). A "-standalone" name runs each file argument once
 * through the target with no libFuzzer runtime, for reproducing a crash.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAYHEM_PG_BIN
#error "MAYHEM_PG_BIN (absolute path of the installed postgres) must be defined"
#endif
#ifndef MAYHEM_PG_TAR
#error "MAYHEM_PG_TAR (absolute path of the data directory archive) must be defined"
#endif

extern int __real_main(int argc, char **argv);

typedef int (*fuzz_cb)(const uint8_t *, size_t);
extern int real_LLVMFuzzerRunDriver(int *argc, char ***argv, fuzz_cb cb);

static int saved_argc;
static char **saved_argv;
static int standalone_mode;
static char datadir[4096];
static char origcwd[4096];
static char backend_cwd[4096];

/*
 * libFuzzer ends a fuzzing run with exit(0), so the backend's directory has to be restored from an atexit
 * hook; it also RETURNS (e.g. for `-help=1`, which Mayhem runs to recognise a libFuzzer target), so the
 * return path restores it too, or the backend's shutdown checkpoint fails on its relative paths.
 */
static void
back_to_backend_dir(void)
{
	if (backend_cwd[0] != '\0' && chdir(backend_cwd) != 0)
		perror("chdir");
}

static fuzz_cb upstream_cb;

/*
 * PostgreSQL's StringInfo buffers are always NUL-terminated just past len, and pq_getmsgstring() relies
 * on it. libFuzzer's input buffer is not, so the target would trip ASan with a strlen() read past the end
 * of the input, which cannot happen in the server. Hand it a copy with the terminator PostgreSQL guarantees.
 */
static int
terminated_target(const uint8_t *data, size_t size)
{
	uint8_t *copy = malloc(size + 1);
	memcpy(copy, data, size);
	copy[size] = '\0';
	int res = upstream_cb(copy, size);
	free(copy);
	return res;
}

/* Called by ts_fuzz_compression() inside the backend instead of the libFuzzer runtime's version. */
int
LLVMFuzzerRunDriver(int *argc, char ***argv, fuzz_cb cb)
{
	(void) argc;
	(void) argv;

	/* the backend chdir()ed into the data directory; corpus paths and crash artifacts are relative to the caller */
	if (getcwd(backend_cwd, sizeof(backend_cwd)) == NULL)
		backend_cwd[0] = '\0';
	atexit(back_to_backend_dir);
	if (origcwd[0] != '\0' && chdir(origcwd) != 0)
		perror("chdir");
	upstream_cb = cb;
	cb = terminated_target;
	if (!standalone_mode)
	{
		int res = real_LLVMFuzzerRunDriver(&saved_argc, &saved_argv, cb);
		back_to_backend_dir();
		return res;
	}

	int rc = 0;
	for (int i = 1; i < saved_argc; i++)
	{
		if (saved_argv[i][0] == '-')
			continue;
		FILE *f = fopen(saved_argv[i], "rb");
		if (f == NULL)
		{
			fprintf(stderr, "cannot open %s: %s\n", saved_argv[i], strerror(errno));
			rc = 1;
			continue;
		}
		size_t cap = 1 << 16, len = 0;
		uint8_t *buf = malloc(cap);
		size_t n;
		while ((n = fread(buf + len, 1, cap - len, f)) > 0)
		{
			len += n;
			if (len == cap)
				buf = realloc(buf, cap *= 2);
		}
		fclose(f);
		(void) cb(buf, len);
		free(buf);
	}
	back_to_backend_dir();
	return rc;
}

static void
remove_datadir(void)
{
	if (datadir[0] != '\0')
	{
		char cmd[4200];
		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", datadir);
		if (system(cmd) != 0)
			;
	}
}

struct target
{
	const char *name;
	const char *algo;
	const char *type;
	int bulk;
};

#define T(a, t, b) { "fuzz_" #a "_" #t "_" #b, #a, #t, !strcmp(#b, "bulk") }
static const struct target targets[] = {
	T(gorilla, float8, bulk),	  T(gorilla, float8, rowbyrow),
	T(deltadelta, int8, bulk),	  T(deltadelta, int8, rowbyrow),
	T(aic, int8, bulk),			  T(aic, int8, rowbyrow),
	T(aic, int4, bulk),			  T(aic, int2, bulk),
	T(bool, bool, bulk),		  T(bool, bool, rowbyrow),
	T(array, text, bulk),		  T(array, text, rowbyrow),
	T(dictionary, text, bulk),	  T(dictionary, text, rowbyrow),
	T(dictionary, uuid, bulk),	  T(uuid, uuid, bulk),
	T(uuid, uuid, rowbyrow),
};


int
__wrap_main(int argc, char **argv)
{
	if (getenv("MAYHEM_PG_PASSTHROUGH") != NULL)
		return __real_main(argc, argv);

	char *exe = strdup(argv[0]);
	char *base = basename(exe);
	size_t blen = strlen(base);
	if (blen > 11 && strcmp(base + blen - 11, "-standalone") == 0)
	{
		standalone_mode = 1;
		base[blen - 11] = '\0';
	}
	const struct target *tgt = NULL;
	for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++)
		if (strcmp(targets[i].name, base) == 0)
			tgt = &targets[i];
	if (tgt == NULL)
	{
		fprintf(stderr, "unknown fuzz target '%s' (executable name selects the target)\n", base);
		return 2;
	}

	if (getcwd(origcwd, sizeof(origcwd)) == NULL)
		origcwd[0] = '\0';
	saved_argc = argc;
	saved_argv = calloc(argc + 1, sizeof(char *));
	for (int i = 0; i < argc; i++)
		saved_argv[i] = strdup(argv[i]);

	const char *tmp = getenv("TMPDIR");
	snprintf(datadir, sizeof(datadir), "%s/tsfuzz.XXXXXX", tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
	if (mkdtemp(datadir) == NULL)
	{
		perror("mkdtemp");
		return 2;
	}
	atexit(remove_datadir);
	{
		char cmd[8300];
		/*
		 * Unpack the template archive mayhem/build.sh produced, rather than copying the template
		 * directory: one sequential read instead of ~1000 small ones (Mayhem materialises the image
		 * lazily and charges per file — a per-file copy did not finish inside the per-exec timeout;
		 * compressed, the 32MB data directory is under 5MB to read),
		 * and the archive still carries initdb's EMPTY directories, which the backend requires and
		 * which Mayhem's filesystem drops. mkdtemp() already made the directory 0700 and the archive
		 * carries initdb's own modes, so no recursive chmod is needed.
		 */
		snprintf(cmd, sizeof(cmd), "tar -xpzf '%s' -C '%s'", MAYHEM_PG_TAR, datadir);
		if (system(cmd) != 0)
		{
			fprintf(stderr, "cannot unpack the data directory template\n");
			return 2;
		}
	}
	{
		/* a data directory with no PG_VERSION cannot boot; say so here rather than inside the backend */
		char probe[4200];
		snprintf(probe, sizeof(probe), "%s/PG_VERSION", datadir);
		if (access(probe, R_OK) != 0)
		{
			fprintf(stderr, "the unpacked data directory is unusable (no PG_VERSION in %s)\n", datadir);
			return 2;
		}
	}

	/* PostgreSQL refuses to run as root, and the fuzzing service may start targets as root. */
	if (geteuid() == 0)
	{
		char cmd[4200];
		snprintf(cmd, sizeof(cmd), "chown -R 2000:2000 '%s'", datadir);
		(void) !system(cmd);
		/* the unprivileged backend must still read the corpus directories and add to them */
		for (int i = 1; i < argc; i++)
			if (argv[i][0] != '-')
			{
				snprintf(cmd, sizeof(cmd), "chmod -R a+rwX '%s' 2>/dev/null", argv[i]);
				(void) !system(cmd);
			}
		if (setgroups(0, NULL) != 0 || setgid(2000) != 0 || setuid(2000) != 0)
		{
			fprintf(stderr, "cannot drop root privileges\n");
			return 2;
		}
	}

	char sql[256];
	int sqllen = snprintf(sql, sizeof(sql), "select fuzz('%s', '%s', %s, 0)\n", tgt->algo, tgt->type,
						  tgt->bulk ? "true" : "false");
	int fd = memfd_create("fuzz-sql", 0);
	if (fd < 0 || write(fd, sql, sqllen) != sqllen || lseek(fd, 0, SEEK_SET) < 0 ||
		dup2(fd, 0) < 0)
	{
		perror("stdin");
		return 2;
	}

	char *pg_argv[] = { (char *) MAYHEM_PG_BIN,
						"--single",
						"-F",
						"-D",
						datadir,
						"-c",
						"shared_preload_libraries=timescaledb",
						"-c",
						"timescaledb.telemetry_level=off",
						"-c",
						"shared_buffers=16MB",
						"postgres",
						NULL };
	return __real_main((int) (sizeof(pg_argv) / sizeof(pg_argv[0])) - 1, pg_argv);
}
