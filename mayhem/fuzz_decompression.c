/*
 * libFuzzer harness for TimescaleDB's decompression fuzz targets.
 *
 * Upstream fuzzes decompression of every compression algorithm with the SQL function
 * ts_fuzz_compression(algo, type, bulk, runs) (tsl/test/src/compression_sql_test.c, built with
 * -DCOMPRESSION_FUZZING=1; .github/workflows/libfuzzer.yaml runs the 20 algo/type/mode combinations).
 * That function picks the per-combination target and hands it to libFuzzer's LLVMFuzzerRunDriver() with a
 * fixed command line, from inside a PostgreSQL server.
 *
 * Here the same code runs as an ordinary libFuzzer executable: PostgreSQL's backend is linked in as a
 * library, the TimescaleDB modules that mayhem/build.sh built are loaded, and ts_fuzz_compression() is
 * called once at start-up. The modules are linked with -Wl,--wrap=LLVMFuzzerRunDriver, so that one call
 * into the fuzzing engine arrives in __wrap_LLVMFuzzerRunDriver() below, which only records the target
 * upstream selected and the memory context it created. LLVMFuzzerTestOneInput() then calls that target
 * for each input. Nothing of TimescaleDB is replaced: target selection, error handling (PG_TRY) and the
 * per-input memory context reset are upstream's.
 *
 * Which combination an executable fuzzes is given by its name, fuzz_<algo>_<type>_<bulk|rowbyrow>
 * (a trailing "-standalone" is ignored: the reproducers are the same code with a run-once main()).
 *
 * The array and dictionary algorithms store their element type BY NAME in the compressed data and look
 * it up in the system catalogs (binary_string_get_type() -> LookupExplicitNamespace()), so those targets
 * need a database: they start a single-user backend, the way `postgres --single` does, on a private
 * copy of an initdb'ed data directory unpacked from the archive mayhem/build.sh made. The other
 * algorithms (gorilla, deltadelta, aic, bool, uuid) never touch the catalogs and need no database.
 *
 * State kept across inputs, on purpose: the loaded modules, upstream's "fuzzing" memory context (reset by
 * upstream's target before every input) and, for the catalog targets, the backend with its one open
 * transaction and its catalog caches. A lookup of a name from the input adds a (negative) cache entry,
 * so the caches are reset every CATCACHE_RESET_INPUTS inputs to bound the process's memory.
 *
 * The backend opens its files by paths relative to its data directory, so it has to run with that
 * directory as the working directory. The process as a whole must not: the fuzzing engine and whatever
 * drives it resolve their own relative paths (corpus, logs, reports) against the directory the target
 * was started in. The working directory is therefore the data directory only while the backend code
 * runs -- during start-up, inside each input, and in the backend's exit hook -- and the original one
 * at all other times.
 *
 * The backend is started by the first input, not in LLVMFuzzerInitialize(): a failure there is then a crash
 * libFuzzer reports, with PostgreSQL's message, instead of a process that ends before it fuzzes.
 */
#include <postgres.h>

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/file.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <access/xact.h>
#include <access/xlog.h>
#include <catalog/pg_type_d.h>
#include <fmgr.h>
#include <libpq/pqsignal.h>
#include <miscadmin.h>
#include <postmaster/postmaster.h>
#include <storage/fd.h>
#include <storage/ipc.h>
#include <storage/pg_shmem.h>
#include <storage/proc.h>
#include <tcop/tcopprot.h>
#include <utils/catcache.h>
#include <utils/elog.h>
#include <utils/guc.h>
#include <utils/memutils.h>
#include <utils/timeout.h>
#include <utils/timestamp.h>

#ifndef FUZZ_CORE_MODULE
#error "FUZZ_CORE_MODULE (absolute path of the built timescaledb-<version>.so) must be defined"
#endif
#ifndef FUZZ_TSL_MODULE
#error "FUZZ_TSL_MODULE (absolute path of the built timescaledb-tsl-<version>.so) must be defined"
#endif
#ifndef FUZZ_PG_BIN
#error "FUZZ_PG_BIN (where PostgreSQL finds itself; its share/ directory is located relative to it) must be defined"
#endif
#ifndef FUZZ_PGDATA_ARCHIVE
#error "FUZZ_PGDATA_ARCHIVE (absolute path of the data directory archive) must be defined"
#endif

extern const char *progname; /* PostgreSQL's src/backend/main/main.c */

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef int (*fuzz_target)(const uint8_t *, size_t);
int __wrap_LLVMFuzzerRunDriver(int *argc, char ***argv, fuzz_target target);

struct combination
{
	const char *name;
	const char *algo;
	Oid type;
	bool bulk;
	bool needs_catalog;
};

/* the combinations of APPLY_FOR_TYPES in tsl/test/src/compression_sql_test.c */
#define BOTH(algo, type, oid, catalog)                                                             \
	{ "fuzz_" algo "_" type "_bulk", algo, oid, true, catalog },                                   \
	{ "fuzz_" algo "_" type "_rowbyrow", algo, oid, false, catalog }
static const struct combination combinations[] = {
	BOTH("gorilla", "float8", FLOAT8OID, false),  BOTH("deltadelta", "int8", INT8OID, false),
	BOTH("aic", "int8", INT8OID, false),		  BOTH("aic", "int4", INT4OID, false),
	BOTH("aic", "int2", INT2OID, false),		  BOTH("bool", "bool", BOOLOID, false),
	BOTH("uuid", "uuid", UUIDOID, false),		  BOTH("array", "text", TEXTOID, true),
	BOTH("dictionary", "text", TEXTOID, true),	  BOTH("dictionary", "uuid", UUIDOID, true),
};

#define CATCACHE_RESET_INPUTS 50000

static fuzz_target upstream_target;
static MemoryContext upstream_context;
static char datadir[MAXPGPATH];
static int datadir_fd = -1; /* the backend's working directory (catalog targets only) */
static int startdir_fd = -1; /* the working directory the process was started in */

/*
 * A failure to prepare the scratch data directory (a directory that cannot be used, an archive that
 * cannot be unpacked) is not allowed to end the process: a fuzzing campaign whose target exits before
 * its first input only reports that it "did not run", with no hint why. It is remembered instead, and
 * the third input crashes the target with the full cause on stderr, which ends up in the defect report.
 * A PostgreSQL FATAL error during start-up ends in exit(); startup_exit_hook() turns that into an abort()
 * that carries what PostgreSQL said, from the stack that called exit().
 */
static bool backend_pending; /* the first input starts the backend */
static bool startup_armed;
static bool startup_failed;
static char startup_error[4096];

static void
startup_note(const char *a, const char *b)
{
	size_t used = strlen(startup_error);

	if (used < sizeof(startup_error))
		snprintf(startup_error + used, sizeof(startup_error) - used, "%s%s", a, b);
}

/* remember a failed step; returns false so that callers can `return failed(...)` */
static bool
failed(const char *what, const char *detail)
{
	fprintf(stderr, "fuzz_decompression: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
	startup_note(what, detail ? ": " : "");
	startup_note(detail ? detail : "", "\n");
	startup_failed = true;
	return false;
}

static void
setup_failed(const char *what, const char *detail)
{
	failed(what, detail);
	exit(2);
}

static emit_log_hook_type previous_emit_log_hook;

static void
startup_log(ErrorData *edata)
{
	if (startup_armed && edata->elevel >= WARNING)
	{
		startup_note("postgres: ", edata->message ? edata->message : "(no message)");
		startup_note(edata->detail != NULL ? " / " : "", edata->detail != NULL ? edata->detail : "");
		startup_note("\n", "");
	}
	if (previous_emit_log_hook != NULL)
		previous_emit_log_hook(edata);
}

static void
startup_exit_hook(void)
{
	if (startup_armed)
	{
		fprintf(stderr, "fuzz_decompression: the process was about to exit during start-up:\n%s", startup_error);
		abort();
	}
}

/* ts_fuzz_compression()'s call into the fuzzing engine: keep what upstream chose, run nothing. */
int
__wrap_LLVMFuzzerRunDriver(int *argc, char ***argv, fuzz_target target)
{
	(void) argc;
	(void) argv;
	upstream_target = target;
	upstream_context = CurrentMemoryContext; /* the "fuzzing" context ts_fuzz_compression() made */
	return 0;
}

/* ---- the data directory of the catalog targets ---- */

static bool
mkdir_checked(const char *path)
{
	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		return failed(path, strerror(errno));
	return true;
}

static bool
read_checked(gzFile in, void *buf, unsigned len)
{
	if (gzread(in, buf, len) != (int) len)
		return failed("truncated data directory archive", FUZZ_PGDATA_ARCHIVE);
	return true;
}

/*
 * Unpack the ustar archive of the initdb'ed data directory into `dir`. One archive rather than a
 * directory to copy because it is a single sequential read, and because initdb leaves a dozen
 * directories empty (pg_notify, pg_replslot, ...) that the backend refuses to start without and that
 * do not survive every way an image gets unpacked.
 */
static bool
unpack_datadir(const char *dir)
{
	gzFile in = gzopen(FUZZ_PGDATA_ARCHIVE, "rb");
	char header[512];
	static char block[1 << 16];

	if (in == NULL)
		return failed("cannot open the data directory archive", FUZZ_PGDATA_ARCHIVE);
	for (;;)
	{
		char name[256];
		char path[MAXPGPATH + 300];
		unsigned long size;

		if (!read_checked(in, header, sizeof(header)))
			goto bad;
		if (header[0] == '\0')
			break; /* end-of-archive marker */
		/* ustar: name[100] at 0, size[12] (octal) at 124, typeflag at 156, prefix[155] at 345 */
		if (header[345] != '\0')
			snprintf(name, sizeof(name), "%.155s/%.100s", header + 345, header);
		else
			snprintf(name, sizeof(name), "%.100s", header);
		if (name[0] == '/' || strstr(name, "..") != NULL)
		{
			failed("unexpected name in the data directory archive", name);
			goto bad;
		}
		snprintf(path, sizeof(path), "%s/%s", dir, name);
		size = strtoul(header + 124, NULL, 8);

		if (header[156] == '5')
		{
			if (!mkdir_checked(path))
				goto bad;
		}
		else if (header[156] == '0' || header[156] == '\0')
		{
			int out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
			ssize_t written;
			unsigned long left = size;

			if (out < 0)
			{
				failed(path, strerror(errno));
				goto bad;
			}
			while (left > 0)
			{
				unsigned n = left < sizeof(block) ? (unsigned) left : (unsigned) sizeof(block);

				if (!read_checked(in, block, n))
				{
					close(out);
					goto bad;
				}
				written = write(out, block, n);
				if (written != (ssize_t) n)
				{
					failed(path, written < 0 ? strerror(errno) : "short write (scratch directory full?)");
					close(out);
					goto bad;
				}
				left -= n;
			}
			close(out);
			if (size % 512 != 0 && !read_checked(in, block, 512 - size % 512))
				goto bad;
		}
		else
		{
			failed("unexpected entry type in the data directory archive", name);
			goto bad;
		}
	}
	gzclose(in);
	return true;
bad:
	gzclose(in);
	return false;
}

static void
remove_tree(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;

	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL)
	{
		char child[MAXPGPATH + 300];
		struct stat st;

		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
		if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
			remove_tree(child);
		else
			unlink(child);
	}
	closedir(d);
	rmdir(path);
}

static void
enter_datadir(void)
{
	if (datadir_fd >= 0 && fchdir(datadir_fd) != 0)
	{
		perror("fuzz_decompression: cannot enter the data directory");
		abort();
	}
}

static void
leave_datadir(void)
{
	if (startdir_fd >= 0 && fchdir(startdir_fd) != 0)
	{
		perror("fuzz_decompression: cannot return to the start directory");
		abort();
	}
}

/* exit hook, registered before the backend's own and therefore run after it */
static void
remove_datadir(void)
{
	leave_datadir();
	if (datadir[0] != '\0')
		remove_tree(datadir);
}

/*
 * A process that is killed, or that ends on a crash, cannot remove its data directory. Every process
 * holds a lock on its own directory for as long as it lives, so a directory under `parent` that can be
 * locked, and is not brand new (its owner may be between creating and locking it), was left behind by
 * a process that is gone: remove it, so that a long campaign does not fill the scratch space.
 */
static void
remove_abandoned_datadirs(const char *parent)
{
	DIR *d = opendir(parent);
	struct dirent *e;
	time_t now = time(NULL);

	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL)
	{
		char path[MAXPGPATH + 300];
		struct stat st;
		int fd;

		if (strncmp(e->d_name, "tsfuzz.", 7) != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", parent, e->d_name);
		fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0)
			continue;
		if (fstat(fd, &st) == 0 && st.st_uid == geteuid() && now - st.st_mtime > 60 &&
			flock(fd, LOCK_EX | LOCK_NB) == 0)
			remove_tree(path);
		close(fd);
	}
	closedir(d);
}

/*
 * A crash is reported from inside an input, while the working directory is the data directory. The
 * paths on the command line -- above all where crash artifacts go -- are therefore made absolute, so
 * that they mean the same thing at any moment.
 */
static char *
absolute(const char *cwd, const char *prefix, const char *path)
{
	size_t len = strlen(prefix) + strlen(cwd) + strlen(path) + 2;
	char *res = malloc(len);

	if (res == NULL)
		setup_failed("out of memory", NULL);
	if (path[0] == '/')
		snprintf(res, len, "%s%s", prefix, path);
	else
		snprintf(res, len, "%s%s/%s", prefix, cwd, path);
	return res;
}

static void
make_paths_absolute(int *argc, char ***argv)
{
	static const char *const path_flags[] = { "-artifact_prefix=", "-exact_artifact_path=", "-dict=",
											  "-merge_control_file=", "-features_dir=" };
	char cwd[MAXPGPATH];
	char **args;
	bool have_artifact_path = false;
	int n = 0;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		setup_failed("getcwd", strerror(errno));
	args = calloc((size_t) *argc + 2, sizeof(char *));
	if (args == NULL)
		setup_failed("out of memory", NULL);
	args[n++] = (*argv)[0];
	for (int i = 1; i < *argc; i++)
	{
		char *arg = (*argv)[i];

		if (arg[0] != '-')
			arg = absolute(cwd, "", arg);
		else
			for (size_t f = 0; f < lengthof(path_flags); f++)
			{
				size_t flen = strlen(path_flags[f]);

				if (strncmp(arg, path_flags[f], flen) == 0)
				{
					have_artifact_path |= f < 2;
					arg = absolute(cwd, path_flags[f], arg + flen);
					break;
				}
			}
		args[n++] = arg;
	}
#ifndef FUZZ_STANDALONE
	/* libFuzzer's default is to write crash artifacts to the working directory */
	if (!have_artifact_path)
		args[n++] = absolute(cwd, "-artifact_prefix=", "");
#else
	(void) have_artifact_path; /* the run-once main() takes input files only */
#endif
	args[n] = NULL;
	*argc = n;
	*argv = args;
}

/*
 * Start a single-user backend on `datadir`, connected to the "postgres" database with a transaction
 * open: the steps of PostgresSingleUserMain() and of PostgresMain() up to its command loop
 * (src/backend/tcop/postgres.c, PostgreSQL 18), which cannot be called themselves because they never
 * return. Signal handlers are left alone (the fuzzing engine installs its own). A failure in here is a
 * PostgreSQL FATAL error: it is reported on stderr and ends the process.
 */
static void
start_backend(void)
{
	char *switches[] = { "postgres", "--single", "-F", "postgres", NULL };
	const char *dbname = NULL;

	/* where the backend believes it is installed: only share/ (timezone data) is looked up from it */
	strlcpy(my_exec_path, FUZZ_PG_BIN, MAXPGPATH);
	InitStandaloneProcess(FUZZ_PG_BIN);
	InitializeGUCOptions();
	whereToSendOutput = DestNone; /* messages go to stderr only, at the data directory's log level */
	process_postgres_switches(4, switches, PGC_POSTMASTER, &dbname);
	if (!SelectConfigFiles(datadir, progname))
		setup_failed("cannot read the configuration of the data directory", datadir);
	checkDataDir();
	ChangeToDataDir();
	CreateDataDirLockFile(false);
	LocalProcessControlFile(false);
	process_shared_preload_libraries();
	InitializeMaxBackends();
	InitPostmasterChildSlots();
	InitializeFastPathLocks();
	process_shmem_requests();
	InitializeShmemGUCs();
	InitializeWalConsistencyChecking();
	CreateSharedMemoryAndSemaphores();
	set_max_safe_fds();
	PgStartTime = GetCurrentTimestamp();
	InitProcess();

	InitializeTimeouts();
	BaseInit();
	sigprocmask(SIG_SETMASK, &UnBlockSig, NULL);
	InitPostgres(dbname, InvalidOid, NULL, InvalidOid, 0, NULL);
	SetProcessingMode(NormalProcessing);

	/*
	 * The backend's System V shared memory segment outlives a process that dies without running its
	 * exit handlers, which is how a fuzzing process ends when it finds a crash or is killed. Mark it
	 * for removal now: the kernel keeps it until this process, its only user, detaches.
	 * (UsedShmemSegID is the segment's key.)
	 */
	{
		int shmid = shmget((key_t) UsedShmemSegID, 0, 0);

		if (shmid >= 0)
			(void) shmctl(shmid, IPC_RMID, NULL);
	}

	/* catalog lookups need a transaction; upstream's targets run inside one, too (a SELECT) */
	StartTransactionCommand();
}

static void *
load_module(const char *path)
{
	void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);

	if (handle == NULL)
		setup_failed("cannot load module", dlerror());
	return handle;
}

static const char *const scratch_fallbacks[] = { "/tmp", "/var/tmp", "/dev/shm", "." };

/* the private data directory of a catalog target, under `parent`: created, locked, unpacked */
static bool
prepare_datadir(const char *parent)
{
	snprintf(datadir, sizeof(datadir), "%s/tsfuzz.XXXXXX", parent);
	if (mkdtemp(datadir) == NULL)
	{
		datadir[0] = '\0';
		return failed(parent, strerror(errno));
	}
	datadir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (datadir_fd < 0)
		return failed(datadir, strerror(errno));
	/* a file system without locks fails for every process alike, so nothing is mistaken for abandoned */
	(void) flock(datadir_fd, LOCK_EX | LOCK_NB);
	return unpack_datadir(datadir);
}

/* the first scratch directory that works, under $TMPDIR and then the usual places; the data dir is entered */
static bool
prepare_scratch(void)
{
	const char *tmp = getenv("TMPDIR");
	const bool had_failed = startup_failed;
	const size_t had_error = strlen(startup_error);

	for (size_t candidate = 0; candidate <= lengthof(scratch_fallbacks); candidate++)
	{
		const char *parent = candidate == 0 ? tmp : scratch_fallbacks[candidate - 1];

		if (parent == NULL || parent[0] == '\0')
			continue;
		remove_abandoned_datadirs(parent);
		if (prepare_datadir(parent))
		{
			startup_failed = had_failed;
			startup_error[had_error] = '\0';
			return true;
		}
		if (datadir_fd >= 0)
		{
			close(datadir_fd);
			datadir_fd = -1;
		}
		if (datadir[0] != '\0')
		{
			remove_tree(datadir);
			datadir[0] = '\0';
		}
	}
	return false;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char exe[MAXPGPATH];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	const struct combination *comb = NULL;
	char *name;
	char *suffix;
	PGFunction fuzz_compression;

	if (len < 0)
		strlcpy(exe, (*argv)[0], sizeof(exe));
	else
		exe[len] = '\0';
	name = strrchr(exe, '/');
	name = name != NULL ? name + 1 : exe;
	suffix = strstr(name, "-standalone");
	if (suffix != NULL && suffix[strlen("-standalone")] == '\0')
		*suffix = '\0';
	for (size_t i = 0; i < lengthof(combinations); i++)
		if (strcmp(combinations[i].name, name) == 0)
			comb = &combinations[i];
	if (comb == NULL)
		setup_failed("the executable's name does not select a fuzz target", name);

	/* what PostgreSQL's main() sets up before it dispatches */
	progname = "postgres";
	MyProcPid = getpid();
	MemoryContextInit();

	previous_emit_log_hook = emit_log_hook;
	emit_log_hook = startup_log;
	atexit(remove_datadir);
	atexit(startup_exit_hook);
	startup_armed = true;

	if (comb->needs_catalog)
	{
		make_paths_absolute(argc, argv);
		startdir_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (startdir_fd < 0)
			setup_failed("cannot open the working directory", strerror(errno));
		if (!prepare_scratch())
		{
			/* reported by the third input, see above */
			startup_armed = false;
			if (startdir_fd >= 0)
				(void) fchdir(startdir_fd);
			return 0;
		}
		backend_pending = true;
	}
	else
	{
		/* no database: memory contexts, settings at their defaults, and no server log */
		InitializeGUCOptions();
		whereToSendOutput = DestNone;
		Log_destination = 0;
	}

	/* the modules as built, loaded the way the server's loader does, minus the extension start-up */
	load_module(FUZZ_CORE_MODULE);
	fuzz_compression = (PGFunction) dlsym(load_module(FUZZ_TSL_MODULE), "ts_fuzz_compression");
	if (fuzz_compression == NULL)
		setup_failed("ts_fuzz_compression is not in the TSL module (built without COMPRESSION_FUZZING?)", NULL);

	MemoryContextSwitchTo(TopMemoryContext);
	(void) DirectFunctionCall4(fuzz_compression,
							   CStringGetDatum(comb->algo),
							   ObjectIdGetDatum(comb->type),
							   BoolGetDatum(comb->bulk),
							   Int32GetDatum(0));
	if (upstream_target == NULL || upstream_context == NULL)
		setup_failed("ts_fuzz_compression did not hand over a fuzz target", name);
	startup_armed = false;
	leave_datadir();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static unsigned inputs_since_reset;
	MemoryContext old_context;
	uint8_t *input;
	int res;

	if (startup_failed)
	{
		static int calls;

		if (++calls < 3) /* let a smoke test of the executable pass: the report comes with the crash */
			return 0;
		fprintf(stderr, "fuzz_decompression: start-up failed, nothing to fuzz:\n%s", startup_error);
		abort();
	}

	if (backend_pending)
	{
		backend_pending = false;
		startup_armed = true;
		start_backend();
		atexit(enter_datadir); /* registered after the backend's exit hook, so it runs before it */
		startup_armed = false;
		leave_datadir();
	}

	/*
	 * Upstream's target reads the input through a StringInfo, and PostgreSQL's StringInfo contract is
	 * that data[len] is a readable '\0' (lib/stringinfo.h: "data ... is always terminated by a null
	 * byte"; pq_getmsgstring() relies on it). libFuzzer's buffer has no such byte, so pass an exact-size
	 * copy with the terminator: any read past it is still out of bounds for ASan.
	 */
	input = malloc(size + 1);
	if (input == NULL)
		abort();
	memcpy(input, data, size);
	input[size] = '\0';

	enter_datadir();
	/* every distinct namespace or type name in an input adds a catcache entry that nothing else frees */
	if (datadir_fd >= 0 && ++inputs_since_reset >= CATCACHE_RESET_INPUTS)
	{
		inputs_since_reset = 0;
		ResetCatalogCaches();
	}
	(void) set_stack_base();
	old_context = MemoryContextSwitchTo(upstream_context);
	res = upstream_target(input, size);
	MemoryContextSwitchTo(old_context);
	leave_datadir();

	free(input);
	return res;
}

#ifdef FUZZ_STANDALONE
/*
 * The TimescaleDB modules are compiled with SanCov (-fsanitize=fuzzer-no-link) and call these hooks,
 * which the libFuzzer runtime defines. The run-once reproducer has no libFuzzer runtime, and with
 * SANITIZER_FLAGS empty no sanitizer runtime either, so it supplies no-op fallbacks (weak: a runtime's
 * own definitions win).
 */
#define SANCOV_HOOK(name, ...) __attribute__((weak)) void name(__VA_ARGS__) {}
SANCOV_HOOK(__sanitizer_cov_8bit_counters_init, uint8_t *start, uint8_t *stop)
SANCOV_HOOK(__sanitizer_cov_pcs_init, const uintptr_t *start, const uintptr_t *stop)
SANCOV_HOOK(__sanitizer_cov_trace_pc_indir, uintptr_t callee)
SANCOV_HOOK(__sanitizer_cov_trace_cmp1, uint8_t a, uint8_t b)
SANCOV_HOOK(__sanitizer_cov_trace_cmp2, uint16_t a, uint16_t b)
SANCOV_HOOK(__sanitizer_cov_trace_cmp4, uint32_t a, uint32_t b)
SANCOV_HOOK(__sanitizer_cov_trace_cmp8, uint64_t a, uint64_t b)
SANCOV_HOOK(__sanitizer_cov_trace_const_cmp1, uint8_t a, uint8_t b)
SANCOV_HOOK(__sanitizer_cov_trace_const_cmp2, uint16_t a, uint16_t b)
SANCOV_HOOK(__sanitizer_cov_trace_const_cmp4, uint32_t a, uint32_t b)
SANCOV_HOOK(__sanitizer_cov_trace_const_cmp8, uint64_t a, uint64_t b)
SANCOV_HOOK(__sanitizer_cov_trace_switch, uint64_t val, uint64_t *cases)
SANCOV_HOOK(__sanitizer_cov_trace_div4, uint32_t val)
SANCOV_HOOK(__sanitizer_cov_trace_div8, uint64_t val)
SANCOV_HOOK(__sanitizer_cov_trace_gep, uintptr_t idx)
__attribute__((weak, tls_model("initial-exec"))) __thread uintptr_t __sancov_lowest_stack;
#endif
