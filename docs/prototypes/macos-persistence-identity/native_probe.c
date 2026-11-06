/* THROWAWAY issue #24: owned scratch files only. Not production storage code. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int ok, const char *operation) {
    if (!ok) { fprintf(stderr, "probe failed: %s (errno=%d)\n", operation, errno); exit(1); }
}
static void sync_result(int fd, const char *object, const char *stage, int full) {
    errno = 0;
    int rc = full ? fcntl(fd, F_FULLFSYNC) : fsync(fd);
    int error = rc == -1 ? errno : 0;
    printf("{\"kind\":\"sync\",\"object\":\"%s\",\"stage\":\"%s\",\"call\":\"%s\",\"rc\":%d,\"errno\":%d}\n",
           object, stage, full ? "F_FULLFSYNC" : "fsync", rc, error);
}
static void pair(int fd, const char *object, const char *stage) {
    sync_result(fd, object, stage, 0);
    sync_result(fd, object, stage, 1);
}
static void native(void) {
    int dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(dir >= 0, "open scratch directory");
    struct statfs fs;
    require(fstatfs(dir, &fs) == 0, "fstatfs");
    printf("{\"kind\":\"filesystem\",\"type\":\"%s\"}\n", fs.f_fstypename);
    int file = openat(dir, "stage", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    require(file >= 0, "create stage");
    require(write(file, "scratch payload\n", 16) == 16, "write stage");
    pair(file, "regular-rw", "after-write");
    pair(dir, "directory-ro", "after-create");
    require(renameat(dir, "stage", dir, "published") == 0, "rename");
    pair(dir, "directory-ro", "after-rename");
    int readfd = openat(dir, "published", O_RDONLY | O_CLOEXEC);
    require(readfd >= 0, "open read-only regular");
    pair(readfd, "regular-ro", "after-rename");
    require(unlinkat(dir, "published", 0) == 0, "unlink");
    pair(dir, "directory-ro", "after-unlink");
    require(close(readfd) == 0 && close(file) == 0 && close(dir) == 0, "close");
    /* Negative control: never turn a failed mandatory sync into success. */
    pair(-1, "invalid-fd", "negative-control");
}
static sqlite3 *connect_db(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2("scratch.sqlite", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    require(rc == SQLITE_OK, "sqlite open");
    return db;
}
static void sql(sqlite3 *db, const char *text) {
    int rc = sqlite3_exec(db, text, NULL, NULL, NULL);
    if (rc != SQLITE_OK) { fprintf(stderr, "sqlite statement failed rc=%d\n", rc); exit(1); }
}
static int scalar(sqlite3 *db, const char *text) {
    sqlite3_stmt *stmt = NULL;
    require(sqlite3_prepare_v2(db, text, -1, &stmt, NULL) == SQLITE_OK, "sqlite prepare");
    require(sqlite3_step(stmt) == SQLITE_ROW, "sqlite row");
    int value = sqlite3_column_int(stmt, 0);
    require(sqlite3_finalize(stmt) == SQLITE_OK, "sqlite finalize");
    return value;
}
static void configure(sqlite3 *db, int setting) {
    sql(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=0;");
    if (setting == 1) sql(db, "PRAGMA checkpoint_fullfsync=ON;");
    if (setting == 2) sql(db, "PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;");
}
static void sqlite_probe(int setting) {
    sqlite3 *db = connect_db();
    configure(db, setting);
    printf("{\"kind\":\"sqlite-settings\",\"library\":\"system\",\"version\":\"%s\",\"synchronous\":%d,\"fullfsync\":%d,\"checkpoint_fullfsync\":%d}\n",
           sqlite3_libversion(), scalar(db, "PRAGMA synchronous"), scalar(db, "PRAGMA fullfsync"), scalar(db, "PRAGMA checkpoint_fullfsync"));
    sql(db, "CREATE TABLE events(id INTEGER PRIMARY KEY); BEGIN IMMEDIATE; INSERT INTO events VALUES(1); COMMIT;");
    int log = -1, done = -1;
    int rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_FULL, &log, &done);
    printf("{\"kind\":\"sqlite-checkpoint\",\"commit_rc\":0,\"checkpoint_rc\":%d,\"wal_frames\":%d,\"checkpointed\":%d}\n", rc, log, done);
    require(rc == SQLITE_OK, "checkpoint");
    require(sqlite3_close(db) == SQLITE_OK, "sqlite close");
}
static void crash_probe(int phase) {
    sqlite3 *db = connect_db();
    configure(db, 2);
    sql(db, "CREATE TABLE events(id INTEGER PRIMARY KEY); BEGIN IMMEDIATE; INSERT INTO events VALUES(1);");
    if (phase == 0) _exit(77);
    sql(db, "COMMIT;");
    if (phase == 1) _exit(77);
    int fd = open("marker.stage", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    require(fd >= 0, "create marker");
    require(write(fd, "operation=1\n", 12) == 12, "write marker");
    require(fcntl(fd, F_FULLFSYNC) == 0, "marker fullsync");
    require(close(fd) == 0, "marker close");
    require(rename("marker.stage", "marker") == 0, "marker rename");
    int dir = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(dir >= 0, "marker parent open");
    sync_result(dir, "directory-ro", "crash-marker-after-rename", 1);
    require(close(dir) == 0, "marker parent close");
    /* fflush only publishes probe output, not a durability workaround. */
    fflush(stdout);
    _exit(77);
}
static void reopen(void) {
    sqlite3 *db = connect_db();
    int rows = scalar(db, "SELECT count(*) FROM events");
    int integrity = scalar(db, "SELECT integrity_check='ok' FROM pragma_integrity_check");
    printf("{\"kind\":\"process-crash-reopen\",\"rows\":%d,\"integrity_ok\":%d,\"marker\":%s}\n",
           rows, integrity, access("marker", F_OK) == 0 ? "true" : "false");
    require(sqlite3_close(db) == SQLITE_OK, "sqlite close");
}
int main(int argc, char **argv) {
    alarm(20);
    umask(0077);
    require(argc >= 3, "usage: native_probe MODE OWNED_DIRECTORY [SETTING]");
    require(chdir(argv[2]) == 0, "enter owned fixture");
    if (strcmp(argv[1], "native") == 0) native();
    else if (strcmp(argv[1], "sqlite") == 0 && argc == 4) sqlite_probe(atoi(argv[3]));
    else if (strcmp(argv[1], "crash") == 0 && argc == 4) crash_probe(atoi(argv[3]));
    else if (strcmp(argv[1], "reopen") == 0) reopen();
    else require(0, "unknown mode");
    return 0;
}
