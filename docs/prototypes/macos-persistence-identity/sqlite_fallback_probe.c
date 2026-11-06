/* THROWAWAY: synthetic calls around the EXACT extracted locked full_fsync().
 * This is NOT execution of bundled SQLite transactions or native fault injection.
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#define HAVE_FULLFSYNC 1
#define OS_VXWORKS 0
#define UNUSED_PARAMETER(x) (void)(x)
static int full_result, sync_result, full_calls, sync_calls;
static int fake_fcntl(int fd, int command, int arg) {
    assert(fd == 42 && command == F_FULLFSYNC && arg == 0);
    ++full_calls;
    if (full_result) errno = EINVAL;
    return full_result;
}
static int fake_fsync(int fd) {
    assert(fd == 42);
    ++sync_calls;
    if (sync_result) errno = EIO;
    return sync_result;
}
#define osFcntl fake_fcntl
#define fsync fake_fsync
#include "sources/sqlite_full_fsync.inc"
static void scenario(const char *name, int requested, int full, int ordinary,
                     int expected_rc, int expected_full, int expected_sync) {
    full_result = full;
    sync_result = ordinary;
    full_calls = sync_calls = 0;
    int rc = full_fsync(42, requested, 0);
    assert(rc == expected_rc && full_calls == expected_full && sync_calls == expected_sync);
    printf("{\"kind\":\"extracted-sqlite-synthetic\",\"case\":\"%s\",\"fullsync_calls\":%d,\"fsync_calls\":%d,\"rc\":%d}\n",
           name, full_calls, sync_calls, rc);
}
int main(void) {
    scenario("ordinary-only", 0, 0, 0, 0, 0, 1);
    scenario("fullsync-success", 1, 0, -1, 0, 1, 0);
    scenario("fullsync-EINVAL-fsync-success", 1, -1, 0, 0, 1, 1);
    scenario("fullsync-EINVAL-fsync-EIO", 1, -1, -1, -1, 1, 1);
    return 0;
}
