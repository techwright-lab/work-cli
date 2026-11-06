/* THROWAWAY macOS probe: not production code or safety qualification.
 * Run in an empty owned fixture directory. Only synthetic files are touched.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what) { perror(what); exit(1); }
static void put(int root, const char *name, const char *text) {
    int fd = openat(root, name, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) die("create fixture");
    size_t n = strlen(text);
    if (write(fd, text, n) != (ssize_t)n) die("write fixture");
    close(fd);
}
static void observe(const char *label, int fd) {
    if (fd < 0) { printf("%s: OPEN FAILED errno=%d (%s)\n", label, errno, strerror(errno)); return; }
    struct stat st;
    if (fstat(fd, &st)) die("fstat");
    errno = 0; int flags = fcntl(fd, F_GETFL); int flag_errno = errno;
    printf("%s: fd=%d dev=%llu inode=%llu type=%o flags=0x%x flags_errno=%d\n",
        label, fd, (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        st.st_mode & S_IFMT, flags, flag_errno);
}
static void read_synthetic(const char *label, int fd) {
    if (fd < 0) return;
    char buf[80] = {0}; errno = 0;
    ssize_t n = read(fd, buf, sizeof(buf)-1); int e = errno;
    printf("%s: read=%zd errno=%d (%s) content=%s\n", label, n, e, strerror(e), n > 0 ? buf : "<none>");
}
static void run_case(int root, const char *name, int metadata_flags, int replacement_kind) {
    printf("\nCASE name=%s metadata_flags=0x%x replacement=%s\n", name, metadata_flags,
        replacement_kind == 0 ? "regular" : replacement_kind == 1 ? "fifo" : "symlink");
    put(root, name, "ORIGINAL-SYNTHETIC-DATA");
    int retained = openat(root, name, metadata_flags | O_NOFOLLOW | O_CLOEXEC);
    observe("retained metadata handle", retained);
    if (retained < 0) return;
    char old[100]; snprintf(old, sizeof(old), "%s.old", name);
    if (renameat(root, name, root, old)) die("rename original");
    if (replacement_kind == 0) put(root, name, "REPLACEMENT-SYNTHETIC-DATA");
    else if (replacement_kind == 1) { if (mkfifoat(root, name, 0600)) die("mkfifoat"); }
    else { if (symlinkat("symlink-target", root, name)) die("symlinkat"); }

    /* Controlled negative: readable open has happened before type/identity recheck.
     * Nonblocking avoids a FIFO hang; no replacement FIFO/device is read.
     */
    int pathfd = openat(root, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    observe("pathname readable-open after replacement", pathfd);
    if (pathfd >= 0) close(pathfd);

    char devfd[80]; snprintf(devfd, sizeof(devfd), "/dev/fd/%d", retained);
    int reopened = open(devfd, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    observe("/dev/fd readable-open", reopened);
    read_synthetic("/dev/fd synthetic read", reopened);
    if (reopened >= 0) close(reopened);
    int duplicated = dup(retained);
    observe("dup retained handle", duplicated);
    read_synthetic("dup synthetic read", duplicated);
    if (duplicated >= 0) close(duplicated);
    close(retained);
}
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: probe EMPTY-FIXTURE-DIRECTORY\n"); return 2; }
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) die("open fixture");
    put(root, "symlink-target", "SYMLINK-TARGET-SYNTHETIC-DATA");
    run_case(root, "event-regular", O_EVTONLY, 0);
    run_case(root, "event-fifo", O_EVTONLY, 1);
    run_case(root, "event-symlink", O_EVTONLY, 2);
    run_case(root, "symlink-handle-regular", O_SYMLINK, 0);
    close(root);
    return 0;
}
