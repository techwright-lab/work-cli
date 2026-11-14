/* Exact-source sidecar propagation harness; mocks model OS ACKs, not APFS. */
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h>
#define SQLITE_PRIVATE
#define SQLITE_IOERR_SHMOPEN 4618
#define SQLITE_IOERR_FSTAT 1802
#define SQLITE_NOMEM_BKPT 7
#define SQLITE_READONLY_CANTINIT 1288
#define SQLITE_MUTEX_FAST 0
#define SQLITE_LOCK_EXCLUSIVE 4
#define SQLITE_CHECKPOINT_PASSIVE 0
#define SQLITE_FCNTL_PERSIST_WAL 10
#define WAL_NORMAL_MODE 0
#define WAL_EXCLUSIVE_MODE 1
#define WAL_HEAPMEMORY_MODE 2
#define O_RDWR 2
#define O_CREAT 64
#define O_RDONLY 0
#define O_NOFOLLOW 0
#define WALTRACE(x)
typedef unsigned char u8;
typedef unsigned int u32;
typedef struct sqlite3 sqlite3;
typedef struct unixShm unixShm;
typedef struct unixShmNode unixShmNode;
typedef struct unixInodeInfo { unixShmNode *pShmNode; int bProcessLock; } unixInodeInfo;
struct unixShm { unixShmNode *pShmNode; unixShm *pNext; };
struct unixShmNode {
  int hShm, isReadonly, nRef; void *pShmMutex;
  unixInodeInfo *pInode; char *zFilename; unixShm *pFirst;
};
typedef struct Wal {
  int exclusiveMode, bShmUnreliable, nWiData, mxWalSize;
  void **apWiData; sqlite3_file *pDbFd, *pWalFd;
  sqlite3_vfs *pVfs; const char *zWalName;
} Wal;
static struct { int bCoreMutex; } sqlite3GlobalConfig;
static int opens, shm_open_fail, shm_lock_fail, checkpoint_fail, persisted;
static void *sqlite3_malloc64(size_t n){ return malloc(n); }
static void sqlite3_free(void *p){ free(p); }
static int sqlite3_uri_boolean(const char *p, const char *key, int d){ (void)p; (void)key; return d; }
static int robust_open(const char *p, int flags, int mode){
  (void)p; (void)flags; (void)mode; assert(++opens<10);
  if(shm_open_fail){ errno=EACCES; return -1; } return 5;
}
static int osFstat(int fd, struct stat *s){ (void)fd; memset(s,0,sizeof(*s)); s->st_mode=0600; return 0; }
static void sqlite3_snprintf(int n, char *s, const char *fmt, ...){
  va_list args; va_start(args,fmt); vsnprintf(s,(size_t)n,fmt,args); va_end(args);
}
static void sqlite3FileSuffix3(const char *a, char *b){ (void)a; (void)b; }
static void robustFchown(int fd, int uid, int gid){ (void)fd; (void)uid; (void)gid; }
static int unixLockSharedMemory(unixFile *f, unixShmNode *n){ (void)f; (void)n; return shm_lock_fail; }
static int unixFileMutexNotheld(unixFile *f){ (void)f; return 1; }
static void unixEnterMutex(void){}
static void unixLeaveMutex(void){}
static void *sqlite3_mutex_alloc(int type){ (void)type; return (void*)1; }
static void sqlite3_mutex_enter(void *m){ (void)m; }
static void sqlite3_mutex_leave(void *m){ (void)m; }
static void unixShmPurge(unixFile *f){
  unixShmNode *n=f->pInode->pShmNode;
  if(n && n->nRef==0){ free(n); f->pInode->pShmNode=0; }
}
static int sqlite3OsLock(sqlite3_file *f, int type){ (void)f; (void)type; return 0; }
static int walAssertLockmask(Wal *w){ (void)w; return 1; }
static int sqlite3WalCheckpoint(Wal *w, sqlite3 *db, int m, void *a, void *b, int sync, int n, u8 *buf, void *c, void *d){
  (void)w; (void)db; (void)m; (void)a; (void)b; (void)sync; (void)n; (void)buf; (void)c; (void)d;
  return checkpoint_fail;
}
static void sqlite3OsFileControlHint(sqlite3_file *f, int op, int *p){ (void)f; (void)op; *p=persisted; }
static void walLimitSize(Wal *w, int n){ (void)w; (void)n; }
static int sqlite3OsClose(sqlite3_file *f){ (void)f; return 0; }
static void sqlite3BeginBenignMalloc(void){}
static void sqlite3EndBenignMalloc(void){}
static int sqlite3OsDelete(sqlite3_vfs *v, const char *path, int sync){ return unixDelete(v,path,sync); }
/* SIDECAR_SOURCE */
static int close_wal(unixFile *file){
  Wal *wal=calloc(1,sizeof(*wal)); u8 buffer=0;
  wal->pDbFd=(sqlite3_file*)file; wal->zWalName="owned.db-wal"; wal->mxWalSize=-1;
  return sqlite3WalClose(wal,0,SQLITE_SYNC_FULL,1,&buffer);
}
static void sidecar_tests(void){
  unixInodeInfo inode={0,0}; unixFile file={3,0,"owned.db",0,&inode};
  reset(); opens=0; dir_open_fail=1;
#ifdef __APPLE__
  assert(unixOpenSharedMemory(&file)!=SQLITE_OK);
  assert(file.pShm==0); assert(inode.pShmNode==0);
#else
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  assert(unixShmUnmap((sqlite3_file*)&file,0)==SQLITE_OK);
#endif
  reset(); opens=0; dir_sync_fail=1;
#ifdef __APPLE__
  assert(unixOpenSharedMemory(&file)==SQLITE_IOERR_DIR_FSYNC);
  assert(file.pShm==0); assert(inode.pShmNode==0);
#else
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  assert(unixShmUnmap((sqlite3_file*)&file,0)==SQLITE_OK);
#endif
  reset(); opens=0; shm_open_fail=1;
  assert(unixOpenSharedMemory(&file)!=SQLITE_OK); assert(file.pShm==0);
  shm_open_fail=0;
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); unlink_fail=EACCES;
#ifdef __APPLE__
  assert(close_wal(&file)==SQLITE_IOERR_DELETE);
#else
  assert(close_wal(&file)==SQLITE_OK);
#endif
  assert(file.pShm==0); assert(inode.pShmNode==0);
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); dir_open_fail=1;
#ifdef __APPLE__
  assert(close_wal(&file)!=SQLITE_OK);
#else
  assert(close_wal(&file)==SQLITE_OK);
#endif
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); dir_sync_fail=1;
#ifdef __APPLE__
  assert(close_wal(&file)==SQLITE_IOERR_DIR_FSYNC);
#else
  assert(close_wal(&file)==SQLITE_OK);
#endif
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); unlink_fail=EACCES; unlink_fail_at=2;
#ifdef __APPLE__
  assert(close_wal(&file)==SQLITE_IOERR_DELETE); assert(unlink_calls==2);
#else
  assert(close_wal(&file)==SQLITE_OK);
#endif
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); dir_open_fail=1; dir_fail_at=2;
#ifdef __APPLE__
  assert(close_wal(&file)!=SQLITE_OK); assert(dir_calls==2);
#else
  assert(close_wal(&file)==SQLITE_OK);
#endif
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); dir_sync_fail=1; dir_fail_at=2;
#ifdef __APPLE__
  assert(close_wal(&file)==SQLITE_IOERR_DIR_FSYNC); assert(dir_calls==2);
#else
  assert(close_wal(&file)==SQLITE_OK);
#endif
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset(); checkpoint_fail=SQLITE_IOERR_FSYNC;
  assert(close_wal(&file)==SQLITE_IOERR_FSYNC); assert(unlink_calls==0);
  checkpoint_fail=0;
  reset(); opens=0;
  assert(unixOpenSharedMemory(&file)==SQLITE_OK);
  reset();
  assert(close_wal(&file)==SQLITE_OK);
  assert(file.pShm==0); assert(inode.pShmNode==0);
}
