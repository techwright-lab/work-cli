/* Test-only bounded fault controls. Never linked into SQLite or Work. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define SQLITE_OK 0
#define SQLITE_CANTOPEN 14
#define SQLITE_CANTOPEN_BKPT SQLITE_CANTOPEN
#define SQLITE_IOERR_FSYNC 1034
#define SQLITE_IOERR_DIR_FSYNC 1290
#define SQLITE_IOERR_DELETE 2570
#define SQLITE_IOERR_DELETE_NOENT 5898
#define SQLITE_SYNC_NORMAL 2
#define SQLITE_SYNC_FULL 3
#define SQLITE_SYNC_DATAONLY 16
#define UNIXFILE_DIRSYNC 8
#ifndef HAVE_FULLFSYNC
#define HAVE_FULLFSYNC 1
#endif
#define F_FULLFSYNC 51
#define OS_VXWORKS 0
#define UNUSED_PARAMETER(x) (void)(x)
#define OSTRACE(x)
#define SimulateIOError(x)
#define SimulateDiskfullError(x)
typedef struct sqlite3_file { int unused; } sqlite3_file;
typedef struct sqlite3_vfs { int unused; } sqlite3_vfs;
typedef struct unixFile {
  int h; unsigned ctrlFlags; const char *zPath;
  struct unixShm *pShm; struct unixInodeInfo *pInode;
} unixFile;
static int full_fail, ordinary_fail, dir_open_fail, dir_sync_fail, unlink_fail;
static int full_fail_errno;
static int unlink_fail_at, dir_fail_at;
static int full_calls, ordinary_calls, dir_calls, close_calls, unlink_calls;
static int negative_dir;
static int mock_fcntl(int fd, int op, int arg){
  assert(op==F_FULLFSYNC && arg==0); assert(++full_calls<10);
  if( (fd==7 && dir_sync_fail && (!dir_fail_at || dir_calls==dir_fail_at))
      || (fd!=7 && full_fail) ){ errno=(fd==7 ? EIO : full_fail_errno); return -1; }
  return 0;
}
static int mock_fsync(int fd){
  assert(++ordinary_calls<10);
  if( ordinary_fail || (fd==7 && dir_sync_fail) ){ errno=EIO; return -1; }
  return 0;
}
static int mock_open_directory(const char *path, int *fd){
  assert(path!=0); assert(++dir_calls<10);
  if(dir_open_fail && (!dir_fail_at || dir_calls==dir_fail_at)){
    errno=EACCES; return SQLITE_CANTOPEN;
  }
  *fd=negative_dir ? -1 : 7; return SQLITE_OK;
}
static int mock_unlink(const char *path){
  assert(path!=0); assert(++unlink_calls<10);
  if(unlink_fail && (!unlink_fail_at || unlink_calls==unlink_fail_at)){
    errno=unlink_fail; return -1;
  } return 0;
}
static void robust_close(unixFile *file, int fd, int line){ (void)file; (void)line; assert(fd==7); close_calls++; }
static int unixLogError(int rc, const char *op, const char *path){ (void)op; (void)path; return rc; }
static void storeLastErrno(unixFile *file, int error){ (void)file; (void)error; }
#define osFcntl mock_fcntl
#define fsync mock_fsync
#define fdatasync mock_fsync
#define osOpenDirectory mock_open_directory
#define osUnlink mock_unlink
typedef long long sqlite3_int64;
typedef struct Pager {
  int noSync;
  sqlite3_file *jfd;
  sqlite3_int64 journalHdr;
} Pager;
static int unixSync(sqlite3_file *, int);
static int journal_flags, journal_sync_calls, journal_size_calls;
static int journal_order, journal_ack_order, journal_size_order;
static int journal_size_rc;
static sqlite3_int64 journal_size_value;
static int sqlite3OsSync(sqlite3_file *f, int flags){
  int rc;
  journal_flags=flags;
  journal_sync_calls++;
  rc=unixSync(f,flags);
  if( rc==SQLITE_OK ) journal_ack_order=++journal_order;
  return rc;
}
static int sqlite3OsFileSize(sqlite3_file *f, sqlite3_int64 *size){
  assert(f!=0);
  journal_size_calls++;
  journal_size_order=++journal_order;
  *size=journal_size_value;
  return journal_size_rc;
}
/* EXACT_SOURCE */
static void reset(void);
/* SIDECAR_HARNESS */
static void reset(void){
  full_fail=ordinary_fail=dir_open_fail=dir_sync_fail=unlink_fail=negative_dir=0;
  unlink_fail_at=dir_fail_at=0;
  full_calls=ordinary_calls=dir_calls=close_calls=unlink_calls=0;
  full_fail_errno=EIO;
  journal_flags=journal_sync_calls=journal_size_calls=0;
  journal_order=journal_ack_order=journal_size_order=0;
  journal_size_rc=SQLITE_OK;
  journal_size_value=321;
}
/* CREATION_CLASSIFIER */
static void journal_tests(void){
  unixFile file={3, 0, "owned.db-journal",0,0};
  Pager pager={0, (sqlite3_file*)&file, 77};
  reset();
  assert(pagerSyncHotJournal(&pager)==SQLITE_OK);
#ifdef __APPLE__
  assert(journal_flags==SQLITE_SYNC_FULL);
  assert(full_calls==1); assert(ordinary_calls==0);
#else
  assert(journal_flags==SQLITE_SYNC_NORMAL);
  assert(full_calls==0); assert(ordinary_calls==1);
#endif
  assert(journal_sync_calls==1); assert(dir_calls==0);
  assert(journal_size_calls==1); assert(pager.journalHdr==321);
  assert(journal_ack_order==1); assert(journal_size_order==2);
#ifdef __APPLE__
  {
    const int errors[]={EIO, ENOTSUP};
    unsigned i;
    for(i=0; i<sizeof(errors)/sizeof(errors[0]); i++){
      unixFile failed_file={3, 0, "owned.db-journal",0,0};
      Pager failed_pager={0, (sqlite3_file*)&failed_file, 77};
      reset(); full_fail=1; full_fail_errno=errors[i];
      assert(ordinary_fail==0);
      assert(pagerSyncHotJournal(&failed_pager)==SQLITE_IOERR_FSYNC);
      assert(journal_flags==SQLITE_SYNC_FULL); assert(journal_sync_calls==1);
      assert(full_calls==1); assert(ordinary_calls==0);
      assert(dir_calls==0); assert(close_calls==0);
      assert(journal_size_calls==0); assert(failed_pager.journalHdr==77);
      assert(journal_ack_order==0); assert(journal_size_order==0);
      assert(journal_order==0);
    }
  }
  {
    unixFile failed_file={3, UNIXFILE_DIRSYNC, "owned.db-journal",0,0};
    Pager failed_pager={0, (sqlite3_file*)&failed_file, 77};
    reset(); full_fail=1;
    assert(ordinary_fail==0);
    assert(pagerSyncHotJournal(&failed_pager)==SQLITE_IOERR_FSYNC);
    assert(journal_flags==SQLITE_SYNC_FULL); assert(journal_sync_calls==1);
    assert(full_calls==1); assert(ordinary_calls==0);
    assert(dir_calls==0); assert(close_calls==0);
    assert(failed_file.ctrlFlags & UNIXFILE_DIRSYNC);
    assert(journal_size_calls==0); assert(failed_pager.journalHdr==77);
    assert(journal_ack_order==0); assert(journal_size_order==0);
    assert(journal_order==0);
  }
#else
  {
    unixFile failed_file={3, 0, "owned.db-journal",0,0};
    Pager failed_pager={0, (sqlite3_file*)&failed_file, 77};
    reset(); ordinary_fail=1;
    assert(pagerSyncHotJournal(&failed_pager)==SQLITE_IOERR_FSYNC);
    assert(journal_flags==SQLITE_SYNC_NORMAL); assert(journal_sync_calls==1);
    assert(full_calls==0); assert(ordinary_calls==1);
    assert(dir_calls==0); assert(close_calls==0);
    assert(journal_size_calls==0); assert(failed_pager.journalHdr==77);
    assert(journal_ack_order==0); assert(journal_size_order==0);
    assert(journal_order==0);
  }
#endif
  {
    unixFile size_file={3, 0, "owned.db-journal",0,0};
    Pager size_pager={0, (sqlite3_file*)&size_file, 77};
    reset(); journal_size_rc=SQLITE_IOERR_FSTAT;
    assert(pagerSyncHotJournal(&size_pager)==SQLITE_IOERR_FSTAT);
#ifdef __APPLE__
    assert(journal_flags==SQLITE_SYNC_FULL);
    assert(full_calls==1); assert(ordinary_calls==0);
#else
    assert(journal_flags==SQLITE_SYNC_NORMAL);
    assert(full_calls==0); assert(ordinary_calls==1);
#endif
    assert(journal_sync_calls==1); assert(dir_calls==0);
    assert(journal_size_calls==1); assert(size_pager.journalHdr==321);
    assert(journal_ack_order==1); assert(journal_size_order==2);
    assert(journal_order==2);
  }
  {
    unixFile bypass_file={3, 0, "owned.db-journal",0,0};
    Pager bypass_pager={1, (sqlite3_file*)&bypass_file, 77};
    reset();
    assert(pagerSyncHotJournal(&bypass_pager)==SQLITE_OK);
    assert(journal_sync_calls==0); assert(journal_flags==0);
    assert(full_calls==0); assert(ordinary_calls==0); assert(dir_calls==0);
    assert(journal_size_calls==1); assert(bypass_pager.journalHdr==321);
    assert(journal_ack_order==0); assert(journal_size_order==1);
    assert(journal_order==1);
  }
  {
    unixFile bypass_file={3, 0, "owned.db-journal",0,0};
    Pager bypass_pager={1, (sqlite3_file*)&bypass_file, 77};
    reset(); journal_size_rc=SQLITE_IOERR_FSTAT;
    assert(pagerSyncHotJournal(&bypass_pager)==SQLITE_IOERR_FSTAT);
    assert(journal_sync_calls==0); assert(journal_flags==0);
    assert(full_calls==0); assert(ordinary_calls==0); assert(dir_calls==0);
    assert(journal_size_calls==1); assert(bypass_pager.journalHdr==321);
    assert(journal_ack_order==0); assert(journal_size_order==1);
    assert(journal_order==1);
  }
}
int main(void){
  const int types[]={SQLITE_OPEN_MAIN_DB, SQLITE_OPEN_MAIN_JOURNAL,
                     SQLITE_OPEN_SUPER_JOURNAL, SQLITE_OPEN_WAL};
  unsigned i;
  unixFile file={3, UNIXFILE_DIRSYNC, "owned.db-wal",0,0};
  reset(); full_fail=1;
#ifdef __APPLE__
  assert(full_fsync(3,1,0)!=0); assert(ordinary_calls==0);
#else
  assert(full_fsync(3,1,0)==0); assert(ordinary_calls==1);
#endif
  reset(); ordinary_fail=1;
  assert(full_fsync(3,0,0)!=0);
  file.ctrlFlags=0;
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_NORMAL)==SQLITE_IOERR_FSYNC);
  file.ctrlFlags=UNIXFILE_DIRSYNC;
  reset(); full_fail=1;
#ifdef __APPLE__
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_IOERR_FSYNC);
  assert(dir_calls==0); assert(file.ctrlFlags & UNIXFILE_DIRSYNC);
#else
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_OK);
#endif
  reset(); file.ctrlFlags=UNIXFILE_DIRSYNC; dir_open_fail=1;
#ifdef __APPLE__
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)!=SQLITE_OK);
  assert(file.ctrlFlags & UNIXFILE_DIRSYNC);
#else
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_OK);
#endif
  reset(); file.ctrlFlags=UNIXFILE_DIRSYNC; dir_sync_fail=1;
#ifdef __APPLE__
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_IOERR_DIR_FSYNC);
  assert(file.ctrlFlags & UNIXFILE_DIRSYNC); assert(close_calls==1);
#else
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_OK);
#endif
  reset(); file.ctrlFlags=UNIXFILE_DIRSYNC;
  assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_OK);
  assert(!(file.ctrlFlags & UNIXFILE_DIRSYNC)); assert(close_calls==1);
  reset(); dir_open_fail=1;
#ifdef __APPLE__
  assert(unixDelete(0,"owned.db-wal",1)!=SQLITE_OK);
#else
  assert(unixDelete(0,"owned.db-wal",1)==SQLITE_OK);
#endif
  reset(); dir_sync_fail=1;
  assert(unixDelete(0,"owned.db-wal",1)==SQLITE_IOERR_DIR_FSYNC);
  assert(close_calls==1);
  reset(); unlink_fail=EACCES;
  assert(unixDelete(0,"owned.db-wal",1)==SQLITE_IOERR_DELETE);
  assert(dir_calls==0);
  reset(); unlink_fail=ENOENT;
  assert(unixDelete(0,"owned.db-wal",1)==SQLITE_IOERR_DELETE_NOENT);
#ifdef __APPLE__
  reset(); negative_dir=1;
  assert(unixDelete(0,"owned.db-wal",1)!=SQLITE_OK); assert(close_calls==0);
  reset();
  assert(unixDelete(0,"owned.db-wal",0)==SQLITE_OK);
  assert(dir_calls==1); assert(full_calls==1);
#endif
  for(i=0; i<sizeof(types)/sizeof(types[0]); i++){
    int flags=creation_flags(1,types[i]);
    reset(); file.ctrlFlags=(unsigned)flags; dir_open_fail=1;
#ifdef __APPLE__
    assert(flags & UNIXFILE_DIRSYNC);
    assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)!=SQLITE_OK);
    assert(file.ctrlFlags & UNIXFILE_DIRSYNC);
#else
    if(types[i]==SQLITE_OPEN_MAIN_DB) assert(flags==0);
    else assert(flags & UNIXFILE_DIRSYNC);
    assert(unixSync((sqlite3_file*)&file,SQLITE_SYNC_FULL)==SQLITE_OK);
#endif
    assert(creation_flags(0,types[i])==0);
  }
  sidecar_tests();
  journal_tests();
  return 0;
}
