/* Whole-amalgamation Linux smoke. No injected production switches or system SQLite. */
#include "sqlite3.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static void sql(sqlite3 *db, const char *statement){
  int rc=sqlite3_exec(db,statement,0,0,0);
  if(rc!=SQLITE_OK) fprintf(stderr,"%s: %s\n",statement,sqlite3_errmsg(db));
  assert(rc==SQLITE_OK);
}
int main(int argc, char **argv){
  sqlite3 *db=0, *second=0;
  int log=-1, done=-1;
  assert(argc==2);
  assert(strcmp(sqlite3_libversion(),"3.51.1")==0);
  assert(strcmp(sqlite3_sourceid(),SQLITE_SOURCE_ID)==0);
  assert(sqlite3_open(argv[1],&db)==SQLITE_OK);
  sql(db,"PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; CREATE TABLE t(x);");
  sql(db,"INSERT INTO t VALUES(1);");
  sql(db,"PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO t VALUES(2);");
  assert(sqlite3_open(argv[1],&second)==SQLITE_OK);
  sql(second,"PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; INSERT INTO t VALUES(3);");
  assert(sqlite3_close(second)==SQLITE_OK);
  assert(sqlite3_wal_checkpoint_v2(db,0,SQLITE_CHECKPOINT_TRUNCATE,&log,&done)==SQLITE_OK);
  sql(db,"PRAGMA journal_mode=DELETE; INSERT INTO t VALUES(4);");
  assert(sqlite3_close(db)==SQLITE_OK);
  return 0;
}
