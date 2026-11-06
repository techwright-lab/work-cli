/* THROWAWAY: deterministic clone consistency counterexamples.
 * Only synthetic fixture files. Not production code or race proof.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/clonefile.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static void die(const char *s){perror(s);exit(1);}
static void put(int root,const char *name,const char *s){
 int f=openat(root,name,O_WRONLY|O_CREAT|O_EXCL,0600);if(f<0)die("create");
 size_t n=strlen(s);if(write(f,s,n)!=(ssize_t)n)die("write");close(f);
}
static struct stat stamp(int root,const char *name){struct stat s;if(fstatat(root,name,&s,AT_SYMLINK_NOFOLLOW))die("stat");return s;}
static int timeeq(struct timespec a,struct timespec b){return a.tv_sec==b.tv_sec&&a.tv_nsec==b.tv_nsec;}
static int full_equal(struct stat a,struct stat b){return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&a.st_nlink==b.st_nlink&&a.st_size==b.st_size&&timeeq(a.st_mtimespec,b.st_mtimespec)&&timeeq(a.st_ctimespec,b.st_ctimespec)&&timeeq(a.st_birthtimespec,b.st_birthtimespec);}
static void show(const char *label,struct stat s){printf("%s inode=%llu size=%lld mtime=%lld.%09ld ctime=%lld.%09ld nlink=%u\n",label,(unsigned long long)s.st_ino,(long long)s.st_size,(long long)s.st_mtimespec.tv_sec,s.st_mtimespec.tv_nsec,(long long)s.st_ctimespec.tv_sec,s.st_ctimespec.tv_nsec,s.st_nlink);}
static void clone(int src,const char *from,int dst,const char *to){if(clonefileat(src,from,dst,to,CLONE_NOFOLLOW_ANY|CLONE_RESOLVE_BENEATH))die("clone");}
static void show_clone(int dst,const char *name){
 int f=openat(dst,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("read clone");char b[128]={0};ssize_t n=read(f,b,sizeof(b)-1);if(n<0)die("read");printf("captured_content=%s\n",b);close(f);
}
static void report(struct stat a,struct stat b){show("before",a);show("after",b);printf("identity_only_accepts=%d full_stamp_accepts=%d\n",a.st_dev==b.st_dev&&a.st_ino==b.st_ino,full_equal(a,b));}
static void pause_for_observable_time(void){struct timespec t={0,20000000};if(nanosleep(&t,NULL))die("nanosleep");}
int main(int argc,char **argv){
 if(argc!=2)return 2;int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("fixture");
 if(mkdirat(root,"source",0700)||mkdirat(root,"private-clones",0700))die("mkdir");
 int src=openat(root,"source",O_RDONLY|O_DIRECTORY|O_CLOEXEC),dst=openat(root,"private-clones",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(src<0||dst<0)die("subdirs");
 put(src,"stable","ORIGINAL");struct stat a=stamp(src,"stable");clone(src,"stable",dst,"stable");struct stat b=stamp(src,"stable");printf("\nCASE unchanged\n");report(a,b);show_clone(dst,"stable");
 put(src,"aba","ORIGINAL");put(src,"replacement","REPLACED");a=stamp(src,"aba");pause_for_observable_time();
 if(renameat(src,"aba",src,"original-away")||renameat(src,"replacement",src,"aba"))die("swap");
 clone(src,"aba",dst,"aba");
 if(renameat(src,"aba",src,"replacement-away")||renameat(src,"original-away",src,"aba"))die("restore");
 b=stamp(src,"aba");printf("\nCASE pathname ABA (original inode restored)\n");report(a,b);show_clone(dst,"aba");
 put(src,"content","ORIGINAL");a=stamp(src,"content");pause_for_observable_time();
 int f=openat(src,"content",O_WRONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("writer");
 if(pwrite(f,"REPLACED",8,0)!=8)die("replace content");clone(src,"content",dst,"content");
 if(pwrite(f,"ORIGINAL",8,0)!=8)die("restore content");close(f);
 struct timespec restore[2]={a.st_atimespec,a.st_mtimespec};if(utimensat(src,"content",restore,AT_SYMLINK_NOFOLLOW))die("restore mtime");
 b=stamp(src,"content");printf("\nCASE content ABA (inode, size and mtime restored)\n");report(a,b);show_clone(dst,"content");
 printf("\nLIMIT: deliberate time separation makes timestamp changes observable; not a proof at clock granularity, all races, all metadata or other OS versions.\n");close(src);close(dst);close(root);return 0;
}
