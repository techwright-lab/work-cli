/* THROWAWAY clone capture budget probe. Small synthetic trees only. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/clonefile.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
static void die(const char *s){perror(s);exit(1);}
static void put(int d,const char *n){int f=openat(d,n,O_CREAT|O_EXCL|O_WRONLY,0600);if(f<0)die("create");if(write(f,"SYNTHETIC",9)!=9)die("write");close(f);}
static unsigned census(int d,unsigned depth){
 if(depth>3)die("synthetic depth exceeded");int fresh=openat(d,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fresh<0)die("fresh dir");DIR *dir=fdopendir(fresh);if(!dir)die("fdopendir");unsigned total=0;struct dirent *e;
 while((e=readdir(dir))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;if(++total>32)die("synthetic count exceeded");struct stat st;if(fstatat(d,e->d_name,&st,AT_SYMLINK_NOFOLLOW))die("entry stat");printf(" captured depth=%u name=%s type=%o\n",depth,e->d_name,st.st_mode&S_IFMT);if(S_ISDIR(st.st_mode)){int child=openat(d,e->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(child<0)die("child");total+=census(child,depth+1);close(child);if(total>32)die("synthetic total exceeded");}}
 closedir(dir);return total;
}
static void run(int src,int dst,const char *name,int populated){
 put(src,name);struct stat before;if(fstatat(src,name,&before,AT_SYMLINK_NOFOLLOW))die("before");
 char old[80];snprintf(old,sizeof(old),"%s-old",name);if(renameat(src,name,src,old)||mkdirat(src,name,0700))die("substitute directory");
 if(populated){int d=openat(src,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(d<0)die("source dir");for(int i=0;i<4;i++){char n[20];snprintf(n,sizeof(n),"file-%d",i);put(d,n);}if(mkdirat(d,"nested",0700))die("nested");int nested=openat(d,"nested",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(nested<0)die("nested open");for(int i=0;i<4;i++){char n[20];snprintf(n,sizeof(n),"child-%d",i);put(nested,n);}close(nested);close(d);}
 printf("\nCASE %s precheck_type=%o precheck_size=%lld precheck_capture_object_budget=1 replacement=%s\n",name,before.st_mode&S_IFMT,(long long)before.st_size,populated?"directory-with-9-descendants":"empty-directory");
 errno=0;int r=clonefileat(src,name,dst,name,CLONE_NOFOLLOW_ANY|CLONE_RESOLVE_BENEATH);int e=errno;printf("clone_result=%d errno=%d (%s)\n",r,e,strerror(e));
 if(r==0){struct stat captured;if(fstatat(dst,name,&captured,AT_SYMLINK_NOFOLLOW))die("captured stat");printf("captured_root_type=%o regular_candidate_decision=REFUSE readable_payload_opens=0\n",captured.st_mode&S_IFMT);if(S_ISDIR(captured.st_mode)){int d=openat(dst,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(d<0)die("clone dir");unsigned count=1+census(d,0);close(d);printf("actual_captured_objects=%u budget_exceeded=%d\n",count,count>1);}}
 else{struct stat absence;errno=0;int a=fstatat(dst,name,&absence,AT_SYMLINK_NOFOLLOW);printf("destination_absence_check=%d errno=%d\n",a,errno);}
}
int main(int argc,char **argv){if(argc!=2)return 2;int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("root");if(mkdirat(root,"source",0700)||mkdirat(root,"private-clones",0700))die("mkdir");int src=openat(root,"source",O_RDONLY|O_DIRECTORY|O_CLOEXEC),dst=openat(root,"private-clones",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(src<0||dst<0)die("subdirs");run(src,dst,"empty",0);run(src,dst,"populated",1);close(src);close(dst);close(root);return 0;}
