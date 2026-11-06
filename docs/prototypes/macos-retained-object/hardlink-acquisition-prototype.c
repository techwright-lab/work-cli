/* THROWAWAY hard-link acquisition probe, SYNTHETIC fixtures only.
 * Mutates link counts/ctime: not approved for production passive inspection.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
static void die(const char *s){perror(s);exit(1);}
static void put(int d,const char *n,const char *s){int f=openat(d,n,O_CREAT|O_EXCL|O_WRONLY,0600);if(f<0)die("create");size_t z=strlen(s);if(write(f,s,z)!=(ssize_t)z)die("write");close(f);}
static struct stat stamp(int d,const char *n){struct stat s;if(fstatat(d,n,&s,AT_SYMLINK_NOFOLLOW))die("stat");return s;}
static void show(const char *label,struct stat s){printf("%s inode=%llu type=%o nlink=%u ctime=%lld.%09ld\n",label,(unsigned long long)s.st_ino,s.st_mode&S_IFMT,s.st_nlink,(long long)s.st_ctimespec.tv_sec,s.st_ctimespec.tv_nsec);}
static void run(int src,int stage,const char *name,int replacement){
 printf("\nCASE %s replacement=%d\n",name,replacement);put(src,name,"ORIGINAL");struct stat original=stamp(src,name);show("before",original);
 if(replacement){char old[80];snprintf(old,sizeof(old),"%s-old",name);if(renameat(src,name,src,old))die("rename source");
  if(replacement==1){if(mkdirat(src,name,0700))die("directory");int d=openat(src,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(d<0)die("dir");for(int i=0;i<4;i++){char n[20];snprintf(n,sizeof(n),"file-%d",i);put(d,n,"SYNTHETIC");}close(d);}
  if(replacement==2){if(mkfifoat(src,name,0600))die("fifo");}
  if(replacement==3){if(symlinkat("sentinel",src,name))die("symlink");}
 }
 errno=0;int r=linkat(src,name,stage,name,0);int e=errno;printf("link_result=%d errno=%d (%s)\n",r,e,strerror(e));
 if(r==0){struct stat retained=stamp(stage,name);show("private hardlink",retained);show("source after acquisition",stamp(src,name));int eligible=S_ISREG(retained.st_mode)&&retained.st_dev==original.st_dev&&retained.st_ino==original.st_ino&&original.st_nlink==1&&retained.st_nlink==2;
  if(eligible){char old[80];snprintf(old,sizeof(old),"%s-away",name);if(renameat(src,name,src,old))die("move acquired original");put(src,name,"REPLACED");int f=openat(stage,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("read retained regular");struct stat fs;if(fstat(f,&fs))die("fstat");if(fs.st_ino!=original.st_ino||!S_ISREG(fs.st_mode))die("wrong retained object");char b[16]={0};ssize_t n=read(f,b,sizeof(b)-1);if(n<0)die("read");printf("retained_read=%s opened_original_inode=1 source_replaced=1\n",b);close(f);
  }else printf("decision=REFUSE readable_payload_opens=0\n");
 }else{struct stat s;errno=0;int a=fstatat(stage,name,&s,AT_SYMLINK_NOFOLLOW);printf("destination_check=%d errno=%d\n",a,errno);}
}
int main(int argc,char **argv){if(argc!=2)return 2;int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("root");if(mkdirat(root,"source",0700)||mkdirat(root,"private-links",0700))die("mkdir");int src=openat(root,"source",O_RDONLY|O_DIRECTORY|O_CLOEXEC),stage=openat(root,"private-links",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(src<0||stage<0)die("dirs");put(src,"sentinel","DO-NOT-READ");run(src,stage,"regular",0);run(src,stage,"directory",1);run(src,stage,"fifo",2);run(src,stage,"symlink",3);close(src);close(stage);close(root);return 0;}
