/* THROWAWAY: APFS clone acquisition experiment, synthetic scratch only.
 * Clones are new objects: this is not a production exact-object proof.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/clonefile.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
static void die(const char *s){perror(s);exit(1);}
static void put(int d,const char *name,const char *data){
 int f=openat(d,name,O_CREAT|O_EXCL|O_WRONLY,0600);if(f<0)die("create");
 size_t n=strlen(data);if(write(f,data,n)!=(ssize_t)n)die("write");close(f);
}
static void copy_probe(int src,int dst,const char *from,const char *to){
 struct stat before; if(fstatat(src,from,&before,AT_SYMLINK_NOFOLLOW))die("source stat");
 errno=0;int r=clonefileat(src,from,dst,to,CLONE_NOFOLLOW_ANY|CLONE_RESOLVE_BENEATH);int e=errno;
 printf("clone %s -> %s source_type=%o source_inode=%llu result=%d errno=%d (%s)\n",from,to,before.st_mode&S_IFMT,(unsigned long long)before.st_ino,r,e,strerror(e));
 if(r==0){
  struct stat st;if(fstatat(dst,to,&st,AT_SYMLINK_NOFOLLOW))die("clone stat");
  printf(" clone_type=%o clone_inode=%llu same_inode=%d\n",st.st_mode&S_IFMT,(unsigned long long)st.st_ino,st.st_ino==before.st_ino);
  if(S_ISREG(st.st_mode)){
   int f=openat(dst,to,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("read clone");
   char b[80]={0};ssize_t n=read(f,b,sizeof(b)-1);if(n<0)die("read");
   printf(" clone_content=%s\n",b);close(f);
  }
 }
}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("root");
 if(mkdirat(root,"source",0700)||mkdirat(root,"private-clones",0700))die("mkdir");
 int src=openat(root,"source",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 int dst=openat(root,"private-clones",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(src<0||dst<0)die("directories");
 put(src,"file","ORIGINAL-SYNTHETIC");
 copy_probe(src,dst,"file","before-replacement");
 if(renameat(src,"file",src,"old"))die("rename");put(src,"file","REPLACEMENT-SYNTHETIC");
 copy_probe(src,dst,"file","after-replacement");
 copy_probe(src,dst,"file","before-replacement");
 if(mkfifoat(src,"fifo",0600))die("fifo");copy_probe(src,dst,"fifo","fifo-copy");
 if(symlinkat("file",src,"link"))die("link");copy_probe(src,dst,"link","link-copy");
 close(src);close(dst);close(root);return 0;
}
