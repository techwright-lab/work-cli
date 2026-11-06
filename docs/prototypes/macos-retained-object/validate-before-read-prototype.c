/* THROWAWAY validation-before-open/read probe, synthetic private fixtures only.
 * Packed getattrlist layout parsed with memcpy; no production Rust/proof claim.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
struct token { int valid; uint32_t generation; uint64_t fileid, cloneid; attribute_set_t returned; };
static void die(const char *s){perror(s);exit(1);}
static void put(int d,const char *name,const char *s){int f=openat(d,name,O_CREAT|O_EXCL|O_WRONLY,0600);if(f<0)die("create");size_t n=strlen(s);if(write(f,s,n)!=(ssize_t)n)die("write");close(f);}
static struct stat st(int d,const char *p){struct stat s;if(fstatat(d,p,&s,AT_SYMLINK_NOFOLLOW))die("stat");return s;}
static struct token token(int d,const char *p){
 struct token t={0}; struct attrlist a={0};a.bitmapcount=ATTR_BIT_MAP_COUNT;
 a.commonattr=ATTR_CMN_RETURNED_ATTRS|ATTR_CMN_GEN_COUNT|ATTR_CMN_FILEID;
 a.forkattr=ATTR_CMNEXT_CLONEID;
 unsigned char b[256]={0}; errno=0;
 int r=getattrlistat(d,p,&a,b,sizeof(b),FSOPT_NOFOLLOW|FSOPT_ATTR_CMN_EXTENDED|FSOPT_PACK_INVAL_ATTRS);
 if(r){printf("token path=%s FAILED errno=%d (%s)\n",p,errno,strerror(errno));return t;}
 uint32_t len;memcpy(&len,b,4);size_t need=4+sizeof(attribute_set_t)+4+8+8;
 if(len!=need){printf("token path=%s unexpected packed length=%u expected=%zu\n",p,len,need);return t;}
 size_t off=4;memcpy(&t.returned,b+off,sizeof(t.returned));off+=sizeof(t.returned);
 memcpy(&t.generation,b+off,4);off+=4;memcpy(&t.fileid,b+off,8);off+=8;memcpy(&t.cloneid,b+off,8);
 t.valid=(t.returned.commonattr&a.commonattr)==a.commonattr&&(t.returned.forkattr&a.forkattr)==a.forkattr&&t.generation!=0&&t.cloneid!=0;
 printf("token path=%s len=%u common=0x%x fork=0x%x generation=%u fileid=%llu cloneid=%llu valid=%d\n",p,len,t.returned.commonattr,t.returned.forkattr,t.generation,(unsigned long long)t.fileid,(unsigned long long)t.cloneid,t.valid);return t;
}
static int same(struct stat a,struct stat b){return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&a.st_nlink==b.st_nlink&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&a.st_size==b.st_size&&a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec&&a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec&&a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;}
static void run(int src,int dst,const char *name,int mode){
 printf("\nCASE %s\n",name);put(src,name,"ORIGINAL");
 int mapfd=-1;void *mapping=MAP_FAILED;
 if(mode==3){mapfd=openat(src,name,O_RDWR|O_CLOEXEC);if(mapfd<0)die("mmap file");mapping=mmap(NULL,8,PROT_READ|PROT_WRITE,MAP_SHARED,mapfd,0);if(mapping==MAP_FAILED)die("mmap");}
 struct stat before=st(src,name);struct token pre=token(src,name);
 if(!pre.valid){
  printf("decision=REFUSE capture_calls=0 readable_clone_opens=0 clone_bytes_read=0 reason=invalid_initial_tokens\n");
  if(mapping!=MAP_FAILED&&munmap(mapping,8))die("munmap");if(mapfd>=0)close(mapfd);return;
 }
 char old[64],other[64];snprintf(old,sizeof(old),"%s-old",name);snprintf(other,sizeof(other),"%s-other",name);
 if(mode==1){put(src,other,"REPLACED");if(renameat(src,name,src,old)||renameat(src,other,src,name))die("swap");}
 if(mode==2){int f=openat(src,name,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("writer");if(pwrite(f,"REPLACED",8,0)!=8)die("pwrite");close(f);}
 errno=0;int c=clonefileat(src,name,dst,name,CLONE_NOFOLLOW_ANY|CLONE_RESOLVE_BENEATH);int ce=errno;
 if(mode==1){if(renameat(src,name,src,other)||renameat(src,old,src,name))die("restore");}
 if(mode==2){int f=openat(src,name,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("restore writer");if(pwrite(f,"ORIGINAL",8,0)!=8)die("restore bytes");close(f);struct timespec ts[2]={before.st_atimespec,before.st_mtimespec};if(utimensat(src,name,ts,AT_SYMLINK_NOFOLLOW))die("restore mtime");}
 printf("capture result=%d errno=%d (%s)\n",c,ce,strerror(ce));
 struct stat after=st(src,name);struct token post=token(src,name);struct token captured={0};struct stat cs={0};
 if(c==0){captured=token(dst,name);cs=st(dst,name);}
 int valid=c==0&&same(before,after)&&S_ISREG(cs.st_mode)&&cs.st_nlink==1&&pre.valid&&post.valid&&captured.valid&&pre.fileid==(uint64_t)before.st_ino&&post.fileid==(uint64_t)after.st_ino&&captured.fileid==(uint64_t)cs.st_ino&&pre.generation==post.generation&&pre.cloneid==post.cloneid&&post.cloneid==captured.cloneid;
 int opens=0;ssize_t bytes=0;
 if(valid){int f=openat(dst,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("read validated clone");opens++;struct stat fs;if(fstat(f,&fs))die("opened stat");if(fs.st_dev!=cs.st_dev||fs.st_ino!=cs.st_ino)die("stage changed");char b[9]={0};bytes=read(f,b,8);if(bytes<0)die("read");printf("validated content=%s\n",b);close(f);}
 printf("decision=%s readable_clone_opens=%d clone_bytes_read=%zd source_stamp_equal=%d\n",valid?"READ":"REFUSE",opens,bytes,same(before,after));
 if(mapping!=MAP_FAILED&&munmap(mapping,8))die("munmap");if(mapfd>=0)close(mapfd);
}
int main(int argc,char **argv){if(argc!=2)return 2;int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("root");if(mkdirat(root,"source",0700)||mkdirat(root,"private-clones",0700))die("mkdir");int src=openat(root,"source",O_RDONLY|O_DIRECTORY|O_CLOEXEC),dst=openat(root,"private-clones",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(src<0||dst<0)die("subdirs");run(src,dst,"stable",0);run(src,dst,"path-aba",1);run(src,dst,"content-aba",2);run(src,dst,"mapped",3);close(src);close(dst);close(root);return 0;}
