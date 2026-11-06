/* THROWAWAY macOS hardlink protocol; synthetic fixtures only, not production. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *s) { perror(s); exit(1); }
static void require(int ok, const char *s) { if (!ok) { fprintf(stderr,"ASSERT: %s\n",s); exit(1); } }
static void put(int d,const char *n,const char *s) {
 int f=openat(d,n,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); if(f<0)die("put");
 size_t z=strlen(s); if(write(f,s,z)!=(ssize_t)z||fsync(f))die("write"); close(f);
}
static struct stat st(int d,const char *n) { struct stat s; if(fstatat(d,n,&s,AT_SYMLINK_NOFOLLOW))die("stat"); return s; }
static struct stat fst(int f) { struct stat s; if(fstat(f,&s))die("fstat"); return s; }
static int id(struct stat a,struct stat b) { return a.st_dev==b.st_dev&&a.st_ino==b.st_ino; }
static int timeeq(struct timespec a,struct timespec b) { return a.tv_sec==b.tv_sec&&a.tv_nsec==b.tv_nsec; }
static int stamp(struct stat a,struct stat b,int ctime) {
 return id(a,b)&&a.st_mode==b.st_mode&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&a.st_flags==b.st_flags&&a.st_size==b.st_size&&timeeq(a.st_mtimespec,b.st_mtimespec)&&(!ctime||timeeq(a.st_ctimespec,b.st_ctimespec));
}
struct token { uint32_t generation; uint64_t fileid,stream; int valid; };
static struct token tok(int d,const char *n) {
 struct token t={0}; struct attrlist a={0}; a.bitmapcount=ATTR_BIT_MAP_COUNT;
 a.commonattr=ATTR_CMN_RETURNED_ATTRS|ATTR_CMN_GEN_COUNT|ATTR_CMN_FILEID; a.forkattr=ATTR_CMNEXT_CLONEID;
 unsigned char b[256]={0}; if(getattrlistat(d,n,&a,b,sizeof(b),FSOPT_NOFOLLOW|FSOPT_ATTR_CMN_EXTENDED|FSOPT_PACK_INVAL_ATTRS))return t;
 uint32_t len; attribute_set_t returned; memcpy(&len,b,4);
 if(len!=4+sizeof(returned)+4+8+8)return t;
 size_t o=4; memcpy(&returned,b+o,sizeof(returned));o+=sizeof(returned);
 memcpy(&t.generation,b+o,4);o+=4;memcpy(&t.fileid,b+o,8);o+=8;memcpy(&t.stream,b+o,8);
 t.valid=(returned.commonattr&a.commonattr)==a.commonattr&&(returned.forkattr&a.forkattr)==a.forkattr&&t.generation&&t.stream;
 return t;
}
static int teq(struct token a,struct token b) { return a.valid&&b.valid&&a.generation==b.generation&&a.fileid==b.fileid&&a.stream==b.stream; }
static int private_dir(int f) {
 struct stat s=fst(f); if(!S_ISDIR(s.st_mode)||s.st_uid!=geteuid()||(s.st_mode&07777)!=0700)return 0;
 errno=0;acl_t a=acl_get_fd_np(f,ACL_TYPE_EXTENDED);
 if(!a)return errno==ENOENT; /* observed Darwin no-ACL result on a retained valid dir FD */
 if(acl_valid(a)){acl_free(a);return 0;}
 acl_entry_t e;errno=0;int r=acl_get_entry(a,ACL_FIRST_ENTRY,&e);int error=errno;acl_free(a);
 return r==-1&&error==EINVAL; /* Darwin: 0 means an entry exists; any ACL entry holds. */
}
struct capture {
 int root,src,stage; const char *name; struct stat rootid,srcid,stageid,pre,linked;
 struct token before,after; int linked_ok,opens,bytes,charge; const char *phase;
};
static void manifest(struct capture *c) {
 /* Fixed bounded record. A real implementation needs a qualified durable journal,
  * atomic transition publication, boot/session binding and bounded safe parser. */
 char b[2048]; int n=snprintf(b,sizeof(b),
  "THROWAWAY-HARDLINK-1 capture=%s phase=%s charge=%d\nroot=%llu:%llu source_dir=%llu:%llu stage=%llu:%llu\nentry=payload source=payload initial=%llu:%llu initial_nlink=%u linked=%llu:%llu linked_nlink=%u\ngeneration_before=%u generation_linked=%u stream_before=%llu stream_linked=%llu\nsize=%lld mtime=%lld.%09ld ctime_linked=%lld.%09ld\n",
  c->name,c->phase,c->charge,(unsigned long long)c->rootid.st_dev,(unsigned long long)c->rootid.st_ino,
  (unsigned long long)c->srcid.st_dev,(unsigned long long)c->srcid.st_ino,(unsigned long long)c->stageid.st_dev,(unsigned long long)c->stageid.st_ino,
  (unsigned long long)c->pre.st_dev,(unsigned long long)c->pre.st_ino,c->pre.st_nlink,(unsigned long long)c->linked.st_dev,(unsigned long long)c->linked.st_ino,c->linked.st_nlink,
  c->before.generation,c->after.generation,(unsigned long long)c->before.stream,(unsigned long long)c->after.stream,(long long)c->linked.st_size,
  (long long)c->linked.st_mtimespec.tv_sec,c->linked.st_mtimespec.tv_nsec,(long long)c->linked.st_ctimespec.tv_sec,c->linked.st_ctimespec.tv_nsec);
 require(n>0&&(size_t)n<sizeof(b),"manifest bound");
 int f=openat(c->root,"manifest",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);if(f<0)die("manifest");
 if(write(f,b,(size_t)n)!=n||fsync(f))die("manifest sync");close(f);if(fsync(c->root))die("root sync");
}
static struct capture setup(int top,const char *name) {
 if(mkdirat(top,name,0700))die("case mkdir"); struct capture c={0};c.name=name;c.charge=1;c.phase="RESERVED";
 c.root=openat(top,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(c.root<0)die("case open");
 if(mkdirat(c.root,"source",0700)||mkdirat(c.root,"stage",0700))die("subdir mkdir");
 c.src=openat(c.root,"source",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);c.stage=openat(c.root,"stage",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(c.src<0||c.stage<0)die("subdir open");c.rootid=fst(c.root);c.srcid=fst(c.src);c.stageid=fst(c.stage);
 require(private_dir(c.root)&&private_dir(c.stage),"new private stage/root");require(c.srcid.st_dev==c.stageid.st_dev,"same volume");put(c.src,"payload","ORIGINAL");
 c.pre=st(c.src,"payload");c.before=tok(c.src,"payload");return c;
}
static int protected(struct capture *c) {
 return private_dir(c->root)&&private_dir(c->stage)&&id(c->rootid,fst(c->root))&&id(c->stageid,fst(c->stage))&&id(c->stageid,st(c->root,"stage"))&&id(c->srcid,st(c->root,"source"));
}
static int validate(struct capture *c,int full) {
 if(!protected(c))return 0;
 struct stat l=st(c->stage,"payload"),s=st(c->src,"payload");
 if(!S_ISREG(l.st_mode)||!id(l,c->pre)||!id(l,c->linked)||!id(s,l)||c->pre.st_nlink!=1||l.st_nlink!=2||s.st_nlink!=2)return 0;
 if(!stamp(c->pre,l,0)||!stamp(s,l,1)||!teq(c->before,tok(c->src,"payload"))||!teq(c->before,tok(c->stage,"payload")))return 0;
 return !full||stamp(c->linked,l,1);
}
static int acquire(struct capture *c) {
 if(!protected(c)||c->pre.st_nlink!=1||!c->before.valid)return 0;
 c->phase="INTENT";manifest(c);errno=0;int r=linkat(c->src,"payload",c->stage,"payload",0);int e=errno;
 printf("link_result=%d errno=%d\n",r,e);if(r)return 0;
 if(fsync(c->stage))die("stage sync");c->linked_ok=1;c->linked=st(c->stage,"payload");c->after=tok(c->stage,"payload");printf("capture_identity_match=%d nlink_before=%u nlink_linked=%u mtime_equal=%d ctime_equal=%d\n",id(c->pre,c->linked),c->pre.st_nlink,c->linked.st_nlink,timeeq(c->pre.st_mtimespec,c->linked.st_mtimespec),timeeq(c->pre.st_ctimespec,c->linked.st_ctimespec));c->phase="LINKED";manifest(c);return 1;
}
static void mutate(struct capture *c) { int f=openat(c->src,"payload",O_WRONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("actor open");if(pwrite(f,"MUTATED!",8,0)!=8||fsync(f))die("actor write");close(f); }
static void finish(struct capture *c,int clean) {
 if(clean) {
  require(validate(c,1),"cleanup revalidation");
  if(unlinkat(c->stage,"payload",0)||fsync(c->stage))die("owned unlink");
  struct stat s=st(c->src,"payload"),missing; require(id(s,c->pre)&&s.st_nlink==1,"completion identity/count");
  errno=0;require(fstatat(c->stage,"payload",&missing,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT,"completion absence");
  printf("completion_nlink=%u mtime_equal_initial=%d ctime_equal_initial=%d\n",s.st_nlink,timeeq(s.st_mtimespec,c->pre.st_mtimespec),timeeq(s.st_ctimespec,c->pre.st_ctimespec));
  c->phase="LINK_REMOVED";manifest(c);c->charge=0;c->phase="COMPLETE";manifest(c); /* synthetic stage reservation only, never Work checkout capacity */
 } else { c->phase="HELD";manifest(c); }
 printf("outcome=%s data_open_calls=%d data_bytes=%d capture_charge=%d link_retained=%d\n",clean?"COMPLETE":"HOLD",c->opens,c->bytes,c->charge,c->linked_ok&&!clean);
 close(c->src);close(c->stage);close(c->root);
}
static void read_capture(struct capture *c,int gap) {
 if(gap==16)mutate(c); /* exact final-check -> open counterexample */
 c->opens++;int f=openat(c->stage,"payload",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(f<0)die("data open");
 if(!stamp(c->linked,fst(f),1)||!S_ISREG(fst(f).st_mode)){printf("opened_stamp_changed=1 bytes_refused=1\n");close(f);return;}
 if(gap==18)mutate(c); /* ordinary source writer after final FD check, before read */
 char b[9]={0};ssize_t n=read(f,b,8);if(n<0)die("data read");c->bytes+=(int)n;close(f);printf("read=%s\n",b);
}
static void run(int top,const char *name,int mode) {
 printf("\nCASE %s\n",name);struct capture c=setup(top,name);
 if(mode==1){if(linkat(c.src,"payload",c.src,"user-link",0))die("foreign link");c.pre=st(c.src,"payload");}
 if(mode==2){if(renameat(c.src,"payload",c.src,"original")||mkdirat(c.src,"payload",0700))die("dir actor");}
 if(mode==3||mode==4){if(renameat(c.src,"payload",c.src,"original"))die("type actor");if(mode==3){if(mkfifoat(c.src,"payload",0600))die("fifo");}else if(symlinkat("original",c.src,"payload"))die("symlink");}
 if(mode==19){if(renameat(c.src,"payload",c.src,"original"))die("early regular replace");put(c.src,"payload","REPLACED");}
 if(mode==5){if(fchmod(c.stage,0755))die("stage chmod");}
 if(!acquire(&c)){require(mode==1||mode==2||mode==5,"expected acquisition refusal");finish(&c,0);return;}
 if(mode==6){if(renameat(c.src,"payload",c.src,"original"))die("replace");put(c.src,"payload","REPLACED");}
 if(mode==7)mutate(&c);
 if(mode==8){mutate(&c);int f=openat(c.src,"payload",O_WRONLY|O_NOFOLLOW);if(f<0)die("restore");if(pwrite(f,"ORIGINAL",8,0)!=8)die("restore write");close(f);struct timespec ts[2]={c.pre.st_atimespec,c.pre.st_mtimespec};if(utimensat(c.src,"payload",ts,AT_SYMLINK_NOFOLLOW))die("actor restore mtime");}
 if(mode==9){if(renameat(c.root,"stage",c.root,"stage-original")||mkdirat(c.root,"stage",0700))die("stage replace");}
 if(mode==10||mode==11){if(renameat(c.stage,"payload",c.stage,"owned-original"))die("link replace");if(mode==10){put(c.stage,"payload","FOREIGN!");if(linkat(c.stage,"payload",c.src,"user-foreign",0))die("foreign count2");}else if(mkfifoat(c.stage,"payload",0600))die("stage fifo");}
 if(mode==12){if(fchmod(c.stage,0755))die("late stage chmod");}
 if(mode==13){if(linkat(c.src,"payload",c.src,"user-link",0))die("late foreign link");}
 if(mode==14){if(renameat(c.src,"payload",c.src,"away")||renameat(c.src,"away",c.src,"payload"))die("path ABA");}
 if(mode==15){
  acl_t a=acl_init(1);acl_entry_t e;acl_permset_t perms;unsigned char synthetic_uuid[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  if(!a||acl_create_entry(&a,&e)||acl_set_tag_type(e,ACL_EXTENDED_ALLOW)||acl_set_qualifier(e,synthetic_uuid)||acl_get_permset(e,&perms)||acl_add_perm(perms,ACL_READ_DATA)||acl_set_permset(e,perms)||acl_set_fd_np(c.stage,a,ACL_TYPE_EXTENDED))die("acl actor");acl_free(a);
 }
 int valid=validate(&c,1);printf("pre_read_validation=%d gen_before=%u gen_linked=%u gen_now=%u\n",valid,c.before.generation,c.after.generation,tok(c.src,"payload").generation);
 if(!valid){require(mode!=0&&mode!=16&&mode!=17&&mode!=18,"stable validation");finish(&c,0);return;}
 if(mode==17){mutate(&c);valid=validate(&c,1);require(!valid,"second handoff gate");finish(&c,0);return;}
 require(mode==0||mode==16||mode==18,"negative case unexpectedly accepted");read_capture(&c,mode);int post=validate(&c,1);printf("post_read_validation=%d\n",post);
 require(post==(mode==0),"postvalidation expectation");finish(&c,post);
}
/* Separate process reinspection reads only a bounded synthetic manifest, not payload.
 * Historical records cannot promote a capture to active; even consistent evidence holds. */
static void reinspect(int top,const char *name) {
 int root=openat(top,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("reinspect root");
 int f=openat(root,"manifest",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0){printf("REINSPECT capture=%s manifest_unavailable=1 outcome=HOLD data_open_calls=0 data_bytes=0 unlinks=0 capture_charge=1\n",name);close(root);return;}struct stat ms=fst(f);
 require(S_ISREG(ms.st_mode)&&ms.st_nlink==1&&ms.st_uid==geteuid()&&(ms.st_mode&0777)==0600,"manifest safety");
 char b[2048]={0};ssize_t n=read(f,b,sizeof(b)-1);if(n<0||(size_t)n>=sizeof(b)-1)die("manifest bound");close(f);
 char capture[80],phase[32];int charge;unsigned long long rd,ri,sd,si,td,ti,pd,pi,ld,li;unsigned pn,ln;
 int count=sscanf(b,"THROWAWAY-HARDLINK-1 capture=%79s phase=%31s charge=%d\nroot=%llu:%llu source_dir=%llu:%llu stage=%llu:%llu\nentry=payload source=payload initial=%llu:%llu initial_nlink=%u linked=%llu:%llu linked_nlink=%u",capture,phase,&charge,&rd,&ri,&sd,&si,&td,&ti,&pd,&pi,&pn,&ld,&li,&ln);
 require(count==15,"fixed manifest parser");
 int stage=openat(root,"stage",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),src=openat(root,"source",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(stage<0||src<0)die("reinspect dirs");
 struct stat r=fst(root),s=fst(src),t=fst(stage),l=st(stage,"payload"),p=st(src,"payload");
 int consistent=private_dir(root)&&private_dir(stage)&&(unsigned long long)r.st_dev==rd&&r.st_ino==ri&&(unsigned long long)s.st_dev==sd&&s.st_ino==si&&(unsigned long long)t.st_dev==td&&t.st_ino==ti&&pd==ld&&pi==li&&(unsigned long long)l.st_dev==ld&&l.st_ino==li&&id(p,l)&&pn==1&&ln==2&&l.st_nlink==2;
 printf("REINSPECT capture=%s phase=%s identity_consistent=%d outcome=HOLD data_open_calls=0 data_bytes=0 unlinks=0 capture_charge=%d\n",capture,phase,consistent,charge);
 require(charge==1,"uncertain charge retained");close(stage);close(src);close(root);
}
int main(int argc,char **argv) {
 if(argc!=3)return 2;umask(077);int top=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(top<0)die("fixture");require(private_dir(top),"fixture private");
 if(!strcmp(argv[1],"run")) {
  struct statfs fs;if(fstatfs(top,&fs))die("filesystem");printf("filesystem=%s\n",fs.f_fstypename);
  const char *names[]={"clean","foreign-preexisting","directory-substitution","fifo-substitution","symlink-substitution","stage-mode-before","source-replaced","content-mutated","content-ABA","stage-replaced","link-replaced","link-fifo","stage-mode-after","foreign-added","path-ABA","stage-ACL","open-gap-counterexample","handoff-mutation","read-gap-counterexample","regular-substitution"};
  for(int i=0;i<20;i++)run(top,names[i],i);
 }else if(!strcmp(argv[1],"crash-linked")||!strcmp(argv[1],"crash-intent")||!strcmp(argv[1],"crash-untracked")) {
  struct capture c=setup(top,argv[1]);
  if(strcmp(argv[1],"crash-linked")){c.phase="INTENT";if(!strcmp(argv[1],"crash-intent"))manifest(&c);if(linkat(c.src,"payload",c.stage,"payload",0))die("unreceipted link");}
  else require(acquire(&c),"crash capture");
  printf("CONTROLLED_EXIT phase=%s link_left=1 charge=1\n",c.phase);fflush(stdout);_exit(70);
 }else if(!strcmp(argv[1],"reinspect-linked"))reinspect(top,"crash-linked");
 else if(!strcmp(argv[1],"reinspect-intent"))reinspect(top,"crash-intent");
 else if(!strcmp(argv[1],"reinspect-untracked"))reinspect(top,"crash-untracked");
 else if(!strcmp(argv[1],"replace-leftover-link")){
  int root=openat(top,"crash-linked",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("actor root");
  int stage=openat(root,"stage",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(stage<0)die("actor stage");
  if(renameat(stage,"payload",stage,"owned-original"))die("actor link rename");put(stage,"payload","FOREIGN!");if(linkat(stage,"payload",stage,"foreign-user-link",0))die("foreign leftover count2");close(stage);close(root);
 }else if(!strcmp(argv[1],"replace-leftover-stage")){
  int root=openat(top,"crash-linked",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)die("actor root");
  if(renameat(root,"stage",root,"stage-original")||mkdirat(root,"stage",0700))die("actor stage replace");
  int stage=openat(root,"stage",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(stage<0)die("actor new stage");put(stage,"payload","FOREIGN!");if(linkat(stage,"payload",stage,"foreign-user-link",0))die("foreign leftover count2");close(stage);close(root);
 }
 else return 2;close(top);return 0;
}
