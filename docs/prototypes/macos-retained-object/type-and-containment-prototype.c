/* THROWAWAY native macOS probe; synthetic scratch objects only.
 * Does not establish production safety, race freedom, or Rust API coverage.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void die(const char *s) { perror(s); exit(1); }
static void file(int root, const char *name, mode_t mode) {
    int fd=openat(root,name,O_WRONLY|O_CREAT|O_EXCL,mode);
    if(fd<0) die("create");
    if(write(fd,"SYNTHETIC",9)!=9) die("write");
    close(fd);
}
static void probe(const char *label,int root,const char *path,int flags) {
    errno=0; int fd=openat(root,path,flags|O_CLOEXEC); int e=errno;
    printf("%s path=%s flags=0x%x result=%d errno=%d (%s)",label,path,flags,fd,e,strerror(e));
    if(fd>=0) {
        struct stat st; if(fstat(fd,&st))die("fstat");
        printf(" type=%o inode=%llu actual_flags=0x%x",st.st_mode&S_IFMT,(unsigned long long)st.st_ino,fcntl(fd,F_GETFL));
        close(fd);
    }
    printf("\n");
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0)die("root");
    file(root,"plain",0600); file(root,"executable",0700);
    if(mkfifoat(root,"fifo",0600))die("fifo");
    if(mkdirat(root,"directory",0700))die("mkdir");
    if(symlinkat("plain",root,"link"))die("link");
    int sock=socket(AF_UNIX,SOCK_STREAM,0); if(sock<0)die("socket");
    struct sockaddr_un sa={0};sa.sun_family=AF_UNIX;
    if(fchdir(root))die("fixture cwd");
    memcpy(sa.sun_path,"socket",sizeof("socket"));
    if(bind(sock,(struct sockaddr *)&sa,sizeof(sa)))die("bind");
    const char *names[]={"plain","executable","fifo","socket","link","directory"};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        probe("event-only",root,names[i],O_EVTONLY|O_NONBLOCK|O_NOFOLLOW);
        probe("execute-only",root,names[i],O_EXEC|O_NONBLOCK|O_NOFOLLOW);
    }
    int strict=O_RDONLY|O_NOFOLLOW_ANY|O_RESOLVE_BENEATH;
    probe("containment regular",root,"plain",strict);
    probe("containment symlink",root,"link",strict);
    probe("containment parent escape",root,"../outside-synthetic",strict);
    char absolute[1024];
    snprintf(absolute,sizeof(absolute),"%s/plain",argv[1]);
    probe("containment absolute",root,absolute,strict);
    if(mkdirat(root,"anchor",0700))die("mkdir anchor");
    int anchor=openat(root,"anchor",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(anchor<0)die("anchor");
    file(anchor,"anchored",0600);
    if(renameat(root,"anchor",root,"../moved-anchor"))die("move anchor within scratch");
    probe("root lookup moved anchor",root,"anchor/anchored",strict);
    probe("retained anchor now outside root",anchor,"anchored",strict);
    close(anchor);close(sock);close(root);return 0;
}
