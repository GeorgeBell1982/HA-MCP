#define _GNU_SOURCE
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#define STATUS_DENIED 1
#define STATUS_UNAVAILABLE 4
#define MAX_VISITED 4096
#define MAX_DEPTH 64
#define MAX_FILES 2000
#define MAX_PATH_BYTES 512
#define MAX_OUTPUT (2*1024*1024)
#define RECORD_FIXED 60
static const char *EXCLUDED[]={".git",".storage","deps","node_modules","__pycache__",".cache",NULL};
struct record { unsigned char type; char *path; struct stat st; };
static struct record rows[MAX_VISITED+MAX_FILES]; static size_t rows_n,dirs_n,files_n; static int root_fd; static const char *root_path; static dev_t root_dev; static ino_t root_ino;
static void put32(unsigned char *p,uint32_t v){v=htobe32(v);memcpy(p,&v,4);} static void put64(unsigned char *p,uint64_t v){v=htobe64(v);memcpy(p,&v,8);}
static int fail(unsigned s,int e){unsigned char h[48]={0};memcpy(h,"HALIST2\0",8);put32(h+8,1);put32(h+12,s);put32(h+44,(uint32_t)e);(void)write(1,h,48);return 2;}
static int excluded(const char *n){for(size_t i=0;EXCLUDED[i];++i)if(!strcmp(n,EXCLUDED[i]))return 1;return 0;}
static int valid_name(const char *n){if(!*n||!strcmp(n,".")||!strcmp(n,".."))return 0;for(const unsigned char*p=(const unsigned char*)n;*p;++p)if(*p=='/'||*p=='\\'||*p==':'||*p<32||*p==127)return 0;return 1;}
static int depth(const char*p){int d=1;for(;*p;++p)if(*p=='/')++d;return d;}
static int yaml(const char*p){size_t n=strlen(p);return(n>=5&&!strcmp(p+n-5,".yaml"))||(n>=4&&!strcmp(p+n-4,".yml"));}
static int open_secure(const char*p,int flags){struct open_how h={.flags=(uint64_t)(flags|O_CLOEXEC|O_NOFOLLOW),.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};return(int)syscall(SYS_openat2,root_fd,p,&h,sizeof(h));}
static int add(unsigned char type,const char*p,const struct stat*s){if(rows_n>=MAX_VISITED+MAX_FILES||strlen(p)>MAX_PATH_BYTES)return-1;if(type==1&&++dirs_n>MAX_VISITED)return-1;if(type==2&&++files_n>MAX_FILES)return-1;rows[rows_n]=(struct record){type,strdup(p),*s};return rows[rows_n++].path?0:-1;}
static int join(char*out,const char*parent,const char*name){int n=parent[0]?snprintf(out,MAX_PATH_BYTES+1,"%s/%s",parent,name):snprintf(out,MAX_PATH_BYTES+1,"%s",name);return n>0&&n<=MAX_PATH_BYTES&&depth(out)<=MAX_DEPTH?0:-1;}
static int walk(const char*path){int fd=open_secure(path[0]?path:".",O_RDONLY|O_DIRECTORY);struct stat before;if(fd<0||fstat(fd,&before)||!S_ISDIR(before.st_mode))return-1;DIR*d=fdopendir(fd);if(!d){close(fd);return-1;}errno=0;for(struct dirent*e=readdir(d);e;e=readdir(d)){if(!valid_name(e->d_name)||excluded(e->d_name))continue;char child[MAX_PATH_BYTES+1];if(join(child,path,e->d_name)){closedir(d);return-1;}struct stat seen;if(fstatat(dirfd(d),e->d_name,&seen,AT_SYMLINK_NOFOLLOW)){closedir(d);return-1;}int c=open_secure(child,S_ISDIR(seen.st_mode)?O_RDONLY|O_DIRECTORY:O_PATH);if(c<0){int x=errno;if(x==ELOOP||x==EXDEV){errno=0;continue;}closedir(d);errno=x;return-1;}struct stat opened;if(fstat(c,&opened)||opened.st_dev!=seen.st_dev||opened.st_ino!=seen.st_ino){close(c);closedir(d);return-1;}close(c);if(S_ISDIR(opened.st_mode)){if(add(1,child,&opened)||walk(child)){closedir(d);return-1;}}else if(S_ISREG(opened.st_mode)){if(yaml(child)&&add(2,child,&opened)){closedir(d);return-1;}}/* descriptor-proven nonregular skips */errno=0;}if(errno){closedir(d);return-1;}int again=open_secure(path[0]?path:".",O_RDONLY|O_DIRECTORY);struct stat after;int ok=again>=0&&!fstat(again,&after)&&after.st_dev==before.st_dev&&after.st_ino==before.st_ino&&after.st_mtim.tv_sec==before.st_mtim.tv_sec&&after.st_mtim.tv_nsec==before.st_mtim.tv_nsec&&after.st_ctim.tv_sec==before.st_ctim.tv_sec&&after.st_ctim.tv_nsec==before.st_ctim.tv_nsec;if(again>=0)close(again);closedir(d);return ok?0:-1;}
static int cmp(const void*a,const void*b){return strcmp(((const struct record*)a)->path,((const struct record*)b)->path);}
static int emit(void){qsort(rows,rows_n,sizeof(rows[0]),cmp);size_t payload=0;for(size_t i=0;i<rows_n;++i)payload+=RECORD_FIXED+strlen(rows[i].path);if(payload+48>MAX_OUTPUT)return-1;unsigned char h[48]={0};memcpy(h,"HALIST2\0",8);put32(h+8,1);put64(h+16,root_dev);put64(h+24,root_ino);put32(h+32,(uint32_t)dirs_n);put32(h+36,(uint32_t)files_n);put32(h+40,(uint32_t)payload);if(write(1,h,48)!=48)return-1;for(size_t i=0;i<rows_n;++i){unsigned char f[60]={0};size_t n=strlen(rows[i].path);f[0]=rows[i].type;uint16_t p=htobe16((uint16_t)n);memcpy(f+2,&p,2);put64(f+4,rows[i].st.st_dev);put64(f+12,rows[i].st.st_ino);put64(f+20,rows[i].type==1?0:(uint64_t)rows[i].st.st_size);put64(f+28,rows[i].st.st_mtim.tv_sec);put64(f+36,rows[i].st.st_mtim.tv_nsec);put64(f+44,rows[i].st.st_ctim.tv_sec);put64(f+52,rows[i].st.st_ctim.tv_nsec);if(write(1,f,60)!=60||write(1,rows[i].path,n)!=(ssize_t)n)return-1;}return 0;}
int main(int argc,char**argv){if(argc!=3||strcmp(argv[1],"--root")||argv[2][0]!='/')return fail(STATUS_DENIED,EINVAL);root_path=argv[2];root_fd=open(root_path,O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat before;if(root_fd<0||fstat(root_fd,&before))return fail(STATUS_DENIED,errno);root_dev=before.st_dev;root_ino=before.st_ino;if(walk("")){int e=errno;return fail(e==ENOSYS||e==E2BIG||e==EINVAL||e==EPERM?STATUS_UNAVAILABLE:STATUS_DENIED,e);}struct stat by_path,by_fd;if(stat(root_path,&by_path)||fstat(root_fd,&by_fd)||by_path.st_dev!=root_dev||by_path.st_ino!=root_ino||by_fd.st_dev!=root_dev||by_fd.st_ino!=root_ino)return fail(STATUS_DENIED,ESTALE);int rc=emit()?fail(STATUS_DENIED,EOVERFLOW):0;for(size_t i=0;i<rows_n;++i)free(rows[i].path);close(root_fd);return rc;}