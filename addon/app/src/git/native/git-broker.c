#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* Slice F source contract. Packaging and hostile Linux execution remain Slice G. */
#define REQUEST_HEADER 16U
#define MAX_REQUEST 16384U
#define MAX_OUTPUT (4U * 1024U * 1024U)
#define RESOLVE_POLICY (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)

#define MAX_RUNTIME_INPUTS 16U
#if defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error Unsupported broker architecture
#endif

static const unsigned char request_magic[7] = {'H','A','G','I','T','1','\0'};
static const unsigned char response_magic[8] = {'H','A','G','I','T','R','1','\0'};

static int open_beneath(int directory, const char *path, int flags) {
  struct open_how how = {.flags = (uint64_t)(flags | O_CLOEXEC), .resolve = RESOLVE_POLICY};
  return (int)syscall(SYS_openat2, directory, path, &how, sizeof(how));
}

static void limit_resources(void) {
  const struct rlimit cpu = {5, 5}, address = {256U * 1024U * 1024U, 256U * 1024U * 1024U};
  const struct rlimit file = {MAX_OUTPUT, MAX_OUTPUT}, descriptors = {32, 32}, processes = {8, 8};
  if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &address) ||
      setrlimit(RLIMIT_FSIZE, &file) || setrlimit(RLIMIT_NOFILE, &descriptors) ||
      setrlimit(RLIMIT_NPROC, &processes)) _exit(125);
}

static void exact_environment(const char *home,const char *tmp,const char *null_path) {
  if (clearenv() || setenv("LC_ALL", "C", 1) || setenv("HOME", home, 1) ||
      setenv("XDG_CONFIG_HOME", home, 1) || setenv("XDG_CACHE_HOME", home, 1) ||
      setenv("TMPDIR", tmp, 1) || setenv("GIT_CONFIG_NOSYSTEM", "1", 1) ||
      setenv("GIT_CONFIG_SYSTEM", null_path, 1) || setenv("GIT_CONFIG_GLOBAL", null_path, 1) ||
      setenv("GIT_TERMINAL_PROMPT", "0", 1) || setenv("GIT_OPTIONAL_LOCKS", "0", 1) ||
      setenv("GIT_PAGER", "cat", 1) || setenv("GIT_EXTERNAL_DIFF", "", 1) ||
      setenv("GIT_ASKPASS", "", 1) || setenv("SSH_ASKPASS", "", 1) ||
      setenv("GIT_SSH_COMMAND", "", 1) || setenv("GIT_NO_LAZY_FETCH", "1", 1) ||
      setenv("GIT_NO_REPLACE_OBJECTS", "1", 1) || setenv("GIT_LITERAL_PATHSPECS", "1", 1) ||
      setenv("GIT_ATTR_NOSYSTEM", "1", 1) || setenv("NO_PROXY", "*", 1) ||
      setenv("no_proxy", "*", 1)) _exit(125);
}

static void install_seccomp_isolation(int runtime_fd) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 6),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)runtime_fd, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AT_EMPTY_PATH, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  const struct sock_fprog program = {.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter};
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) _exit(125);
}

static int add_landlock_path(int ruleset, int fd, uint64_t access) {
  struct landlock_path_beneath_attr rule = {.allowed_access = access, .parent_fd = fd};
  return (int)syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
}

static void install_read_only_landlock(int root_fd,int git_fd,int runtime_fd,int loader_fd,int null_fd,const int *runtime_inputs,size_t runtime_count) {
  const uint64_t read = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  struct landlock_ruleset_attr attr = {.handled_access_fs = read | LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM};
  int ruleset = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if(ruleset<0||
      add_landlock_path(ruleset,root_fd,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR)||
      add_landlock_path(ruleset,git_fd,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR)||
      add_landlock_path(ruleset,runtime_fd,LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE)||
      add_landlock_path(ruleset,loader_fd,LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE)||
      add_landlock_path(ruleset,null_fd,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_WRITE_FILE))_exit(125);
  for(size_t index=0;index<runtime_count;index++)
    if(add_landlock_path(ruleset,runtime_inputs[index],LANDLOCK_ACCESS_FS_READ_FILE))_exit(125);
  if(syscall(SYS_landlock_restrict_self,ruleset,0))_exit(125);
  close(ruleset);
}

static char *trim(char *value){while(*value==' '||*value=='\t')value++;char *end=value+strlen(value);while(end>value&&(end[-1]==' '||end[-1]=='\t'||end[-1]=='\r'||end[-1]=='\n'))*--end='\0';return value;}
static void lowercase(char *value){for(;*value;value++)if(*value>='A'&&*value<='Z')*value=(char)(*value+('a'-'A'));}
static int section_base_is(const char *section,const char *base){size_t width=strcspn(section," .\t");return strlen(base)==width&&!strncmp(section,base,width);}
static int denied_section(const char *section){return section_base_is(section,"include")||section_base_is(section,"includeif")||section_base_is(section,"filter")||section_base_is(section,"diff")||section_base_is(section,"credential")||section_base_is(section,"http")||section_base_is(section,"url")||section_base_is(section,"remote")||section_base_is(section,"submodule")||section_base_is(section,"mailmap")||section_base_is(section,"maintenance")||section_base_is(section,"receive")||section_base_is(section,"uploadpack")||section_base_is(section,"protocol")||section_base_is(section,"alias")||section_base_is(section,"gpg");}
static int denied_config_key(const char *section,const char *key,const char *value){
  if(denied_section(section))return 1;
  if(!strcmp(section,"core")){if(!strcmp(key,"hookspath")||!strcmp(key,"fsmonitor")||!strcmp(key,"attributesfile")||!strcmp(key,"excludesfile")||!strcmp(key,"worktree")||!strcmp(key,"gitproxy")||!strcmp(key,"sshcommand")||!strcmp(key,"editor")||!strcmp(key,"pager"))return 1;if(!strcmp(key,"bare")&&strcmp(value,"false")&&strcmp(value,"no")&&strcmp(value,"0"))return 1;if(!strcmp(key,"repositoryformatversion")&&strcmp(value,"0")&&strcmp(value,"1"))return 1;}
  if(!strcmp(section,"extensions")&&(!strcmp(key,"worktreeconfig")||!strcmp(key,"partialclone")||!strcmp(key,"relativeworktrees")||!strcmp(key,"noopfetch")))return 1;
  if(strstr(key,"command")||strstr(key,"program")||strstr(key,"helper")||strstr(key,"proxy")||strstr(key,"askpass")||strstr(key,"promisor")||strstr(key,"partialclone")||strstr(key,"replace"))return 1;
  return 0;
}
static int validate_local_config(int config_fd) {
  int copy=dup(config_fd);if(copy<0||lseek(copy,0,SEEK_SET)<0){if(copy>=0)close(copy);return -1;}FILE *stream=fdopen(copy,"r");if(!stream){close(copy);return -1;}
  char *line=NULL;size_t capacity=0;ssize_t length;char section[256]="";int denied=0;
  while((length=getline(&line,&capacity,stream))>=0){if(length>4096){denied=1;break;}char *item=trim(line);if(!*item||*item=='#'||*item==';')continue;
    if(*item=='['){char *close=strrchr(item,']');if(!close||close[1]){denied=1;break;}*close='\0';item=trim(item+1);if(!*item||strlen(item)>=sizeof(section)){denied=1;break;}strcpy(section,item);lowercase(section);if(denied_section(section)){denied=1;break;}continue;}
    char *separator=strchr(item,'=');if(!separator||!*section){denied=1;break;}*separator='\0';char *key=trim(item),*value=trim(separator+1);lowercase(key);lowercase(value);if(!*key||denied_config_key(section,key,value)){denied=1;break;}
  }
  if(ferror(stream)){
    denied=1;
  }
  free(line);
  fclose(stream);
  return denied?-1:0;
}
static int require_regular_beneath(int directory, const char *path, dev_t device, int optional) {
  int fd = open_beneath(directory, path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) return optional && errno == ENOENT ? 0 : -1;
  struct stat metadata;
  int denied = fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_dev != device;
  close(fd);
  return denied ? -1 : 0;
}
static int sha256_fd(int fd,unsigned char out[32]);
static int absent_beneath(int directory,const char *path,int flags){int fd=open_beneath(directory,path,flags|O_NOFOLLOW);if(fd>=0){close(fd);return -1;}return errno==ENOENT?0:-1;}
static int file_contains(int directory,const char *path,const char *needle){int fd=open_beneath(directory,path,O_RDONLY|O_NOFOLLOW);if(fd<0)return errno==ENOENT?0:-1;char buffer[4096];size_t carry=0;ssize_t got=0;int found=0;while((got=read(fd,buffer+carry,sizeof(buffer)-carry-1))>0){size_t bytes=carry+(size_t)got;buffer[bytes]='\0';if(strstr(buffer,needle)){found=1;break;}carry=strlen(needle);if(carry>bytes)carry=bytes;memmove(buffer,buffer+bytes-carry,carry);}memset(buffer,0,sizeof(buffer));close(fd);return got<0?-1:found;}
static int no_promisor_packs(int objects_fd){int pack_fd=open_beneath(objects_fd,"pack",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(pack_fd<0)return errno==ENOENT?0:-1;int scan=dup(pack_fd);if(scan<0){close(pack_fd);return -1;}DIR *directory=fdopendir(scan);if(!directory){close(scan);close(pack_fd);return -1;}struct dirent *entry;int denied=0;errno=0;while((entry=readdir(directory))){size_t length=strlen(entry->d_name);if(length>9&&!strcmp(entry->d_name+length-9,".promisor")){denied=1;break;}}if(errno)denied=1;closedir(directory);close(pack_fd);return denied?-1:0;}
struct file_snapshot{int present;struct stat metadata;unsigned char digest[32];};
static int snapshot_file(int directory,const char *path,int required,struct file_snapshot *out){memset(out,0,sizeof(*out));int fd=open_beneath(directory,path,O_RDONLY|O_NOFOLLOW);if(fd<0)return !required&&errno==ENOENT?0:-1;out->present=1;int failed=fstat(fd,&out->metadata)||!S_ISREG(out->metadata.st_mode)||sha256_fd(fd,out->digest);close(fd);return failed?-1:0;}
static int same_timespec(struct timespec a,struct timespec b){return a.tv_sec==b.tv_sec&&a.tv_nsec==b.tv_nsec;}
static int same_file_snapshot(const struct file_snapshot *a,const struct file_snapshot *b){return a->present==b->present&&(!a->present||(a->metadata.st_dev==b->metadata.st_dev&&a->metadata.st_ino==b->metadata.st_ino&&a->metadata.st_mode==b->metadata.st_mode&&a->metadata.st_size==b->metadata.st_size&&same_timespec(a->metadata.st_mtim,b->metadata.st_mtim)&&same_timespec(a->metadata.st_ctim,b->metadata.st_ctim)&&!memcmp(a->digest,b->digest,32)));}
static int stable_directory(const struct stat *a,const struct stat *b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&same_timespec(a->st_mtim,b->st_mtim)&&same_timespec(a->st_ctim,b->st_ctim);}
static void wipe_snapshot(struct file_snapshot *value){memset(value,0,sizeof(*value));}

struct sha256_state { uint32_t h[8]; uint64_t bits; unsigned char block[64]; size_t used; };
static uint32_t rotr(uint32_t value, unsigned shift) { return (value >> shift) | (value << (32U - shift)); }
static void sha256_compress(struct sha256_state *state, const unsigned char *block) {
  static const uint32_t k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4U,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
  uint32_t w[64],a,b,c,d,e,f,g,h;
  for(unsigned i=0;i<16;i++)w[i]=((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|((uint32_t)block[i*4+2]<<8)|block[i*4+3];
  for(unsigned i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-16]+(rotr(y,17)^rotr(y,19)^(y>>10))+w[i-7];}
  a=state->h[0];b=state->h[1];c=state->h[2];d=state->h[3];e=state->h[4];f=state->h[5];g=state->h[6];h=state->h[7];
  for(unsigned i=0;i<64;i++){uint32_t t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+k[i]+w[i];uint32_t t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
  state->h[0]+=a;state->h[1]+=b;state->h[2]+=c;state->h[3]+=d;state->h[4]+=e;state->h[5]+=f;state->h[6]+=g;state->h[7]+=h;
}
static void sha256_init(struct sha256_state *s){static const uint32_t initial[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};memcpy(s->h,initial,sizeof(initial));s->bits=0;s->used=0;}
static void sha256_update(struct sha256_state *s,const unsigned char *data,size_t length){s->bits+=(uint64_t)length*8U;while(length){size_t take=64U-s->used;if(take>length)take=length;memcpy(s->block+s->used,data,take);s->used+=take;data+=take;length-=take;if(s->used==64U){sha256_compress(s,s->block);s->used=0;}}}
static void sha256_final(struct sha256_state *s,unsigned char out[32]){s->block[s->used++]=0x80;if(s->used>56){memset(s->block+s->used,0,64-s->used);sha256_compress(s,s->block);s->used=0;}memset(s->block+s->used,0,56-s->used);for(unsigned i=0;i<8;i++)s->block[63-i]=(unsigned char)(s->bits>>(i*8));sha256_compress(s,s->block);for(unsigned i=0;i<8;i++){out[i*4]=(unsigned char)(s->h[i]>>24);out[i*4+1]=(unsigned char)(s->h[i]>>16);out[i*4+2]=(unsigned char)(s->h[i]>>8);out[i*4+3]=(unsigned char)s->h[i];}memset(s,0,sizeof(*s));}
static int sha256_fd(int fd,unsigned char out[32]){struct sha256_state state;unsigned char buffer[4096];ssize_t got;if(lseek(fd,0,SEEK_SET)<0)return -1;sha256_init(&state);while((got=read(fd,buffer,sizeof(buffer)))>0)sha256_update(&state,buffer,(size_t)got);memset(buffer,0,sizeof(buffer));if(got<0)return -1;sha256_final(&state,out);return 0;}
static int read_exact(int fd,void *buffer,size_t length){unsigned char *cursor=buffer;while(length){ssize_t got=read(fd,cursor,length);if(got<=0)return -1;cursor+=(size_t)got;length-=(size_t)got;}return 0;}
static int write_exact(int fd,const void *buffer,size_t length){const unsigned char *cursor=buffer;while(length){ssize_t sent=write(fd,cursor,length);if(sent<=0)return -1;cursor+=(size_t)sent;length-=(size_t)sent;}return 0;}
static void put32(unsigned char *p,uint32_t value){p[0]=(unsigned char)(value>>24);p[1]=(unsigned char)(value>>16);p[2]=(unsigned char)(value>>8);p[3]=(unsigned char)value;}
static void put64(unsigned char *p,uint64_t value){for(unsigned i=0;i<8;i++)p[7-i]=(unsigned char)(value>>(i*8));}
static int clear_cloexec_for_child(int fd){int flags=fcntl(fd,F_GETFD);return flags<0||fcntl(fd,F_SETFD,flags&~FD_CLOEXEC)<0?-1:0;}
static int run_git(int runtime_fd,int root_fd,int git_fd,int null_fd,char *const argv[],const unsigned char *input,size_t input_bytes,unsigned char **output,size_t *output_bytes){
  int in_pipe[2],out_pipe[2],err_pipe[2];
  if(pipe2(in_pipe,O_CLOEXEC)||pipe2(out_pipe,O_CLOEXEC)||pipe2(err_pipe,O_CLOEXEC))return -1;
  int execute_fd=fcntl(runtime_fd,F_DUPFD_CLOEXEC,3);if(execute_fd<0){close(in_pipe[0]);close(in_pipe[1]);close(out_pipe[0]);close(out_pipe[1]);close(err_pipe[0]);close(err_pipe[1]);return -1;}
  pid_t child=fork();
  if(child<0){close(execute_fd);close(in_pipe[0]);close(in_pipe[1]);close(out_pipe[0]);close(out_pipe[1]);close(err_pipe[0]);close(err_pipe[1]);return -1;}
  if(child==0){
    if(dup2(in_pipe[0],STDIN_FILENO)<0||dup2(out_pipe[1],STDOUT_FILENO)<0||dup2(err_pipe[1],STDERR_FILENO)<0)_exit(126);
    close(in_pipe[0]);close(in_pipe[1]);close(out_pipe[0]);close(out_pipe[1]);close(err_pipe[0]);close(err_pipe[1]);
    if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()==1)_exit(126);
    if(clear_cloexec_for_child(root_fd)||clear_cloexec_for_child(git_fd)||clear_cloexec_for_child(null_fd))_exit(126);
    install_seccomp_isolation(execute_fd);
    syscall(SYS_execveat,execute_fd,"",argv,environ,AT_EMPTY_PATH);
    _exit(126);
  }
  close(in_pipe[0]);close(out_pipe[1]);close(err_pipe[1]);
  close(execute_fd);
  int failed=0;
  if(input_bytes&&(write_exact(in_pipe[1],input,input_bytes)||write_exact(in_pipe[1],"\n",1)))failed=1;
  close(in_pipe[1]);
  unsigned char *result=malloc(MAX_OUTPUT);
  size_t used=0,diagnostics=0;
  if(!result)failed=1;
  int out_open=1,err_open=1;
  while(!failed&&(out_open||err_open)){
    struct pollfd streams[2]={
      {.fd=out_open?out_pipe[0]:-1,.events=POLLIN|POLLHUP},
      {.fd=err_open?err_pipe[0]:-1,.events=POLLIN|POLLHUP}
    };
    int ready;
    do{ready=poll(streams,2,-1);}while(ready<0&&errno==EINTR);
    if(ready<0){failed=1;break;}
    if(streams[0].revents&(POLLERR|POLLNVAL)){failed=1;break;}
    if(streams[0].revents&(POLLIN|POLLHUP)){
      unsigned char extra;
      void *target=used<MAX_OUTPUT?(void *)(result+used):(void *)&extra;
      size_t capacity=used<MAX_OUTPUT?MAX_OUTPUT-used:1;
      ssize_t got=read(out_pipe[0],target,capacity);
      if(got<0&&errno!=EINTR){failed=1;break;}
      if(got==0)out_open=0;
      else if(got>0){if(used==MAX_OUTPUT){memset(&extra,0,sizeof(extra));failed=1;break;}used+=(size_t)got;}
    }
    if(streams[1].revents&(POLLERR|POLLNVAL)){failed=1;break;}
    if(streams[1].revents&(POLLIN|POLLHUP)){
      unsigned char errors[512];
      ssize_t got=read(err_pipe[0],errors,sizeof(errors));
      if(got<0&&errno!=EINTR){failed=1;break;}
      if(got==0)err_open=0;
      else if(got>0){diagnostics+=(size_t)got;memset(errors,0,(size_t)got);if(diagnostics>4096){failed=1;break;}}
    }
  }
  if(failed)kill(child,SIGKILL);
  close(out_pipe[0]);close(err_pipe[0]);
  int status;
  pid_t waited;
  do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
  if(waited<0||!WIFEXITED(status)||WEXITSTATUS(status)!=0)failed=1;
  if(failed){if(result){memset(result,0,MAX_OUTPUT);free(result);}return -1;}
  *output=result;*output_bytes=used;return 0;
}
static int write_response(uint32_t status,const struct stat *root,const struct stat *git,const unsigned char head[32],const unsigned char index[32],const unsigned char *payload,size_t payload_bytes){unsigned char header[128]={0};memcpy(header,response_magic,8);put32(header+8,1);put32(header+12,status);if(status==0){put64(header+24,(uint64_t)root->st_dev);put64(header+32,(uint64_t)root->st_ino);put64(header+40,(uint64_t)git->st_dev);put64(header+48,(uint64_t)git->st_ino);memcpy(header+56,head,32);memcpy(header+88,index,32);put32(header+120,(uint32_t)payload_bytes);}if(write_exact(STDOUT_FILENO,header,sizeof(header)))return -1;if(status==0&&payload_bytes&&write_exact(STDOUT_FILENO,payload,payload_bytes))return -1;memset(header,0,sizeof(header));return 0;}
static int valid_object_payload(const unsigned char *payload,size_t bytes){if(!bytes)return -1;size_t start=0,width=0,count=0;for(size_t i=0;i<=bytes;i++){if(i==bytes||payload[i]=='\n'){size_t length=i-start;if(!width)width=length;if((width!=40&&width!=64)||length!=width||++count>200)return -1;for(size_t j=start;j<i;j++)if(!((payload[j]>='0'&&payload[j]<='9')||(payload[j]>='a'&&payload[j]<='f')))return -1;start=i+1;}else if(payload[i]=='\0'||payload[i]=='\r')return -1;}return 0;}
static int append_common(char **argv,size_t *used,const char *git_path,const char *git_dir,const char *work_tree,const char *safe){argv[(*used)++]=(char*)git_path;argv[(*used)++]="--no-pager";argv[(*used)++]=(char*)git_dir;argv[(*used)++]=(char*)work_tree;argv[(*used)++]="-c";argv[(*used)++]=(char*)safe;static char *fixed[]={"-c","core.hooksPath=/dev/null","-c","core.fsmonitor=false","-c","core.attributesFile=/dev/null","-c","core.excludesFile=/dev/null","-c","diff.external=","-c","diff.trustExitCode=false","-c","filter.lfs.required=false","-c","credential.helper=","-c","protocol.file.allow=never","-c","protocol.allow=never","-c","fetch.writeCommitGraph=false"};for(size_t i=0;i<sizeof(fixed)/sizeof(fixed[0]);i++)argv[(*used)++]=fixed[i];return 0;}
static int validate_batch_check(const unsigned char *output,size_t bytes,size_t expected){size_t lines=0,start=0;for(size_t i=0;i<bytes;i++)if(output[i]=='\n'){size_t length=i-start;if(length<48||length>90)return -1;char line[96];memcpy(line,output+start,length);line[length]='\0';char object[65],type[16],extra;unsigned long size;if(sscanf(line,"%64s %15s %lu %c",object,type,&size,&extra)!=3||strcmp(type,"blob")||size>512U*1024U)return -1;lines++;start=i+1;}return start==bytes&&lines==expected?0:-1;}
static int canonicalize_batch(unsigned char *raw,size_t raw_bytes,unsigned char **canonical,size_t *canonical_bytes,size_t expected){unsigned char *result=malloc(raw_bytes);if(!result)return -1;size_t in=0,out=0,records=0;while(in<raw_bytes){size_t end=in;while(end<raw_bytes&&raw[end]!='\n'&&end-in<=90)end++;if(end==raw_bytes||end-in>90)goto fail;char header[96],object[65],extra;unsigned long size;memcpy(header,raw+in,end-in);header[end-in]='\0';if(sscanf(header,"%64s %lu %c",object,&size,&extra)!=2||size>512U*1024U||end+1+size>=raw_bytes||raw[end+1+size]!='\n')goto fail;int written=snprintf((char*)result+out,raw_bytes-out,"%s %lu\n",object,size);if(written<0||(size_t)written>=raw_bytes-out)goto fail;out+=(size_t)written;memcpy(result+out,raw+end+1,size);out+=size;in=end+1+size+1;records++;}if(records!=expected)goto fail;*canonical=result;*canonical_bytes=out;return 0;fail:memset(result,0,raw_bytes);free(result);return -1;}
static void empty_sha256(unsigned char out[32]){struct sha256_state state;sha256_init(&state);sha256_final(&state,out);}
static int same_identity(const struct stat *left,const struct stat *right){return left->st_dev==right->st_dev&&left->st_ino==right->st_ino;}
int main(int argc, char **argv) {
  if(argc<8||strcmp(argv[1],"--protocol-v1")||strcmp(argv[2],"--git")||argv[3][0]!='/'||strcmp(argv[4],"--root")||argv[5][0]!='/'||strcmp(argv[6],"--runtime-loader")||argv[7][0]!='/'||(argc-8)%2)return 125;
  size_t runtime_count=(size_t)(argc-8)/2;if(runtime_count>MAX_RUNTIME_INPUTS)return 125;for(size_t i=0;i<runtime_count;i++)if(strcmp(argv[8+i*2],"--runtime-input")||argv[9+i*2][0]!='/')return 125;
  unsigned char header[REQUEST_HEADER],trailing;
  if(read_exact(STDIN_FILENO,header,sizeof(header))||memcmp(header,request_magic,sizeof(request_magic))||header[12]||header[13]||header[14]||header[15])return 125;
  unsigned operation=header[7];uint32_t payload_bytes=((uint32_t)header[8]<<24)|((uint32_t)header[9]<<16)|((uint32_t)header[10]<<8)|header[11];
  if(operation<1||operation>5||payload_bytes>MAX_REQUEST||(operation!=5&&payload_bytes)||(!payload_bytes&&operation==5))return 125;
  unsigned char *payload=payload_bytes?malloc(payload_bytes):NULL;if(payload_bytes&&(!payload||read_exact(STDIN_FILENO,payload,payload_bytes)))return 125;
  if(read(STDIN_FILENO,&trailing,1)!=0||(operation==5&&valid_object_payload(payload,payload_bytes)))return 125;
  int root_fd=open(argv[5],O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(root_fd<0){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}
  int git_fd=open_beneath(root_fd,".git",O_PATH|O_DIRECTORY|O_NOFOLLOW);if(git_fd<0){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}
  int config_fd=open_beneath(git_fd,"config",O_RDONLY|O_NOFOLLOW),objects_fd=open_beneath(git_fd,"objects",O_PATH|O_DIRECTORY|O_NOFOLLOW),runtime_fd=open(argv[3],O_PATH|O_CLOEXEC|O_NOFOLLOW),loader_fd=open(argv[7],O_PATH|O_CLOEXEC|O_NOFOLLOW),null_fd=open("/dev/null",O_RDWR|O_CLOEXEC|O_NOFOLLOW),runtime_inputs[MAX_RUNTIME_INPUTS];
  for(size_t i=0;i<runtime_count;i++)runtime_inputs[i]=open(argv[9+i*2],O_PATH|O_CLOEXEC|O_NOFOLLOW);
  struct stat root_before,git_before,root_after,git_after,runtime_metadata,loader_metadata,input_metadata[MAX_RUNTIME_INPUTS];if(config_fd<0||objects_fd<0||runtime_fd<0||loader_fd<0||null_fd<0||fstat(root_fd,&root_before)||fstat(git_fd,&git_before)||fstat(runtime_fd,&runtime_metadata)||!S_ISREG(runtime_metadata.st_mode)||fstat(loader_fd,&loader_metadata)||!S_ISREG(loader_metadata.st_mode)){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}for(size_t i=0;i<runtime_count;i++){if(runtime_inputs[i]<0||fstat(runtime_inputs[i],&input_metadata[i])||!S_ISREG(input_metadata[i].st_mode)||same_identity(&loader_metadata,&input_metadata[i])){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}for(size_t j=0;j<i;j++)if(same_identity(&input_metadata[j],&input_metadata[i])){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}}
  if(validate_local_config(config_fd)||require_regular_beneath(git_fd,"HEAD",git_before.st_dev,0)||require_regular_beneath(git_fd,"index",git_before.st_dev,1)||require_regular_beneath(git_fd,"packed-refs",git_before.st_dev,1)||absent_beneath(git_fd,"commondir",O_RDONLY)||absent_beneath(git_fd,"gitdir",O_RDONLY)||absent_beneath(git_fd,"modules",O_PATH|O_DIRECTORY)||absent_beneath(git_fd,"shallow",O_RDONLY)||absent_beneath(git_fd,"refs/replace",O_PATH)||absent_beneath(objects_fd,"info/alternates",O_RDONLY)||absent_beneath(objects_fd,"info/http-alternates",O_RDONLY)||file_contains(git_fd,"packed-refs","refs/replace/")||no_promisor_packs(objects_fd)){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}
  struct file_snapshot head_before,index_before,config_before,packed_before;if(snapshot_file(git_fd,"HEAD",1,&head_before)||snapshot_file(git_fd,"index",0,&index_before)||snapshot_file(git_fd,"config",1,&config_before)||snapshot_file(git_fd,"packed-refs",0,&packed_before)){write_response(1,NULL,NULL,NULL,NULL,NULL,0);return 0;}
  unsigned char head_digest[32],index_digest[32];memcpy(head_digest,head_before.digest,32);if(index_before.present)memcpy(index_digest,index_before.digest,32);else empty_sha256(index_digest);
  char home_path[64],null_path[64];snprintf(home_path,sizeof(home_path),"/proc/self/fd/%d",root_fd);snprintf(null_path,sizeof(null_path),"/proc/self/fd/%d",null_fd);
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){write_response(4,NULL,NULL,NULL,NULL,NULL,0);return 0;}limit_resources();exact_environment(home_path,home_path,null_path);install_read_only_landlock(root_fd,git_fd,runtime_fd,loader_fd,null_fd,runtime_inputs,runtime_count);if(fchdir(root_fd)){write_response(1,NULL,NULL,NULL,NULL,NULL,0);return 0;}
  char git_dir[64],work_tree[64],safe[80];snprintf(git_dir,sizeof(git_dir),"--git-dir=/proc/self/fd/%d",git_fd);snprintf(work_tree,sizeof(work_tree),"--work-tree=/proc/self/fd/%d",root_fd);snprintf(safe,sizeof(safe),"safe.directory=/proc/self/fd/%d",root_fd);
  char *git_argv[64];size_t used=0;append_common(git_argv,&used,argv[3],git_dir,work_tree,safe);
  if(operation==1){git_argv[used++]="status";git_argv[used++]="--porcelain=v2";git_argv[used++]="-z";git_argv[used++]="--branch";git_argv[used++]="--untracked-files=all";git_argv[used++]="--ignore-submodules=all";git_argv[used++]="--no-renames";git_argv[used++]="--no-ahead-behind";}
  else if(operation==2){git_argv[used++]="rev-parse";git_argv[used++]="--show-object-format";}
  else if(operation==3){git_argv[used++]="ls-files";git_argv[used++]="--stage";git_argv[used++]="-z";git_argv[used++]="--";}
  else if(operation==4){git_argv[used++]="ls-tree";git_argv[used++]="-rz";git_argv[used++]="--full-tree";git_argv[used++]="HEAD";git_argv[used++]="--";}
  else {git_argv[used++]="cat-file";git_argv[used++]="--batch=%(objectname) %(objectsize)";}
  git_argv[used]=NULL;unsigned char *output=NULL;size_t output_bytes=0;int failed=0;
  if(operation==5){size_t expected=1;for(size_t i=0;i<payload_bytes;i++)if(payload[i]=='\n')expected++;char *check_argv[64];size_t check_used=0;append_common(check_argv,&check_used,argv[3],git_dir,work_tree,safe);check_argv[check_used++]="cat-file";check_argv[check_used++]="--batch-check=%(objectname) %(objecttype) %(objectsize)";check_argv[check_used]=NULL;unsigned char *check=NULL;size_t check_bytes=0;if(run_git(runtime_fd,root_fd,git_fd,null_fd,check_argv,payload,payload_bytes,&check,&check_bytes)||validate_batch_check(check,check_bytes,expected))failed=1;if(check){memset(check,0,check_bytes);free(check);}if(!failed){unsigned char *raw=NULL;size_t raw_bytes=0;if(run_git(runtime_fd,root_fd,git_fd,null_fd,git_argv,payload,payload_bytes,&raw,&raw_bytes)||canonicalize_batch(raw,raw_bytes,&output,&output_bytes,expected))failed=1;if(raw){memset(raw,0,raw_bytes);free(raw);}}}
  else if(run_git(runtime_fd,root_fd,git_fd,null_fd,git_argv,NULL,0,&output,&output_bytes))failed=1;
  close(runtime_fd);close(loader_fd);if(payload){memset(payload,0,payload_bytes);free(payload);}for(size_t i=0;i<runtime_count;i++)close(runtime_inputs[i]);close(null_fd);
  struct file_snapshot head_after,index_after,config_after,packed_after;int post_config_fd=open_beneath(git_fd,"config",O_RDONLY|O_NOFOLLOW);
  if(fstat(root_fd,&root_after)||fstat(git_fd,&git_after)||!stable_directory(&root_before,&root_after)||!stable_directory(&git_before,&git_after)||snapshot_file(git_fd,"HEAD",1,&head_after)||snapshot_file(git_fd,"index",0,&index_after)||snapshot_file(git_fd,"config",1,&config_after)||snapshot_file(git_fd,"packed-refs",0,&packed_after)||!same_file_snapshot(&head_before,&head_after)||!same_file_snapshot(&index_before,&index_after)||!same_file_snapshot(&config_before,&config_after)||!same_file_snapshot(&packed_before,&packed_after)||post_config_fd<0||validate_local_config(post_config_fd)||absent_beneath(git_fd,"commondir",O_RDONLY)||absent_beneath(git_fd,"gitdir",O_RDONLY)||absent_beneath(git_fd,"modules",O_PATH|O_DIRECTORY)||absent_beneath(git_fd,"shallow",O_RDONLY)||absent_beneath(git_fd,"refs/replace",O_PATH)||absent_beneath(objects_fd,"info/alternates",O_RDONLY)||absent_beneath(objects_fd,"info/http-alternates",O_RDONLY)||file_contains(git_fd,"packed-refs","refs/replace/")||no_promisor_packs(objects_fd)){
    failed=1;
  }
  if(post_config_fd>=0){
    close(post_config_fd);
  }
  int result=failed?write_response(1,NULL,NULL,NULL,NULL,NULL,0):write_response(0,&root_after,&git_after,head_digest,index_digest,output,output_bytes);if(output){memset(output,0,output_bytes);free(output);}memset(head_digest,0,sizeof(head_digest));memset(index_digest,0,sizeof(index_digest));
  wipe_snapshot(&head_before);wipe_snapshot(&index_before);wipe_snapshot(&config_before);wipe_snapshot(&packed_before);wipe_snapshot(&head_after);wipe_snapshot(&index_after);wipe_snapshot(&config_after);wipe_snapshot(&packed_after);return result?125:0;
}