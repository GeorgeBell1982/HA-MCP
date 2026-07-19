#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int (*open64_fn)(const char *path, int flags, ...);
typedef int (*openat64_fn)(int directory, const char *path, int flags, ...);
typedef int (*renameat2_fn)(int old_directory, const char *old_path,
                            int new_directory, const char *new_path,
                            unsigned int flags);

static void arm(const char *path) {
  int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  if (fd < 0 || syscall(SYS_write, fd, "armed", 5) != 5 || syscall(SYS_close, fd)) exit(3);
}
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  const char *name = argv[1], *path = argv[2], *arm_path = argv[3];
  char rename_path[PATH_MAX];
  int rename_length = snprintf(rename_path, sizeof(rename_path), "%s.renamed", path);
  if (rename_length < 0 || (size_t)rename_length >= sizeof(rename_path)) return 3;
  int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_CREAT | O_RDWR | O_TRUNC, 0600);
  if (fd < 0) return 3;
  arm(arm_path);
  char bytes[] = "0123456789"; struct iovec vectors[2] = {{bytes, 5}, {bytes + 5, 5}};
  int failed = 0;
  if (!strcmp(name, "open")) failed = open(path, O_RDONLY) < 0;
  else if (!strcmp(name, "open64")) failed = ((open64_fn)dlsym(RTLD_DEFAULT, "open64"))(path, O_RDONLY) < 0;
  else if (!strcmp(name, "openat")) failed = openat(AT_FDCWD, path, O_RDONLY) < 0;
  else if (!strcmp(name, "openat64")) failed = ((openat64_fn)dlsym(RTLD_DEFAULT, "openat64"))(AT_FDCWD, path, O_RDONLY) < 0;
  else if (!strcmp(name, "write")) { ssize_t got = write(fd, bytes, sizeof(bytes)); failed = got < 0 || got < (ssize_t)sizeof(bytes); }
  else if (!strcmp(name, "pwrite")) { ssize_t got = pwrite(fd, bytes, sizeof(bytes), 0); failed = got < 0 || got < (ssize_t)sizeof(bytes); }
  else if (!strcmp(name, "writev")) { ssize_t got = writev(fd, vectors, 2); failed = got < 0 || got < 10; }
  else if (!strcmp(name, "fsync")) failed = fsync(fd) < 0;
  else if (!strcmp(name, "fdatasync")) failed = fdatasync(fd) < 0;
  else if (!strcmp(name, "rename")) failed = rename(path, rename_path) < 0;
  else if (!strcmp(name, "renameat")) failed = renameat(AT_FDCWD, path, AT_FDCWD, rename_path) < 0;
  else if (!strcmp(name, "renameat2")) failed = ((renameat2_fn)dlsym(RTLD_DEFAULT, "renameat2"))(AT_FDCWD, path, AT_FDCWD, rename_path, 0) < 0;
  else if (!strcmp(name, "close")) { failed = close(fd) < 0; fd = -1; }
  else return 2;
  if (fd >= 0) (void)syscall(SYS_close, fd);
  return failed ? 0 : 1;
}
