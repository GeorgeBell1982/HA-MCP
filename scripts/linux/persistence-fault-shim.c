#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *target;
static const char *mode;
static const char *arm_path;
static const char *proof_path;
static unsigned long target_nth;
static unsigned long seen;
static int proof_fd = -1;
static char root_path[PATH_MAX];
static char normalized_arm[PATH_MAX];
static char normalized_proof[PATH_MAX];
static size_t root_length;

static int target_matches(const char *name);

static int normalize_absolute(const char *input, char *output, size_t capacity) {
  char copy[PATH_MAX];
  size_t length, output_length = 1, depth = 0;
  size_t marks[PATH_MAX / 2];
  char *cursor;
  if (!input || input[0] != '/') return 0;
  length = strlen(input);
  if (length >= sizeof(copy) || capacity < 2) return 0;
  memcpy(copy, input, length + 1);
  output[0] = '/';
  output[1] = '\0';
  cursor = copy + 1;
  while (*cursor) {
    char *segment;
    size_t segment_length;
    while (*cursor == '/') cursor++;
    if (!*cursor) break;
    segment = cursor;
    while (*cursor && *cursor != '/') cursor++;
    segment_length = (size_t)(cursor - segment);
    if (segment_length == 1 && segment[0] == '.') continue;
    if (segment_length == 2 && segment[0] == '.' && segment[1] == '.') {
      if (depth) {
        output_length = marks[--depth];
        output[output_length] = '\0';
      }
      continue;
    }
    if (depth >= sizeof(marks) / sizeof(marks[0])) return 0;
    marks[depth++] = output_length;
    if (output_length > 1) {
      if (output_length + 1 >= capacity) return 0;
      output[output_length++] = '/';
    }
    if (output_length + segment_length >= capacity) return 0;
    memcpy(output + output_length, segment, segment_length);
    output_length += segment_length;
    output[output_length] = '\0';
  }
  return 1;
}

static int descriptor_path(int descriptor, char *output, size_t capacity) {
  char link_path[64];
  long length;
  int printed = snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", descriptor);
  if (printed < 0 || (size_t)printed >= sizeof(link_path)) return 0;
  length = syscall(SYS_readlinkat, AT_FDCWD, link_path, output, capacity - 1);
  if (length <= 0 || (size_t)length >= capacity) return 0;
  output[length] = '\0';
  {
    const char suffix[] = " (deleted)";
    size_t output_length = (size_t)length, suffix_length = sizeof(suffix) - 1;
    if (output_length > suffix_length &&
        !strcmp(output + output_length - suffix_length, suffix))
      output[output_length - suffix_length] = '\0';
  }
  return output[0] == '/';
}

static int absolute_path(const char *path, int directory, char *output,
                         size_t capacity) {
  char base[PATH_MAX], combined[PATH_MAX];
  long length;
  int printed;
  if (!path) return 0;
  if (path[0] == '/') return normalize_absolute(path, output, capacity);
  if (directory == AT_FDCWD) {
    length = syscall(SYS_getcwd, base, sizeof(base));
    if (length <= 0 || (size_t)length > sizeof(base)) return 0;
  } else if (!descriptor_path(directory, base, sizeof(base))) {
    return 0;
  }
  printed = snprintf(combined, sizeof(combined), "%s/%s", base, path);
  if (printed < 0 || (size_t)printed >= sizeof(combined)) return 0;
  return normalize_absolute(combined, output, capacity);
}

static int scoped_path(const char *absolute, char *relative, size_t capacity) {
  const char *suffix;
  size_t length, index;
  if (!root_length || !absolute) return 0;
  if (!strcmp(absolute, normalized_arm) || !strcmp(absolute, normalized_proof))
    return 0;
  if (root_length == 1) {
    if (absolute[0] != '/') return 0;
    suffix = absolute + 1;
  } else {
    if (strncmp(absolute, root_path, root_length) ||
        (absolute[root_length] != '\0' && absolute[root_length] != '/'))
      return 0;
    suffix = absolute + root_length;
    if (*suffix == '/') suffix++;
  }
  if (!*suffix) suffix = ".";
  length = strlen(suffix);
  if (length >= capacity) return 0;
  for (index = 0; index < length; index++) {
    unsigned char value = (unsigned char)suffix[index];
    relative[index] =
        (value == '/' || value == '.' || value == '_' || value == '-' ||
         (value >= '0' && value <= '9') ||
         (value >= 'A' && value <= 'Z') ||
         (value >= 'a' && value <= 'z'))
            ? (char)value
            : '_';
  }
  relative[length] = '\0';
  return 1;
}

static int armed(void) {
  struct stat metadata;
  if (!arm_path) return 1;
  return syscall(SYS_newfstatat, AT_FDCWD, arm_path, &metadata, 0) == 0;
}

static int write_all(int descriptor, const char *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    long written = syscall(SYS_write, descriptor, bytes + offset,
                           length - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return 0;
    offset += (size_t)written;
  }
  return 1;
}

static int intercept_resolved(const char *name, const char *absolute) {
  char relative[PATH_MAX], record[PATH_MAX + 192];
  int length;
  if (!target_matches(name) || !armed() ||
      !scoped_path(absolute, relative, sizeof(relative)))
    return 0;
  seen++;
  if (!target_nth || seen != target_nth) return 0;
  if (proof_fd >= 0) {
    length = snprintf(
        record, sizeof(record),
        "{\"syscall\":\"%s\",\"nth\":%lu,\"mode\":\"%s\",\"target\":\"%s\"}\n",
        name, seen, mode ? mode : "fail", relative);
    if (length > 0 && (size_t)length < sizeof(record))
      (void)write_all(proof_fd, record, (size_t)length);
  }
  errno = mode && !strcmp(mode, "enospc") ? ENOSPC : EIO;
  return 1;
}

static int intercept_path(const char *name, int directory, const char *path) {
  char absolute[PATH_MAX];
  if (!target_matches(name) ||
      !absolute_path(path, directory, absolute, sizeof(absolute)))
    return 0;
  return intercept_resolved(name, absolute);
}

static int intercept_descriptor(const char *name, int descriptor) {
  char absolute[PATH_MAX];
  if (!target || strcmp(target, name) ||
      !descriptor_path(descriptor, absolute, sizeof(absolute)))
    return 0;
  return intercept_resolved(name, absolute);
}

static int intercept_rename(const char *name, int old_directory,
                            const char *old_path, int new_directory,
                            const char *new_path) {
  char old_absolute[PATH_MAX], new_absolute[PATH_MAX], ignored[PATH_MAX];
  if (!target || strcmp(target, name) ||
      !absolute_path(old_path, old_directory, old_absolute,
                     sizeof(old_absolute)) ||
      !absolute_path(new_path, new_directory, new_absolute,
                     sizeof(new_absolute)) ||
      !scoped_path(old_absolute, ignored, sizeof(ignored)) ||
      !scoped_path(new_absolute, ignored, sizeof(ignored)))
    return 0;
  return intercept_resolved(name, new_absolute);
}

static void initialize(void) __attribute__((constructor));
static void initialize(void) {
  const char *root = getenv("HA_FAULT_ROOT");
  const char *nth = getenv("HA_FAULT_NTH");
  target = getenv("HA_FAULT_SYSCALL");
  mode = getenv("HA_FAULT_MODE");
  arm_path = getenv("HA_FAULT_ARM");
  proof_path = getenv("HA_FAULT_PROOF");
  target_nth = nth ? strtoul(nth, NULL, 10) : 0;
  if (root && normalize_absolute(root, root_path, sizeof(root_path)))
    root_length = strlen(root_path);
  if (arm_path)
    (void)absolute_path(arm_path, AT_FDCWD, normalized_arm,
                        sizeof(normalized_arm));
  if (proof_path)
    (void)absolute_path(proof_path, AT_FDCWD, normalized_proof,
                        sizeof(normalized_proof));
  if (proof_path)
    proof_fd = (int)syscall(SYS_openat, AT_FDCWD, proof_path,
                            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

static ssize_t short_count(size_t count) {
  if (count <= 1) return 0;
  return (ssize_t)(count / 2);
}

static int target_matches(const char *name) {
  return target &&
         (!strcmp(target, name) ||
          (!strcmp(target, "open-family") &&
           (!strcmp(name, "open") || !strcmp(name, "open64") ||
            !strcmp(name, "openat") || !strcmp(name, "openat64"))) ||
          (!strcmp(target, "link-family") &&
           (!strcmp(name, "link") || !strcmp(name, "linkat"))));
}

static int intercept_link(const char *name, int old_directory,
                          const char *old_path, int new_directory,
                          const char *new_path) {
  char old_absolute[PATH_MAX], new_absolute[PATH_MAX], ignored[PATH_MAX];
  if (!target_matches(name) ||
      !absolute_path(old_path, old_directory, old_absolute,
                     sizeof(old_absolute)) ||
      !absolute_path(new_path, new_directory, new_absolute,
                     sizeof(new_absolute)) ||
      !scoped_path(old_absolute, ignored, sizeof(ignored)) ||
      !scoped_path(new_absolute, ignored, sizeof(ignored)))
    return 0;
  return intercept_resolved(name, new_absolute);
}

#define RESOLVE(symbol)                                                     \
  static __typeof__(symbol) *real_##symbol;                                 \
  if (!real_##symbol) real_##symbol = dlsym(RTLD_NEXT, #symbol)

int open(const char *path, int flags, ...) {
  mode_t create_mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    create_mode = va_arg(args, mode_t);
    va_end(args);
  }
  RESOLVE(open);
  if (intercept_path("open", AT_FDCWD, path)) return -1;
  return real_open(path, flags, create_mode);
}
int open64(const char *path, int flags, ...) {
  mode_t create_mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    create_mode = va_arg(args, mode_t);
    va_end(args);
  }
  RESOLVE(open64);
  if (intercept_path("open64", AT_FDCWD, path)) return -1;
  return real_open64(path, flags, create_mode);
}
int openat(int directory, const char *path, int flags, ...) {
  mode_t create_mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    create_mode = va_arg(args, mode_t);
    va_end(args);
  }
  RESOLVE(openat);
  if (intercept_path("openat", directory, path)) return -1;
  return real_openat(directory, path, flags, create_mode);
}
int openat64(int directory, const char *path, int flags, ...) {
  mode_t create_mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    create_mode = va_arg(args, mode_t);
    va_end(args);
  }
  RESOLVE(openat64);
  if (intercept_path("openat64", directory, path)) return -1;
  return real_openat64(directory, path, flags, create_mode);
}
int link(const char *old_path, const char *new_path) {
  RESOLVE(link);
  if (intercept_link("link", AT_FDCWD, old_path, AT_FDCWD, new_path))
    return -1;
  return real_link(old_path, new_path);
}
int linkat(int old_dir, const char *old_path, int new_dir,
           const char *new_path, int flags) {
  RESOLVE(linkat);
  if (intercept_link("linkat", old_dir, old_path, new_dir, new_path))
    return -1;
  return real_linkat(old_dir, old_path, new_dir, new_path, flags);
}
ssize_t write(int fd, const void *buffer, size_t count) {
  RESOLVE(write);
  if (!intercept_descriptor("write", fd)) return real_write(fd, buffer, count);
  if (mode && !strcmp(mode, "short"))
    return real_write(fd, buffer, (size_t)short_count(count));
  return -1;
}
ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset) {
  RESOLVE(pwrite);
  if (!intercept_descriptor("pwrite", fd))
    return real_pwrite(fd, buffer, count, offset);
  if (mode && !strcmp(mode, "short"))
    return real_pwrite(fd, buffer, (size_t)short_count(count), offset);
  return -1;
}
ssize_t writev(int fd, const struct iovec *iov, int count) {
  RESOLVE(writev);
  if (!intercept_descriptor("writev", fd)) return real_writev(fd, iov, count);
  if (mode && !strcmp(mode, "short") && count > 0) {
    RESOLVE(write);
    return real_write(fd, iov[0].iov_base,
                      (size_t)short_count(iov[0].iov_len));
  }
  return -1;
}
int fsync(int fd) {
  RESOLVE(fsync);
  if (intercept_descriptor("fsync", fd)) return -1;
  return real_fsync(fd);
}
int fdatasync(int fd) {
  RESOLVE(fdatasync);
  if (intercept_descriptor("fdatasync", fd)) return -1;
  return real_fdatasync(fd);
}
int rename(const char *old_path, const char *new_path) {
  RESOLVE(rename);
  if (intercept_rename("rename", AT_FDCWD, old_path, AT_FDCWD, new_path))
    return -1;
  return real_rename(old_path, new_path);
}
int renameat(int old_dir, const char *old_path, int new_dir,
             const char *new_path) {
  RESOLVE(renameat);
  if (intercept_rename("renameat", old_dir, old_path, new_dir, new_path))
    return -1;
  return real_renameat(old_dir, old_path, new_dir, new_path);
}
int renameat2(int old_dir, const char *old_path, int new_dir,
              const char *new_path, unsigned flags) {
  RESOLVE(renameat2);
  if (intercept_rename("renameat2", old_dir, old_path, new_dir, new_path))
    return -1;
  return real_renameat2(old_dir, old_path, new_dir, new_path, flags);
}
int close(int fd) {
  RESOLVE(close);
  if (fd != proof_fd && intercept_descriptor("close", fd)) return -1;
  return real_close(fd);
}
