#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif
#ifndef EXT2_SUPER_MAGIC
#define EXT2_SUPER_MAGIC 0xEF53
#endif
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif
#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif

static const char protocol_prefix[] = "phase3-approval-custody-v1";

static bool ignore_broken_pipe_signal(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_IGN;
  if (sigemptyset(&action.sa_mask) != 0) {
    return false;
  }
  return sigaction(SIGPIPE, &action, NULL) == 0;
}

static bool write_all(int descriptor, const char *buffer, size_t length) {
  size_t offset = 0U;
  while (offset < length) {
    ssize_t written = write(descriptor, buffer + offset, length - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (written == 0) {
      return false;
    }
    offset += (size_t)written;
  }
  return true;
}

static int startup_failure(const char *code, int status) {
  char frame[128];
  int length = snprintf(frame, sizeof(frame), "%s\tfailure\tcode=%s\n",
                        protocol_prefix, code);
  if (length < 0 || (size_t)length >= sizeof(frame) ||
      !write_all(STDOUT_FILENO, frame, (size_t)length)) {
    return 69;
  }
  return status;
}

static bool canonical_absolute_path(const char *path) {
  size_t length;
  size_t index;
  if (path == NULL || path[0] != '/') {
    return false;
  }
  length = strlen(path);
  if (length == 0U || (length > 1U && path[length - 1U] == '/')) {
    return false;
  }
  for (index = 0U; index < length; index += 1U) {
    if (path[index] == '\n' || path[index] == '\r' || path[index] == '\t') {
      return false;
    }
    if (index > 0U && path[index] == '/' && path[index - 1U] == '/') {
      return false;
    }
  }
  for (index = 0U; index < length;) {
    size_t start;
    size_t component_length;
    while (index < length && path[index] == '/') {
      index += 1U;
    }
    if (index >= length) {
      break;
    }
    start = index;
    while (index < length && path[index] != '/') {
      index += 1U;
    }
    component_length = index - start;
    if ((component_length == 1U && path[start] == '.') ||
        (component_length == 2U && path[start] == '.' &&
         path[start + 1U] == '.')) {
      return false;
    }
  }
  return true;
}

static bool parse_parent(const char *value, pid_t *result) {
  char *end = NULL;
  uintmax_t parsed;
  if (value == NULL || value[0] == '\0' ||
      (value[0] == '0' && value[1] != '\0')) {
    return false;
  }
  for (size_t index = 0U; value[index] != '\0'; index += 1U) {
    if (value[index] < '0' || value[index] > '9') {
      return false;
    }
  }
  errno = 0;
  parsed = strtoumax(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0U ||
      parsed > (uintmax_t)INT32_MAX) {
    return false;
  }
  *result = (pid_t)parsed;
  return true;
}

static bool supported_filesystem(uintmax_t filesystem_type) {
  return filesystem_type == (uintmax_t)TMPFS_MAGIC ||
         filesystem_type == (uintmax_t)EXT2_SUPER_MAGIC ||
         filesystem_type == (uintmax_t)XFS_SUPER_MAGIC ||
         filesystem_type == (uintmax_t)BTRFS_SUPER_MAGIC ||
         filesystem_type == (uintmax_t)OVERLAYFS_SUPER_MAGIC;
}

static int emit_ready(const struct stat *metadata,
                      const struct statfs *filesystem) {
  char frame[512];
  uintmax_t ctime_seconds;
  uintmax_t ctime_nanoseconds;
  int length;
  if (metadata->st_ctim.tv_sec < 0 || metadata->st_ctim.tv_nsec < 0 ||
      metadata->st_ctim.tv_nsec > 999999999L) {
    return startup_failure("internal_error", 74);
  }
  ctime_seconds = (uintmax_t)metadata->st_ctim.tv_sec;
  ctime_nanoseconds = (uintmax_t)metadata->st_ctim.tv_nsec;
  length = snprintf(
      frame, sizeof(frame),
      "%s\tready\tdev=%" PRIuMAX "\tino=%" PRIuMAX "\tmode=%" PRIuMAX
      "\tuid=%" PRIuMAX "\tgid=%" PRIuMAX "\tnlink=%" PRIuMAX
      "\tctime_sec=%" PRIuMAX "\tctime_nsec=%" PRIuMAX
      "\tfs_type=%" PRIuMAX "\n",
      protocol_prefix, (uintmax_t)metadata->st_dev,
      (uintmax_t)metadata->st_ino, (uintmax_t)metadata->st_mode,
      (uintmax_t)metadata->st_uid, (uintmax_t)metadata->st_gid,
      (uintmax_t)metadata->st_nlink, ctime_seconds, ctime_nanoseconds,
      (uintmax_t)(unsigned long)filesystem->f_type);
  if (length < 0 || (size_t)length >= sizeof(frame) ||
      !write_all(STDOUT_FILENO, frame, (size_t)length)) {
    return 69;
  }
  return 0;
}

static int read_control(void) {
  unsigned char control[2];
  size_t length = 0U;
  for (;;) {
    ssize_t received = read(STDIN_FILENO, control + length,
                            sizeof(control) - length);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      return 74;
    }
    if (received == 0) {
      break;
    }
    length += (size_t)received;
    if (length == sizeof(control)) {
      unsigned char trailing;
      for (;;) {
        received = read(STDIN_FILENO, &trailing, 1U);
        if (received < 0 && errno == EINTR) {
          continue;
        }
        break;
      }
      return received < 0 ? 74 : 71;
    }
  }
  if (length == 0U) {
    return 70;
  }
  if (length != 1U || control[0] != 0x52U) {
    return 71;
  }
  return 0;
}

int main(int argc, char **argv) {
  pid_t expected_parent;
  int root_descriptor;
  struct stat metadata;
  struct statfs filesystem;
  int status;

  if (!ignore_broken_pipe_signal()) {
    return startup_failure("internal_error", 74);
  }
  if (argc != 3 || !canonical_absolute_path(argv[1])) {
    return startup_failure("invalid_arguments", 64);
  }
  if (!parse_parent(argv[2], &expected_parent)) {
    return startup_failure("parent_invalid", 65);
  }
  if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
    return startup_failure("internal_error", 74);
  }
  if (getppid() != expected_parent) {
    return startup_failure("parent_changed", 65);
  }

  root_descriptor =
      open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root_descriptor < 0) {
    return startup_failure("root_open_failed", 66);
  }
  if (fstat(root_descriptor, &metadata) != 0 ||
      fstatfs(root_descriptor, &filesystem) != 0) {
    status = startup_failure("root_open_failed", 66);
    (void)close(root_descriptor);
    return status;
  }
  if (!supported_filesystem((uintmax_t)filesystem.f_type)) {
    status = startup_failure("filesystem_unsupported", 67);
    (void)close(root_descriptor);
    return status;
  }
  if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
      (metadata.st_mode & (mode_t)0077) != (mode_t)0) {
    status = startup_failure("root_unsafe", 66);
    (void)close(root_descriptor);
    return status;
  }
  if (flock(root_descriptor, LOCK_EX) != 0) {
    status = startup_failure("lock_failed", 68);
    (void)close(root_descriptor);
    return status;
  }

  status = emit_ready(&metadata, &filesystem);
  if (status != 0) {
    (void)flock(root_descriptor, LOCK_UN);
    (void)close(root_descriptor);
    return status;
  }
  status = read_control();
  if (status != 0) {
    (void)flock(root_descriptor, LOCK_UN);
    (void)close(root_descriptor);
    return status;
  }
  if (flock(root_descriptor, LOCK_UN) != 0) {
    (void)close(root_descriptor);
    return 72;
  }
  if (close(root_descriptor) != 0) {
    return 73;
  }
  return 0;
}
