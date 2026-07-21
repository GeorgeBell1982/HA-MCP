#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif

#define PHASE2_MAX_TEXT_BYTES (512U * 1024U)
#define SHA256_LEN 32
#define SHA256_HEX_LEN 64
#define PENDING_PREFIX ".phase3-atomic-"
#define MAX_PARENT_SCAN 1024

extern unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);

static volatile sig_atomic_t cancel_requested = 0;

static void on_signal(int signo) {
  (void)signo;
  cancel_requested = 1;
}

static void secure_bzero(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len-- > 0) *p++ = 0;
}

static void frame(const char *status, const char *error) {
  if (error == NULL)
    printf("phase3-atomic-apply-v1 status=%s\n", status);
  else
    printf("phase3-atomic-apply-v1 status=%s error=%s\n", status, error);
  fflush(stdout);
}

static void fail_before(const char *error) {
  frame("before_commit", error);
}

static void fail_unknown(const char *error) {
  frame("commit_unknown", error);
}

static int is_hex_digest(const char *value) {
  if (strlen(value) != SHA256_HEX_LEN) return 0;
  for (size_t i = 0; i < SHA256_HEX_LEN; i++) {
    char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static void digest_hex(const unsigned char *bytes, size_t len, char out[65]) {
  static const char hex[] = "0123456789abcdef";
  unsigned char md[SHA256_LEN];
  SHA256(bytes, len, md);
  for (size_t i = 0; i < SHA256_LEN; i++) {
    out[i * 2] = hex[md[i] >> 4];
    out[i * 2 + 1] = hex[md[i] & 0xf];
  }
  secure_bzero(md, sizeof(md));
  out[64] = '\0';
}

static int same_stat_exact(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
         a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
         a->st_size == b->st_size &&
         a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
         a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
         a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
         a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int same_dir_identity_metadata(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
         a->st_gid == b->st_gid;
}

static int same_file_identity_metadata(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
         a->st_gid == b->st_gid && a->st_size == b->st_size;
}

static int validate_regular_target(int fd, const struct stat *expected) {
  struct stat st;
  if (fstat(fd, &st) != 0) return -1;
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1) return -1;
  if ((st.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) return -1;
  if (st.st_size < 0 || (uint64_t)st.st_size > PHASE2_MAX_TEXT_BYTES) return -1;
  ssize_t xattrs = flistxattr(fd, NULL, 0);
  if (xattrs != 0) return -1;
  if (expected != NULL && !same_stat_exact(&st, expected)) return -1;
  return 0;
}

static int validate_staged_file(int fd, const struct stat *expected) {
  struct stat st;
  if (fstat(fd, &st) != 0) return -1;
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1) return -1;
  if ((st.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) return -1;
  if (st.st_size < 0 || (uint64_t)st.st_size > PHASE2_MAX_TEXT_BYTES) return -1;
  ssize_t xattrs = flistxattr(fd, NULL, 0);
  if (xattrs != 0) return -1;
  return same_file_identity_metadata(&st, expected) ? 0 : -1;
}

static int file_digest(int fd, char out[65], struct stat *stable) {
  struct stat before;
  struct stat after;
  if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size < 0 || (uint64_t)before.st_size > PHASE2_MAX_TEXT_BYTES)
    return -1;
  unsigned char *buf = calloc(1, before.st_size == 0 ? 1 : (size_t)before.st_size);
  if (buf == NULL) return -1;
  size_t off = 0;
  while (off < (size_t)before.st_size) {
    ssize_t n = pread(fd, buf + off, (size_t)before.st_size - off, (off_t)off);
    if (n < 0) {
      if (errno == EINTR) continue;
      secure_bzero(buf, (size_t)before.st_size);
      free(buf);
      return -1;
    }
    if (n == 0) {
      secure_bzero(buf, (size_t)before.st_size);
      free(buf);
      return -1;
    }
    off += (size_t)n;
  }
  if (fstat(fd, &after) != 0 || !same_stat_exact(&before, &after)) {
    secure_bzero(buf, (size_t)before.st_size);
    free(buf);
    return -1;
  }
  digest_hex(buf, (size_t)before.st_size, out);
  secure_bzero(buf, (size_t)before.st_size);
  free(buf);
  if (stable != NULL) *stable = after;
  return 0;
}

static int read_exact_stdin(unsigned char *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = read(STDIN_FILENO, buf + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return -1;
    off += (size_t)n;
  }
  unsigned char extra;
  for (;;) {
    ssize_t n = read(STDIN_FILENO, &extra, 1);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return 0;
    return -1;
  }
}

static int full_write(int fd, const unsigned char *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, buf + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return -1;
    off += (size_t)n;
  }
  return 0;
}

static int openat2_beneath(int dfd, const char *path, int flags, mode_t mode) {
  struct open_how how = {
    .flags = (uint64_t)flags,
    .mode = (uint64_t)mode,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
               RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
  };
  return (int)syscall(SYS_openat2, dfd, path, &how, sizeof(how));
}

static int rename_exchange(int dfd, const char *a, const char *b) {
  return (int)syscall(SYS_renameat2, dfd, a, dfd, b, RENAME_EXCHANGE);
}

static int split_path(const char *path, char parent[PATH_MAX], char base[NAME_MAX + 1]) {
  if (path[0] == '/' || strstr(path, "\\") != NULL || strstr(path, "..") != NULL)
    return -1;
  const char *slash = strrchr(path, '/');
  if (slash == NULL) {
    strcpy(parent, ".");
    if (strlen(path) == 0 || strlen(path) > NAME_MAX) return -1;
    strcpy(base, path);
    return 0;
  }
  size_t parent_len = (size_t)(slash - path);
  size_t base_len = strlen(slash + 1);
  if (parent_len == 0 || parent_len >= PATH_MAX || base_len == 0 ||
      base_len > NAME_MAX)
    return -1;
  memcpy(parent, path, parent_len);
  parent[parent_len] = '\0';
  memcpy(base, slash + 1, base_len + 1);
  return 0;
}

static int random_pending(char out[NAME_MAX + 1]) {
  unsigned char bytes[16];
  if (getrandom(bytes, sizeof(bytes), 0) != (ssize_t)sizeof(bytes)) return -1;
  static const char hex[] = "0123456789abcdef";
  strcpy(out, PENDING_PREFIX);
  size_t prefix = strlen(out);
  for (size_t i = 0; i < sizeof(bytes); i++) {
    out[prefix + i * 2] = hex[bytes[i] >> 4];
    out[prefix + i * 2 + 1] = hex[bytes[i] & 0xf];
  }
  out[prefix + sizeof(bytes) * 2] = '\0';
  secure_bzero(bytes, sizeof(bytes));
  return 0;
}

static int scan_pending_blockers(int parent) {
  int scan_fd = dup(parent);
  if (scan_fd < 0) return -1;
  DIR *dir = fdopendir(scan_fd);
  if (dir == NULL) {
    close(scan_fd);
    return -1;
  }
  size_t count = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(dir)) != NULL) {
    count++;
    if (count > MAX_PARENT_SCAN) {
      closedir(dir);
      return -1;
    }
    if (strncmp(entry->d_name, PENDING_PREFIX, strlen(PENDING_PREFIX)) == 0) {
      closedir(dir);
      return -1;
    }
  }
  if (errno != 0) {
    closedir(dir);
    return -1;
  }
  return closedir(dir) == 0 ? 0 : -1;
}

static int revalidate_root_parent(int root, int parent,
                                  const struct stat *root_initial,
                                  const struct stat *parent_initial) {
  struct stat root_now;
  struct stat parent_now;
  if (fstat(root, &root_now) != 0 || fstat(parent, &parent_now) != 0)
    return -1;
  if (!same_dir_identity_metadata(&root_now, root_initial)) return -1;
  if (!same_dir_identity_metadata(&parent_now, parent_initial)) return -1;
  return 0;
}

static int cleanup_pending_before(int parent, const char *pending) {
  int rc = 0;
  if (pending != NULL && unlinkat(parent, pending, 0) != 0) rc = -1;
  if (fsync(parent) != 0) rc = -1;
  return rc;
}

static int test_fail_stage(const char *stage) {
#ifdef PHASE3_ATOMIC_APPLY_TEST_FAILURE
  const char *wanted = getenv("PHASE3_ATOMIC_APPLY_TEST_FAILURE");
  return wanted != NULL && strcmp(wanted, stage) == 0;
#else
  (void)stage;
  return 0;
#endif
}

int main(int argc, char **argv) {
  signal(SIGTERM, on_signal);
  signal(SIGINT, on_signal);
  if (argc != 6) {
    fail_before("invalid_input");
    return 2;
  }
  const char *root_path = argv[1];
  const char *rel_path = argv[2];
  const char *expected_sha = argv[3];
  const char *candidate_sha = argv[4];
  char *end = NULL;
  errno = 0;
  unsigned long len_ul = strtoul(argv[5], &end, 10);
  if (errno != 0 || end == argv[5] || *end != '\0' ||
      len_ul > PHASE2_MAX_TEXT_BYTES || !is_hex_digest(expected_sha) ||
      !is_hex_digest(candidate_sha)) {
    fail_before("invalid_input");
    return 2;
  }

  size_t candidate_len = (size_t)len_ul;
  unsigned char *candidate = calloc(1, candidate_len == 0 ? 1 : candidate_len);
  if (candidate == NULL) {
    fail_before("internal_error");
    return 2;
  }
  if (read_exact_stdin(candidate, candidate_len) != 0) {
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("candidate_read_failed");
    return 2;
  }
  char observed_candidate[65];
  digest_hex(candidate, candidate_len, observed_candidate);
  if (strcmp(observed_candidate, candidate_sha) != 0) {
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("candidate_digest_mismatch");
    return 2;
  }

  int root = open(root_path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root < 0) {
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("open_root_failed");
    return 2;
  }
  struct stat root_initial;
  if (fstat(root, &root_initial) != 0) {
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("open_root_failed");
    return 2;
  }

  char parent_path[PATH_MAX];
  char base[NAME_MAX + 1];
  if (split_path(rel_path, parent_path, base) != 0) {
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("invalid_input");
    return 2;
  }
  int parent = openat2_beneath(root, parent_path,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
  if (parent < 0) {
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("open_parent_failed");
    return 2;
  }
  struct stat parent_initial;
  if (fstat(parent, &parent_initial) != 0 ||
      scan_pending_blockers(parent) != 0) {
    close(parent);
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("pending_blocked");
    return 2;
  }

  int target = openat2_beneath(parent, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
  if (target < 0) {
    close(parent);
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("open_target_failed");
    return 2;
  }
  struct stat target_initial;
  struct stat target_digest_st;
  if (fstat(target, &target_initial) != 0 ||
      validate_regular_target(target, NULL) != 0) {
    close(target);
    close(parent);
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("target_unsafe");
    return 2;
  }
  char target_sha[65];
  if (file_digest(target, target_sha, &target_digest_st) != 0 ||
      !same_stat_exact(&target_initial, &target_digest_st) ||
      strcmp(target_sha, expected_sha) != 0) {
    close(target);
    close(parent);
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("target_digest_mismatch");
    return 2;
  }
  close(target);

  int tmp = openat(parent, ".", O_TMPFILE | O_RDWR | O_CLOEXEC,
                   target_initial.st_mode & 0777);
  if (tmp < 0) {
    close(parent);
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("temp_create_failed");
    return 2;
  }
  if (fchown(tmp, target_initial.st_uid, target_initial.st_gid) != 0 ||
      fchmod(tmp, target_initial.st_mode & 0777) != 0 ||
      full_write(tmp, candidate, candidate_len) != 0 || fsync(tmp) != 0) {
    close(tmp);
    close(parent);
    close(root);
    secure_bzero(candidate, candidate_len);
    free(candidate);
    fail_before("temp_write_failed");
    return 2;
  }
  secure_bzero(candidate, candidate_len);
  free(candidate);

  struct stat staged_prelink;
  if (fstat(tmp, &staged_prelink) != 0 || !S_ISREG(staged_prelink.st_mode) ||
      staged_prelink.st_nlink != 0 || staged_prelink.st_uid != target_initial.st_uid ||
      staged_prelink.st_gid != target_initial.st_gid ||
      (staged_prelink.st_mode & 0777) != (target_initial.st_mode & 0777) ||
      staged_prelink.st_size != (off_t)candidate_len) {
    close(tmp);
    close(parent);
    close(root);
    fail_before("temp_verify_failed");
    return 2;
  }

  if (cancel_requested || test_fail_stage("pre_exchange")) {
    close(tmp);
    close(parent);
    close(root);
    fail_before("cancelled");
    return 2;
  }

  if (revalidate_root_parent(root, parent, &root_initial, &parent_initial) != 0) {
    close(tmp);
    close(parent);
    close(root);
    fail_before("race_detected");
    return 2;
  }

  char pending[NAME_MAX + 1];
  if (random_pending(pending) != 0 ||
      linkat(tmp, "", parent, pending, AT_EMPTY_PATH) != 0) {
    close(tmp);
    close(parent);
    close(root);
    fail_before("temp_verify_failed");
    return 2;
  }
  close(tmp);

  int staged = openat2_beneath(parent, pending, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
  struct stat staged_link;
  char staged_sha[65];
  if (staged < 0 || fstat(staged, &staged_link) != 0 ||
      !same_file_identity_metadata(&staged_link, &staged_prelink) ||
      validate_staged_file(staged, &staged_prelink) != 0 ||
      file_digest(staged, staged_sha, NULL) != 0 ||
      strcmp(staged_sha, candidate_sha) != 0) {
    if (staged >= 0) close(staged);
    cleanup_pending_before(parent, pending);
    close(parent);
    close(root);
    fail_before("temp_verify_failed");
    return 2;
  }
  close(staged);

  if (cancel_requested) {
    cleanup_pending_before(parent, pending);
    close(parent);
    close(root);
    fail_before("cancelled");
    return 2;
  }

  target = openat2_beneath(parent, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
  struct stat target_preexchange;
  struct stat target_preexchange_digest_st;
  if (target < 0 || fstat(target, &target_preexchange) != 0 ||
      validate_regular_target(target, &target_initial) != 0 ||
      file_digest(target, target_sha, &target_preexchange_digest_st) != 0 ||
      !same_stat_exact(&target_preexchange, &target_preexchange_digest_st) ||
      strcmp(target_sha, expected_sha) != 0 ||
      revalidate_root_parent(root, parent, &root_initial, &parent_initial) != 0) {
    if (target >= 0) close(target);
    cleanup_pending_before(parent, pending);
    close(parent);
    close(root);
    fail_before("race_detected");
    return 2;
  }
  close(target);

  if (test_fail_stage("exchange") || rename_exchange(parent, pending, base) != 0) {
    fail_unknown("exchange_failed");
    close(parent);
    close(root);
    return 3;
  }

  int current = openat2_beneath(parent, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
  int displaced = openat2_beneath(parent, pending, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
  struct stat current_st;
  struct stat displaced_st;
  char current_sha[65];
  char displaced_sha[65];
  if (test_fail_stage("post_exchange") || current < 0 || displaced < 0 ||
      fstat(current, &current_st) != 0 || fstat(displaced, &displaced_st) != 0 ||
      !same_file_identity_metadata(&current_st, &staged_link) ||
      !same_file_identity_metadata(&displaced_st, &target_preexchange) ||
      validate_staged_file(current, &staged_link) != 0 ||
      validate_staged_file(displaced, &target_preexchange) != 0 ||
      file_digest(current, current_sha, NULL) != 0 ||
      file_digest(displaced, displaced_sha, NULL) != 0 ||
      strcmp(current_sha, candidate_sha) != 0 ||
      strcmp(displaced_sha, expected_sha) != 0 || fsync(parent) != 0) {
    if (current >= 0) close(current);
    if (displaced >= 0) close(displaced);
    close(parent);
    close(root);
    fail_unknown("commit_verification_failed");
    return 3;
  }
  close(current);
  close(displaced);

  if (unlinkat(parent, pending, 0) != 0 || fsync(parent) != 0) {
    close(parent);
    close(root);
    fail_unknown("cleanup_failed");
    return 3;
  }
  close(parent);
  close(root);
  frame("committed", NULL);
  return 0;
}