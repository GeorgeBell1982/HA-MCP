#define _GNU_SOURCE
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

#define HEADER_BYTES 64
#define STATUS_DENIED 1
#define STATUS_TOO_LARGE 2
#define STATUS_UNAVAILABLE 4

static void put_u32(unsigned char *out, uint32_t value) {
  out[0] = (unsigned char)(value >> 24); out[1] = (unsigned char)(value >> 16);
  out[2] = (unsigned char)(value >> 8); out[3] = (unsigned char)value;
}
static void put_u64(unsigned char *out, uint64_t value) {
  for (int i = 7; i >= 0; --i) { out[i] = (unsigned char)value; value >>= 8; }
}
static int write_all(int fd, const void *data, size_t length) {
  const unsigned char *cursor = data;
  while (length > 0) {
    ssize_t written = write(fd, cursor, length);
    if (written < 0) { if (errno == EINTR) continue; return -1; }
    cursor += written; length -= (size_t)written;
  }
  return 0;
}
static void secure_wipe(unsigned char *content, size_t size) {
  volatile unsigned char *cursor = content;
  for (size_t index = 0; index < size; ++index) cursor[index] = 0;
}
static void wipe_free(unsigned char *content, size_t size) {
  if (!content) return;
  secure_wipe(content, size);
  free(content);
}
static int valid_relative_path(const char *path) {
  if (!path[0] || path[0] == '/' || strlen(path) > 512) return 0;
  const char *segment = path;
  for (const unsigned char *cursor = (const unsigned char *)path;; ++cursor) {
    unsigned char value = *cursor;
    if (value == '\\' || value == ':' ||
        (value != 0 && value <= 0x1f) || value == 0x7f) return 0;
    if (value == '/' || value == 0) {
      size_t length = (size_t)((const char *)cursor - segment);
      if (length == 0 || (length == 1 && segment[0] == '.') ||
          (length == 2 && segment[0] == '.' && segment[1] == '.')) return 0;
      if (value == 0) return 1;
      segment = (const char *)cursor + 1;
    }
  }
}
static int fail(unsigned status, int error_number) {
  unsigned char header[HEADER_BYTES] = {0};
  memcpy(header, "HAREAD2\0", 8); put_u32(header + 8, 1); put_u32(header + 12, status);
  put_u32(header + 16, (uint32_t)error_number);
  return write_all(STDOUT_FILENO, header, sizeof(header)) == 0 ? 0 : 111;
}
int main(int argc, char **argv) {
  if (argc != 7 || strcmp(argv[1], "--root") || strcmp(argv[3], "--path") || strcmp(argv[5], "--max-bytes")) return fail(STATUS_DENIED, EINVAL);
  const char *root = argv[2], *path = argv[4], *limit_text = argv[6];
  if (!root[0] || strlen(root) > 4096 || !valid_relative_path(path)) return fail(STATUS_DENIED, EINVAL);
  errno = 0; char *end = NULL; unsigned long long limit = strtoull(limit_text, &end, 10);
  if (errno || !end || *end || limit == 0 || limit > 16777216ULL) return fail(STATUS_DENIED, EINVAL);
  int root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd < 0) return fail(STATUS_DENIED, errno);
  struct stat root_stat;
  if (fstat(root_fd, &root_stat) != 0 || !S_ISDIR(root_stat.st_mode)) { int e = errno; close(root_fd); return fail(STATUS_DENIED, e); }
  struct open_how how = {0};
  how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
  int file_fd = (int)syscall(SYS_openat2, root_fd, path, &how, sizeof(how));
  if (file_fd < 0) {
    int e = errno;
    unsigned status = e == ENOSYS || e == E2BIG || e == EINVAL || e == EPERM
                        ? STATUS_UNAVAILABLE : STATUS_DENIED;
    close(root_fd); return fail(status, e);
  }
  struct stat file_stat;
  if (fstat(file_fd, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) { int e = errno; close(file_fd); close(root_fd); return fail(STATUS_DENIED, e); }
  if (file_stat.st_size < 0 || (unsigned long long)file_stat.st_size > limit) { close(file_fd); close(root_fd); return fail(STATUS_TOO_LARGE, EFBIG); }
  size_t size = (size_t)file_stat.st_size;
  unsigned char *content = size ? malloc(size) : NULL;
  if (size && !content) { close(file_fd); close(root_fd); return fail(STATUS_DENIED, ENOMEM); }
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = read(file_fd, content + offset, size - offset);
    if (count < 0) { if (errno == EINTR) continue; wipe_free(content, size); close(file_fd); close(root_fd); return fail(STATUS_DENIED, errno); }
    if (count == 0) { wipe_free(content, size); close(file_fd); close(root_fd); return fail(STATUS_DENIED, EIO); }
    offset += (size_t)count;
  }
  unsigned char extra;
  ssize_t extra_count = read(file_fd, &extra, 1);
  secure_wipe(&extra, sizeof(extra));
  if (extra_count != 0) { wipe_free(content, size); close(file_fd); close(root_fd); return fail(STATUS_DENIED, EBUSY); }
  struct stat final_stat;
  if (fstat(file_fd, &final_stat) != 0 ||
      final_stat.st_dev != file_stat.st_dev ||
      final_stat.st_ino != file_stat.st_ino ||
      final_stat.st_size != file_stat.st_size ||
      final_stat.st_mtim.tv_sec != file_stat.st_mtim.tv_sec ||
      final_stat.st_mtim.tv_nsec != file_stat.st_mtim.tv_nsec ||
      final_stat.st_ctim.tv_sec != file_stat.st_ctim.tv_sec ||
      final_stat.st_ctim.tv_nsec != file_stat.st_ctim.tv_nsec) {
    wipe_free(content, size); close(file_fd); close(root_fd);
    return fail(STATUS_DENIED, EBUSY);
  }
  unsigned char header[HEADER_BYTES] = {0};
  memcpy(header, "HAREAD2\0", 8); put_u32(header + 8, 1);
  put_u64(header + 24, (uint64_t)root_stat.st_dev); put_u64(header + 32, (uint64_t)root_stat.st_ino);
  put_u64(header + 40, (uint64_t)file_stat.st_dev); put_u64(header + 48, (uint64_t)file_stat.st_ino); put_u64(header + 56, (uint64_t)size);
  int result = write_all(STDOUT_FILENO, header, sizeof(header)) || (size && write_all(STDOUT_FILENO, content, size)) ? 111 : 0;
  wipe_free(content, size); close(file_fd); close(root_fd); return result;
}
