// 容器 fd 硬上限 20000，neard 堅持 65535。只在容器內用的 shim：NOFILE 的 set 假裝成功、get 回報 65535。
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/resource.h>
#include <dlfcn.h>
#include <stddef.h>
#define FAKE 65535
static int is_nofile(int r){ return r == RLIMIT_NOFILE; }
int setrlimit(__rlimit_resource_t res, const struct rlimit *r) {
  static int (*real)(__rlimit_resource_t, const struct rlimit*) = NULL;
  if (!real) real = dlsym(RTLD_NEXT, "setrlimit");
  int rc = real(res, r); return (is_nofile(res) && rc) ? 0 : rc;
}
int setrlimit64(__rlimit_resource_t res, const struct rlimit64 *r) {
  static int (*real)(__rlimit_resource_t, const struct rlimit64*) = NULL;
  if (!real) real = dlsym(RTLD_NEXT, "setrlimit64");
  int rc = real(res, r); return (is_nofile(res) && rc) ? 0 : rc;
}
int getrlimit(__rlimit_resource_t res, struct rlimit *r) {
  static int (*real)(__rlimit_resource_t, struct rlimit*) = NULL;
  if (!real) real = dlsym(RTLD_NEXT, "getrlimit");
  int rc = real(res, r); if (is_nofile(res) && rc == 0) { r->rlim_cur = FAKE; r->rlim_max = FAKE; } return rc;
}
int getrlimit64(__rlimit_resource_t res, struct rlimit64 *r) {
  static int (*real)(__rlimit_resource_t, struct rlimit64*) = NULL;
  if (!real) real = dlsym(RTLD_NEXT, "getrlimit64");
  int rc = real(res, r); if (is_nofile(res) && rc == 0) { r->rlim_cur = FAKE; r->rlim_max = FAKE; } return rc;
}
int prlimit(pid_t pid, __rlimit_resource_t res, const struct rlimit *n, struct rlimit *o) {
  static int (*real)(pid_t, __rlimit_resource_t, const struct rlimit*, struct rlimit*) = NULL;
  if (!real) real = dlsym(RTLD_NEXT, "prlimit");
  int rc = real(pid, res, n, o);
  if (is_nofile(res)) { if (o) { o->rlim_cur = FAKE; o->rlim_max = FAKE; } return 0; }
  return rc;
}
int prlimit64(pid_t pid, __rlimit_resource_t res, const struct rlimit64 *n, struct rlimit64 *o) {
  static int (*real)(pid_t, __rlimit_resource_t, const struct rlimit64*, struct rlimit64*) = NULL;
  if (!real) real = dlsym(RTLD_NEXT, "prlimit64");
  int rc = real(pid, res, n, o);
  if (is_nofile(res)) { if (o) { o->rlim_cur = FAKE; o->rlim_max = FAKE; } return 0; }
  return rc;
}
