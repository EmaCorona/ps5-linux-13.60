#ifndef __RESOLVE_SHIM_H__
#define __RESOLVE_SHIM_H__
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#define f_open open
#define f_close close
#define f_read read
#define f_write write
#define f_lseek lseek
#define f_ioctl ioctl
#define f_malloc malloc
#define f_calloc calloc
#define f_free free
#define f_memcpy memcpy
#define f_memset memset
#define f_strcmp strcmp
#define f_strlen strlen
#define f_sprintf sprintf
#define f_snprintf snprintf
#define f_vsprintf vsprintf
#define f_strcpy strcpy
#define f_strncpy strncpy
#define f_strcat strcat
#define f_strchr strchr
#define f_strrchr strrchr
#define f_sscanf sscanf
#define f_puts puts
#define f_time time
#define f_localtime localtime
#define f_strerror strerror
static inline void *f_memalign(size_t boundary, size_t size) {
  void *p = NULL;
  if (size == 0) size = 1;
  if (posix_memalign(&p, boundary, size) != 0) return NULL;
  return p;
}
#endif
