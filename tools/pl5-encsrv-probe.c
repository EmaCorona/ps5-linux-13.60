#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ps5/kernel.h>

static void try_open(const char *tag, int flags) {
  int fd = open("/dev/pup_update0", flags);
  printf("%s: open -> %d errno=%d (%s)\n", tag, fd, errno, strerror(errno));
  fflush(stdout);
  if (fd >= 0) close(fd);
}

int main(void) {
  pid_t me = getpid();
  uint8_t caps[16];
  memset(caps, 0xff, sizeof(caps));

  printf("fw=%08x pid=%d authid_before=%#lx\n", kernel_get_fw_version(), (int)me,
         (unsigned long)kernel_get_ucred_authid(me));
  fflush(stdout);

  printf("set authid 0x4800000000000007 rc=%d\n",
         kernel_set_ucred_authid(me, 0x4800000000000007ULL));
  printf("set caps  0xff*16           rc=%d\n", kernel_set_ucred_caps(me, caps));
  printf("authid_after=%#lx uid=%d euid=%d\n",
         (unsigned long)kernel_get_ucred_authid(me), (int)getuid(), (int)geteuid());
  fflush(stdout);
  try_open("A7-rdwr", O_RDWR);
  try_open("A7-rdonly", O_RDONLY);

  printf("set authid 0x4800000000010003 rc=%d\n",
         kernel_set_ucred_authid(me, 0x4800000000010003ULL));
  printf("authid_after2=%#lx\n", (unsigned long)kernel_get_ucred_authid(me));
  fflush(stdout);
  try_open("A3-rdwr", O_RDWR);
  try_open("A3-rdonly", O_RDONLY);

  {
    uint8_t attrs[32]; memset(attrs, 0xff, sizeof(attrs));
    kernel_set_ucred_authid(me, 0x4800000000000007ULL);
    kernel_set_ucred_caps(me, caps);
    int ra = kernel_set_ucred_attrs(me, attrs);
    int r0 = kernel_set_ucred_uid(me, 0);
    int r1 = kernel_set_ucred_ruid(me, 0);
    int r2 = kernel_set_ucred_svuid(me, 0);
    printf("full: attrs=%d uid=%d ruid=%d svuid=%d authid=%#lx\n", ra, r0, r1, r2,
           (unsigned long)kernel_get_ucred_authid(me));
    fflush(stdout);
  }
  try_open("FULL-rdwr", O_RDWR);
  {
    int fd = open("/dev/sc_fw_update0", O_RDWR);
    printf("sc_fw_update0: open -> %d errno=%d (%s)\n", fd, errno, strerror(errno));
    fflush(stdout);
    if (fd >= 0) close(fd);
  }
  printf("probe done\n"); fflush(stdout);
  return 0;
}
