#include "defines.h"
#include "resolve.h"
#include <ps5/kernel.h>

void decrypt_pups(const char *InputPath, const char *OutputPath);

static void elevate(void) {
  uint8_t caps[16];
  memset(caps, 0xff, sizeof(caps));
  int r1 = kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);
  int r2 = kernel_set_ucred_caps(getpid(), caps);
  printf("elevate: authid rc=%d caps rc=%d\n", r1, r2);
  fflush(stdout);
}

int main(void) {
  printf("pl5-pup-decrypt: start\n"); fflush(stdout);
  elevate();
  {
    int fd = open("/dev/pup_update0", O_RDWR);
    printf("probe: open(/dev/pup_update0) -> %d errno=%d (%s) uid=%d euid=%d\n",
           fd, errno, strerror(errno), (int)getuid(), (int)geteuid());
    fflush(stdout);
    if (fd >= 0) close(fd);
  }
  decrypt_pups(INPUTPATH, OUTPUTPATH);
  printf("pl5-pup-decrypt: done\n"); fflush(stdout);
  return 0;
}
