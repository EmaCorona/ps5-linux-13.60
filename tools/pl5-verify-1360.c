#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>

int main(void) {
  const long TEXT_END = 0xCC0000;
  uint64_t kt = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  printf("fw=%08x ktext=%#lx kdata=%#lx\n", kernel_get_fw_version(),
         (unsigned long)kt, (unsigned long)(uint64_t)KERNEL_ADDRESS_DATA_BASE);
  /* ONLY kernel .data offsets (>= 0xCC0000). Never probe a ktext-relative
   * offset below 0xCC0000: that is the protected .text region and reading it
   * powers this console off (measured). HV-relative values (0x83028, 0x82A60)
   * are NOT ktext-relative and must never be added to ktext. */
  static const long offs[] = {0x3B48FF8, 0x3BB4300, 0x3BB6FE0, 0x3B49294, 0x3B49298,
                              0x3B47E4C};
  for (unsigned i = 0; i < sizeof(offs)/sizeof(offs[0]); i++) {
    if (offs[i] < TEXT_END) { printf("VAL %#010lx SKIP (in .text, unsafe)\n", (unsigned long)offs[i]); continue; }
    uint64_t v = 0;
    int rc = kernel_copyout((intptr_t)(kt + offs[i]), &v, 8);
    if (rc == 0) printf("VAL %#010lx %#018lx\n", (unsigned long)offs[i], (unsigned long)v);
    else         printf("VAL %#010lx READ_FAIL rc=%d\n", (unsigned long)offs[i], rc);
  }
  fflush(stdout);
  return 0;
}
