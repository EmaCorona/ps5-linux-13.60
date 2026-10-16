/* khook_trampoline_block — the memory the Stage-1 trampoline reads.
 *
 * The trampoline (source/shellcode/db_trampoline/) runs in kernel context with no
 * libc and no calls: it can only compare values it finds at known offsets. This
 * header is the contract between the C side that fills those values and the
 * assembly that checks them, so neither side can change a layout alone.
 *
 * Layout is inside the scratch page the khook already uses (kdlsym(KERNEL_SYM_DATA_CAVE)):
 *   code  at KH_TR_OFF_CODE  (the trampoline's entry point)
 *   block at KH_TR_OFF_BLOCK (the values below)
 * Both sit in the gap between the khook's chains (<= 0x500) and its big chain
 * (0x3a00); kh_trampoline_layout_ok() and the host tests check that.
 */
#ifndef KH_TRAMPOLINE_BLOCK_H
#define KH_TRAMPOLINE_BLOCK_H

#include <stdint.h>

#include "byepervisor/khook_trampoline_defs.h"

/* The offsets themselves live in khook_trampoline_defs.h, which the assembly also
 * includes, so this file only adds the C-side layout check. */

static inline int kh_trampoline_layout_ok(void) {
  if (KH_TR_OFF_BLOCK <= KH_TR_OFF_CODE)
    return 0;
  if (KH_TR_OFF_BLOCK - KH_TR_OFF_CODE < KH_TR_CODE_SIZE_MIN)
    return 0;
  if (KH_TR_BLOCK_SIZE > 0x1000)
    return 0;
  return 1;
}

#endif /* KH_TRAMPOLINE_BLOCK_H */
