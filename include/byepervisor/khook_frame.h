/* khook_frame — the exception frame the #DB gate actually sees, and the pivot contract.
 *
 * Why this file exists: the design first described the gate's pivot as
 * `add rsp, 0x28; pop rbp; ret` (the name of the offset field is
 * GAD_ADD_RSP_28_POP_RBP_RET), and derived the forwarding arithmetic from it. The
 * field name is wrong: the dump-verified bytes at that address are
 *
 *     48 83 c4 28    add rsp, 0x28
 *     f3 c3          rep ret
 *
 * which is five qwords skipped and a return -- there is no `pop rbp`, and the
 * order matters for anything that touches the frame. This header is the single
 * place that states the layout, so a design sentence and the code cannot drift
 * apart silently again.
 *
 * Freestanding (stdint only): the payload and the host test suite compile the
 * same file.
 */
#ifndef KH_FRAME_H
#define KH_FRAME_H

#include <stdint.h>

/* What the CPU pushes for #DB (vector 1) when the gate has an IST.
 * #DB has no error code, so the frame is exactly five qwords, pushed in this
 * order (highest address first): SS, RSP, RFLAGS, CS, RIP.
 * On entry to the gate, RSP points at RIP -- the frame occupies
 * [RSP, RSP + 0x28). */
#define KH_DB_FRAME_QWORDS 5
#define KH_DB_FRAME_BYTES (KH_DB_FRAME_QWORDS * 8) /* 0x28 */

#define KH_FRAME_RIP_OFF 0x00
#define KH_FRAME_CS_OFF 0x08
#define KH_FRAME_RFLAGS_OFF 0x10
#define KH_FRAME_RSP_OFF 0x18
#define KH_FRAME_SS_OFF 0x20

/* What the pivot gadget consumes before it returns into the staged chain. */
#define KH_PIVOT_SKIP_BYTES KH_DB_FRAME_BYTES

/* RFLAGS.TF is set by the payload's own trigger; RF is what the chain sets so the
 * instruction it resumes at does not re-trigger. */
#define KH_RFLAG_TF 0x00000100ULL
#define KH_RFLAG_RF 0x00010000ULL

struct kh_frame {
  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
  uint64_t rsp;
  uint64_t ss;
};

static inline uint64_t kh_frame_load64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++)
    v |= (uint64_t)p[i] << (8 * i);
  return v;
}

/* Parse a frame from the bytes the gate finds at RSP. */
static inline void kh_frame_parse(const uint8_t *at_rsp, struct kh_frame *out) {
  out->rip = kh_frame_load64(at_rsp + KH_FRAME_RIP_OFF);
  out->cs = kh_frame_load64(at_rsp + KH_FRAME_CS_OFF);
  out->rflags = kh_frame_load64(at_rsp + KH_FRAME_RFLAGS_OFF);
  out->rsp = kh_frame_load64(at_rsp + KH_FRAME_RSP_OFF);
  out->ss = kh_frame_load64(at_rsp + KH_FRAME_SS_OFF);
}

/* Where the frame sits relative to the value written into the TSS IST slot: the
 * CPU loads RSP = IST, then pushes, so the frame base is IST - 0x28. */
static inline uint64_t kh_frame_base_for_ist(uint64_t ist_value) {
  return ist_value - KH_DB_FRAME_BYTES;
}

/* RSP the original #DB handler must see.
 *
 * The design requires the gate to point at our trampoline, not at the pivot, so
 * the trampoline is entered with RSP already at the frame base and forwarding is
 * a plain jump -- the frame is exactly as the CPU left it.
 *
 * If a check is instead reached *after* the pivot (gate still pointing at the
 * pivot, check later in the chain), the rewind is larger and in the other
 * direction. Both are stated here so neither is guessed, and the difference is
 * exactly why the trampoline-first arrangement is the one required. */
static inline uint64_t kh_forward_rsp_direct(uint64_t rsp_at_trampoline_entry) {
  return rsp_at_trampoline_entry;
}

static inline uint64_t kh_forward_rsp_after_pivot(uint64_t rsp_after_pivot_ret) {
  return rsp_after_pivot_ret - KH_PIVOT_SKIP_BYTES - 8;
}

/* Contract self-check: 0 when the constants agree with each other. The host test
 * calls it, so a future edit that changes one value and not the others fails in
 * the suite instead of on a console. */
static inline int kh_frame_contract_ok(void) {
  if (KH_DB_FRAME_BYTES != 0x28)
    return 0;
  if (KH_DB_FRAME_QWORDS != 5)
    return 0;
  if (KH_FRAME_SS_OFF + 8 != KH_DB_FRAME_BYTES)
    return 0;
  if (KH_PIVOT_SKIP_BYTES != KH_DB_FRAME_BYTES)
    return 0;
  if (!(KH_FRAME_RIP_OFF == 0 && KH_FRAME_CS_OFF == 8 &&
        KH_FRAME_RFLAGS_OFF == 16 && KH_FRAME_RSP_OFF == 24 &&
        KH_FRAME_SS_OFF == 32))
    return 0;
  return 1;
}

/* The pivot's identity, as verified from the capture by
 * tools/verify_off_1360_dump.py: 48 83 c4 28 f3 c3. Kept here so the design's
 * claim and the verifier's expectation are the same statement. */
static const uint8_t KH_PIVOT_BYTES[6] = {0x48, 0x83, 0xc4, 0x28, 0xf3, 0xc3};

static inline int kh_pivot_is_pure_skip(const uint8_t *bytes, int n) {
  if (n != (int)sizeof(KH_PIVOT_BYTES))
    return 0;
  for (int i = 0; i < n; i++)
    if (bytes[i] != KH_PIVOT_BYTES[i])
      return 0;
  return 1;
}

#endif /* KH_FRAME_H */
