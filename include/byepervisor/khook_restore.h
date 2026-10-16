/* khook_restore — what must be written back, and how it is known to be back.
 *
 * The hook is installed by overwriting shared CPU structures (IDT[1], the TSS IST
 * slot) and by leaving DR7 configured. Every path that leaves those overwritten is
 * a path on which an unrelated trap can be misrouted, so "restore" is not a
 * courtesy at the end of the happy path: it is owed by *every* exit, including the
 * failure returns of kh_install()/kh_arm() and the foreign-trap path.
 *
 * This header is the planner: given a state and the saved values it says what has to
 * be written back, refuses when the values were never captured, and checks the
 * read-back. Freestanding: stdint only, shared by payload and host tests.
 */
#ifndef KH_RESTORE_H
#define KH_RESTORE_H

#include <stdint.h>

#include "byepervisor/khook_state.h"

/* Written before the first write to shared state, never after. */
struct kh_saved_state {
  int valid;       /* all four values were captured */
  uint64_t gate_lo; /* IDT[1] low qword, as found */
  uint64_t gate_hi; /* IDT[1] high qword, as found */
  uint64_t ist;     /* TSS IST slot for our index, as found */
  uint64_t dr7;     /* DR7 as found (0 if it was already 0) */
};

enum kh_restore_step {
  KH_RESTORE_GATE = 1u << 0,
  KH_RESTORE_IST = 1u << 1,
  KH_RESTORE_DR7 = 1u << 2,
  KH_RESTORE_ALL = (1u << 3) - 1
};

struct kh_restore_plan {
  int ok;            /* 0 = do not proceed: the plan cannot restore what is needed */
  unsigned steps;    /* bitset of kh_restore_step */
  const char *why;   /* diagnostic */
};

static inline int kh_saved_state_ok(const struct kh_saved_state *s) {
  /* A zero gate_lo means "nothing was ever read", and a zero IST slot likewise:
   * kcs is derived from gate_lo bits, so a zero there is not a valid saved gate. */
  return s && s->valid && s->gate_lo != 0 && s->ist != 0;
}

/* Plan the restore for a state.
 *
 * UNINITIALIZED: nothing was saved, so there is nothing to restore -- and the plan
 * is not "ok", because a caller must not treat "no writes needed" as "the machine is
 * in its original state". It is only ok when the saved values are actually valid. */
static inline struct kh_restore_plan kh_restore_plan_for(enum kh_state st,
                                                         const struct kh_saved_state *saved) {
  struct kh_restore_plan p = {0, 0, "?"};
  switch (st) {
  case KH_ST_UNINITIALIZED:
    p.why = kh_saved_state_ok(saved) ? "nothing was armed; nothing to restore"
                                     : "no saved state; nothing can be restored";
    p.ok = kh_saved_state_ok(saved);
    return p;
  case KH_ST_STAGED:
  case KH_ST_ARMED:
  case KH_ST_TRIGGERED:
  case KH_ST_FAILED:
    if (!kh_saved_state_ok(saved)) {
      p.ok = 0;
      p.why = "saved gate/IST missing: refusing, the original state cannot be restored";
      return p;
    }
    p.ok = 1;
    p.steps = KH_RESTORE_GATE | KH_RESTORE_IST | KH_RESTORE_DR7;
    p.why = "restore gate, IST and DR7";
    return p;
  case KH_ST_RESTORED:
    p.ok = 1;
    p.steps = 0;
    p.why = "already restored";
    return p;
  }
  p.ok = 0;
  p.why = "unknown state";
  return p;
}

/* Read-back check: 1 only when all three values are back where they were. */
static inline int kh_restore_verified(const struct kh_saved_state *saved, uint64_t gate_lo,
                                      uint64_t gate_hi, uint64_t ist) {
  if (!kh_saved_state_ok(saved))
    return 0;
  return gate_lo == saved->gate_lo && gate_hi == saved->gate_hi && ist == saved->ist;
}

/* DR7 is only owed when it was changed; an untouched DR7 that reads back as its
 * saved value is fine either way, so the check is "equals saved", not "is zero". */
static inline int kh_dr7_restored(const struct kh_saved_state *saved, uint64_t dr7) {
  return saved && dr7 == saved->dr7;
}

#endif /* KH_RESTORE_H */
