/* khook_state — the hook's state machine, and the rule for inheriting one.
 *
 * Two problems this file exists to prevent, both observed on hardware:
 *
 *  1. the hook is armed by writing shared CPU structures (IDT[1], the TSS IST
 *     slot). "Is it armed?" is therefore a question about memory that a previous
 *     boot, a previous payload or a crash may have left in any state;
 *  2. a marker in the kernel data cave says "KHOOKED." and the code used to
 *     adopt it silently — which skipped a diagnostic install that was supposed to
 *     run (diag18 reported "no staged hook" because diag17 had set the mark).
 *
 * So: every state transition is named and checked, and inheriting a state is an
 * explicit, verified decision with a safe default (do not inherit).
 *
 * Freestanding: no libc, no PS5 headers. The payload and the host test suite
 * compile this same file, so the model is testable without a console.
 */
#ifndef KH_STATE_H
#define KH_STATE_H

#include <stdint.h>

/* 'KHOOKED.' — the marker the payload writes into the cave. */
#define KH_MARKER_MAGIC 0x4B484F4F4B454401ULL

enum kh_state {
  KH_ST_UNINITIALIZED = 0, /* nothing saved, nothing written */
  KH_ST_STAGED,            /* gate/IST saved, chains written, hook NOT live */
  KH_ST_ARMED,             /* gate + IST point at our chain: live */
  KH_ST_TRIGGERED,         /* our trap was taken and the chain is running */
  KH_ST_RESTORED,          /* gate + IST + DR7 back to the saved values */
  KH_ST_FAILED             /* an error was hit; clean-up still owed */
};

enum kh_event {
  KH_EV_INIT = 0,
  KH_EV_INSTALL,
  KH_EV_ARM,
  KH_EV_TRAP_OURS,
  KH_EV_TRAP_FOREIGN,
  KH_EV_DISARM,
  KH_EV_RESTORE,
  KH_EV_ERROR,
  KH_EV_ADOPT
};

static inline const char *kh_state_name(enum kh_state s) {
  switch (s) {
  case KH_ST_UNINITIALIZED: return "UNINITIALIZED";
  case KH_ST_STAGED:        return "STAGED";
  case KH_ST_ARMED:         return "ARMED";
  case KH_ST_TRIGGERED:     return "TRIGGERED";
  case KH_ST_RESTORED:      return "RESTORED";
  case KH_ST_FAILED:        return "FAILED";
  }
  return "?";
}

/* True while shared CPU structures point at our chain. Payload code must not
 * run for long in these states, and a diagnostic must not start from them. */
static inline int kh_state_is_live(enum kh_state s) {
  return s == KH_ST_ARMED || s == KH_ST_TRIGGERED;
}

/* Transition. Returns 1 and writes *next on success, 0 (and leaves *next
 * untouched) when the event is not valid from that state. */
static inline int kh_state_next(enum kh_state s, enum kh_event ev,
                                enum kh_state *next) {
  enum kh_state n;
  switch (ev) {
  case KH_EV_INIT:
    n = (s == KH_ST_UNINITIALIZED || s == KH_ST_FAILED || s == KH_ST_RESTORED)
            ? KH_ST_STAGED : (enum kh_state)-1;
    break;
  case KH_EV_INSTALL:
    n = (s == KH_ST_STAGED) ? KH_ST_STAGED : (enum kh_state)-1;
    break;
  case KH_EV_ARM:
    n = (s == KH_ST_STAGED || s == KH_ST_RESTORED) ? KH_ST_ARMED
                                                    : (enum kh_state)-1;
    break;
  case KH_EV_TRAP_OURS:
    n = (s == KH_ST_ARMED) ? KH_ST_TRIGGERED : (enum kh_state)-1;
    break;
  case KH_EV_TRAP_FOREIGN:
    /* A trap that is not ours forwards to the original handler and therefore
     * leaves the machine as armed-looking as it was: unsafe. */
    n = (enum kh_state)-1;
    break;
  case KH_EV_DISARM:
    n = (s == KH_ST_TRIGGERED || s == KH_ST_ARMED) ? KH_ST_RESTORED
                                                   : (enum kh_state)-1;
    break;
  case KH_EV_RESTORE:
    n = (s == KH_ST_ARMED || s == KH_ST_STAGED || s == KH_ST_FAILED ||
         s == KH_ST_TRIGGERED) ? KH_ST_RESTORED : (enum kh_state)-1;
    break;
  case KH_EV_ERROR:
    n = (s == KH_ST_UNINITIALIZED) ? (enum kh_state)-1 : KH_ST_FAILED;
    break;
  case KH_EV_ADOPT:
    n = (s == KH_ST_UNINITIALIZED) ? KH_ST_ARMED : (enum kh_state)-1;
    break;
  }
  if ((int)n < 0)
    return 0;
  *next = n;
  return 1;
}

/* Why an inherited marker may or may not be adopted. Kept as named reasons so a
 * diagnostic can print the one that applied instead of a bare "not adopted". */
enum kh_adopt_reason {
  KH_ADOPT_OK = 0,
  KH_ADOPT_DISABLED,      /* the build does not allow inheriting at all */
  KH_ADOPT_NO_MARKER,     /* the cave holds something else */
  KH_ADOPT_EPOCH_MISMATCH,/* the marker is from a different boot/run */
  KH_ADOPT_NO_EVIDENCE    /* the escape is not actually still in effect */
};

/* Decide whether to adopt an inherited armed state.
 *
 *  marker         value read from the cave's marker slot
 *  epoch_matches  caller's proof that the marker belongs to this run
 *  live_evidence  the escape is still in effect (e.g. .text PTE has no XOTEXT)
 *  allow_adopt    build-level opt-in (PL5_1360_ADOPT_ARMED); 0 by default
 *
 * Adoption requires all four. A marker alone is never enough: it is a claim
 * about memory that may since have been reused.
 */
static inline enum kh_adopt_reason kh_marker_adopt(uint64_t marker,
                                                   int epoch_matches,
                                                   int live_evidence,
                                                   int allow_adopt) {
  if (!allow_adopt)
    return KH_ADOPT_DISABLED;
  if (marker != KH_MARKER_MAGIC)
    return KH_ADOPT_NO_MARKER;
  if (!epoch_matches)
    return KH_ADOPT_EPOCH_MISMATCH;
  if (!live_evidence)
    return KH_ADOPT_NO_EVIDENCE;
  return KH_ADOPT_OK;
}

static inline const char *kh_adopt_reason_text(enum kh_adopt_reason r) {
  switch (r) {
  case KH_ADOPT_OK:             return "adopted";
  case KH_ADOPT_DISABLED:       return "inheriting a state is disabled in this build; installing fresh";
  case KH_ADOPT_NO_MARKER:      return "no armed marker; installing fresh";
  case KH_ADOPT_EPOCH_MISMATCH: return "armed marker from another run; installing fresh";
  case KH_ADOPT_NO_EVIDENCE:    return "armed marker but the escape is not in effect; installing fresh";
  }
  return "not adopted";
}

#endif /* KH_STATE_H */
