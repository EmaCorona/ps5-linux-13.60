/* khook_ownership — is this #DB ours, or somebody else's?
 *
 * The measured failure this exists to remove: the gate is global, so any #DB on the
 * core reaches the chain, and the chain then rewrites RIP/RSP of a context it did
 * not create (services killed, one run powered the console off). See
 * docs/1360-khook-design.md.
 *
 * The rule implemented here is fail-closed in one direction only: a trap is treated
 * as ours **only** when every condition that identifies our own trigger holds. Every
 * other outcome -- unreadable gate, stale cookie, wrong core, already disarmed,
 * missing DR6.BS, unexpected RIP/CS -- is FOREIGN, and FOREIGN means "forward to the
 * original handler and restore", never "run the chain".
 *
 * Freestanding: stdint only, compiled by the payload and by the host test suite.
 */
#ifndef KH_OWNERSHIP_H
#define KH_OWNERSHIP_H

#include <stdint.h>

#include "byepervisor/khook_frame.h"

/* Written by the payload into the per-core scratch area immediately before the
 * trigger, cleared by the chain. */
#define KH_TRAP_COOKIE_MAGIC 0x4B48434F4F4B4945ULL /* "KHCOOKIE" */

enum kh_trap_decision {
  KH_TRAP_OURS = 0,
  KH_TRAP_FOREIGN
};

enum kh_trap_reason {
  KH_TRAP_R_OK = 0,
  KH_TRAP_R_BAD_INPUT,     /* the context could not be read: treat as foreign */
  KH_TRAP_R_GATE_CHANGED,  /* IDT[1] is not the encoding we installed */
  KH_TRAP_R_NOT_ARMED,     /* the chain says it is not live (already disarmed) */
  KH_TRAP_R_NO_BS,         /* DR6.BS clear: this trap was not a breakpoint */
  KH_TRAP_R_BAD_COOKIE,    /* the scratch cookie is not ours */
  KH_TRAP_R_WRONG_CORE,    /* a different core entered our gate */
  KH_TRAP_R_STALE_SEQ,     /* a trap from a previous arming */
  KH_TRAP_R_RIP_MISMATCH,  /* interrupted RIP is not the recorded resume RIP */
  KH_TRAP_R_CS_MISMATCH,   /* interrupted CS is not the recorded CS */
  KH_TRAP_R_NO_TF          /* our trigger sets TF; RFLAGS does not have it */
};

struct kh_trap_context {
  /* read from the frame at the gate */
  uint64_t frame_rip;
  uint64_t frame_cs;
  uint64_t frame_rflags;
  /* CPU / scratch state */
  int dr6_bs;        /* DR6.BS (breakpoint) set */
  int armed;         /* the chain's live flag */
  int gate_is_ours;  /* IDT[1] still equals our encoding */
  uint32_t core_id;  /* the core executing the gate */
  uint32_t cookie_core;
  uint64_t cookie_magic;
  uint64_t cookie_seq;
  /* what the arming recorded */
  uint32_t expect_core;
  uint64_t expect_seq;
  uint64_t expect_rip;
  uint64_t expect_cs;
};

struct kh_trap_verdict {
  enum kh_trap_decision decision;
  enum kh_trap_reason reason;
};

static inline const char *kh_trap_reason_text(enum kh_trap_reason r) {
  switch (r) {
  case KH_TRAP_R_OK:            return "ours";
  case KH_TRAP_R_BAD_INPUT:     return "context unreadable";
  case KH_TRAP_R_GATE_CHANGED:  return "IDT[1] is not our gate any more";
  case KH_TRAP_R_NOT_ARMED:     return "the hook is not armed (already disarmed?)";
  case KH_TRAP_R_NO_BS:         return "DR6.BS clear: not a breakpoint trap";
  case KH_TRAP_R_BAD_COOKIE:    return "scratch cookie is not ours";
  case KH_TRAP_R_WRONG_CORE:    return "trap taken on another core";
  case KH_TRAP_R_STALE_SEQ:     return "trap belongs to a previous arming";
  case KH_TRAP_R_RIP_MISMATCH:  return "interrupted RIP is not our resume RIP";
  case KH_TRAP_R_CS_MISMATCH:   return "interrupted CS is not our CS";
  case KH_TRAP_R_NO_TF:         return "RFLAGS.TF is not set";
  }
  return "?";
}

/* Decide. Order is deliberate: cheapest and most decisive first, so a diagnostic
 * names the check that actually failed rather than a downstream consequence. */
static inline struct kh_trap_verdict kh_trap_decide(const struct kh_trap_context *c) {
  struct kh_trap_verdict v = {KH_TRAP_FOREIGN, KH_TRAP_R_BAD_INPUT};
  if (!c)
    return v;

  if (!c->gate_is_ours) {
    v.reason = KH_TRAP_R_GATE_CHANGED;
    return v;
  }
  if (!c->armed) {
    v.reason = KH_TRAP_R_NOT_ARMED;
    return v;
  }
  if (!c->dr6_bs) {
    v.reason = KH_TRAP_R_NO_BS;
    return v;
  }
  if (c->cookie_magic != KH_TRAP_COOKIE_MAGIC) {
    v.reason = KH_TRAP_R_BAD_COOKIE;
    return v;
  }
  if (c->cookie_core != c->expect_core || c->core_id != c->expect_core) {
    v.reason = KH_TRAP_R_WRONG_CORE;
    return v;
  }
  if (c->cookie_seq != c->expect_seq) {
    v.reason = KH_TRAP_R_STALE_SEQ;
    return v;
  }
  if (c->frame_rip != c->expect_rip) {
    v.reason = KH_TRAP_R_RIP_MISMATCH;
    return v;
  }
  if (c->frame_cs != c->expect_cs) {
    v.reason = KH_TRAP_R_CS_MISMATCH;
    return v;
  }
  if ((c->frame_rflags & KH_RFLAG_TF) == 0) {
    v.reason = KH_TRAP_R_NO_TF;
    return v;
  }
  v.decision = KH_TRAP_OURS;
  v.reason = KH_TRAP_R_OK;
  return v;
}

/* A foreign trap must not be "handled" silently: the caller forwards it and
 * restores. This states the two actions as data so a caller cannot do one without
 * the other. */
struct kh_foreign_action {
  int forward_to_original; /* jmp saved_gate_handler with the frame untouched */
  int restore_after;       /* write back gate, IST and DR7 */
  int disarm;              /* do not stay armed after a foreign trap */
};

static inline struct kh_foreign_action kh_foreign_action_for(int decision) {
  struct kh_foreign_action a = {0, 0, 0};
  if (decision != KH_TRAP_OURS) {
    a.forward_to_original = 1;
    a.restore_after = 1;
    a.disarm = 1;
  }
  return a;
}

#endif /* KH_OWNERSHIP_H */
