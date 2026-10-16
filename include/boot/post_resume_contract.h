/* post_resume_contract — who continues after the wake, decided rather than assumed.
 *
 * The measurement (docs/1360-khook-death.md, run 2026-10-16 01:25): the console
 * reached standby and survived the resume, while the payload process, elfldr and the
 * helper did not. main.c nevertheless continues the takeover from
 * hv_defeat_1360_post_resume(), i.e. from a process that may not exist.
 *
 * This header makes the choice explicit and fail-closed: the continuation runs in
 * kernel context from the staged chain whenever the chain is staged, and userland is
 * only used when it is *demonstrated* to be alive. "Probably alive" is not an input
 * this interface accepts.
 *
 * Freestanding (stdint only): payload and host tests share it.
 */
#ifndef PL5_POST_RESUME_CONTRACT_H
#define PL5_POST_RESUME_CONTRACT_H

#include <stdint.h>

enum pl5_continuation {
  PL5_CONT_NONE = 0,     /* nothing can continue: refuse and say so */
  PL5_CONT_KERNEL_CHAIN, /* the staged #DB chain continues in kernel context */
  PL5_CONT_USERLAND      /* userland continues, and it was *shown* to be alive */
};

enum pl5_cont_reason {
  PL5_CONT_R_CHAIN_STAGED = 0, /* preferred: no userland needed */
  PL5_CONT_R_USERLAND_PROVEN,  /* userland liveness demonstrated */
  PL5_CONT_R_NO_CHAIN,         /* no chain staged and userland not proven */
  PL5_CONT_R_BAD_INPUT
};

struct pl5_cont_decision {
  enum pl5_continuation owner;
  enum pl5_cont_reason reason;
};

/* What has to be in place before the standby request. A continuation cannot be
 * chosen from a chain that was never staged, so these are checked explicitly rather
 * than implied by the arming call having returned 0. */
enum pl5_stage_item {
  PL5_STAGE_PAGETABLES = 1u << 0, /* identity map for the cave */
  PL5_STAGE_SHELLCODE = 1u << 1,  /* shellcode_hv in the cave */
  PL5_STAGE_LINUX_INFO = 1u << 2, /* struct linux_info + bzImage/initrd in the cave */
  PL5_STAGE_CHAIN = 1u << 3,      /* the takeover chain written */
  PL5_STAGE_GATE = 1u << 4,       /* IDT/IST armed as the last action */
  PL5_STAGE_ALL = (1u << 5) - 1
};

/* The minimum for a kernel-context continuation: everything the chain needs to run
 * after the wake. The gate is deliberately the *last* item, so "staged but not
 * armed" is a state the machine can sit in safely. */
#define PL5_STAGE_BEFORE_SLEEP \
  (PL5_STAGE_PAGETABLES | PL5_STAGE_SHELLCODE | PL5_STAGE_LINUX_INFO | PL5_STAGE_CHAIN)

static inline int pl5_staging_ok(unsigned mask) {
  return (mask & PL5_STAGE_BEFORE_SLEEP) == PL5_STAGE_BEFORE_SLEEP;
}

static inline struct pl5_cont_decision pl5_continuation_choose(unsigned staged_mask,
                                                              int userland_shown_alive) {
  struct pl5_cont_decision d = {PL5_CONT_NONE, PL5_CONT_R_BAD_INPUT};
  if (pl5_staging_ok(staged_mask)) {
    d.owner = PL5_CONT_KERNEL_CHAIN;
    d.reason = PL5_CONT_R_CHAIN_STAGED;
    return d;
  }
  if (userland_shown_alive) {
    /* Only reachable when userland liveness was demonstrated, never inferred. */
    d.owner = PL5_CONT_USERLAND;
    d.reason = PL5_CONT_R_USERLAND_PROVEN;
    return d;
  }
  d.reason = PL5_CONT_R_NO_CHAIN;
  return d;
}

static inline const char *pl5_continuation_text(enum pl5_continuation c) {
  switch (c) {
  case PL5_CONT_KERNEL_CHAIN: return "kernel chain";
  case PL5_CONT_USERLAND:     return "userland (liveness demonstrated)";
  case PL5_CONT_NONE:         return "none: refusing to continue";
  }
  return "?";
}

static inline const char *pl5_cont_reason_text(enum pl5_cont_reason r) {
  switch (r) {
  case PL5_CONT_R_CHAIN_STAGED:    return "chain staged before the sleep";
  case PL5_CONT_R_USERLAND_PROVEN: return "userland shown alive after the wake";
  case PL5_CONT_R_NO_CHAIN:        return "no chain staged and userland not shown alive";
  case PL5_CONT_R_BAD_INPUT:       return "missing staging information";
  }
  return "?";
}

/* A continuation must not be claimed from a log line the payload wrote, because the
 * payload writing it is exactly what is in doubt. Stated as data so a caller cannot
 * quietly substitute "we saw output" for "it is alive". */
static inline int pl5_userland_liveness_acceptable(int wrote_log_line, int process_present,
                                                   int syscall_served) {
  (void)wrote_log_line; /* retained for callers, deliberately not sufficient */
  return process_present && syscall_served;
}

#endif /* PL5_POST_RESUME_CONTRACT_H */
