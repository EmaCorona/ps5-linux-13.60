/* pl5_dump_policy — the one place that decides what a live payload may read.
 *
 * Read this before adding a read path. The rule it encodes is not a style
 * preference: reading kernel .text on firmware 13.60 powers the console off
 * (docs/1360-port-status.md, docs/1360-khook-death.md), so the decision must be
 * made in code that runs *before* the read, and it must be impossible to skip by
 * forgetting a flag. The same logic is compiled into the payload and exercised
 * by tests/run_tests.py on the host, so the refusal is testable without a
 * console.
 *
 * Offline analysis of a kernel capture is a different activity and is not
 * governed here: tools/verify_off_1360_dump.py re-derives the values from a file
 * on disk and never touches a console.
 */
#ifndef PL5_DUMP_POLICY_H
#define PL5_DUMP_POLICY_H

#include <stdint.h>

/* The firmware whose .text read is fatal. 13.60 only: on 13.20 the escape
 * clears XOTEXT and the post-resume read is the documented, working path. */
#define PL5_FW_FATAL_TEXT 0x1360u

enum pl5_region { /* distinct names: sigtable_*.h owns PL5_REGION_* */
  PL5_REG_TEXT = 0, /* kernel .text: the fatal one */
  PL5_REG_DATA,     /* kernel data */
  PL5_REG_HV        /* hypervisor reservation, reached through the direct map */
};

enum pl5_decision {
  PL5_ALLOW = 0,
  PL5_REFUSE_FW_TEXT,      /* .text on firmware PL5_FW_FATAL_TEXT */
  PL5_REFUSE_NOT_COMMITTED,/* a live read with no explicit commit marker */
  PL5_REFUSE_FW_MISMATCH   /* not the firmware this payload was built for */
};

/* True when reading kernel .text on this firmware is known to be fatal. */
static inline int pl5_text_read_is_fatal(uint32_t fwv) {
  return fwv == PL5_FW_FATAL_TEXT;
}

/* Decide one read.
 *
 *  fwv          firmware version (0x1360, 0x1320, ...)
 *  build_fw     PL5_SIGTABLE_FW: the firmware this payload's tables were built
 *               for. A mismatch is refused outright: the offsets would be wrong
 *               even where the read itself is safe.
 *  region       what is about to be read
 *  committed    non-zero only when the operator left the explicit commit marker
 *               on the console. Dry run is the default so that launching the
 *               payload has no effect by itself.
 */
static inline enum pl5_decision pl5_decide(uint32_t fwv, uint32_t build_fw,
                                           enum pl5_region region,
                                           int committed) {
  if (build_fw != 0 && fwv != build_fw)
    return PL5_REFUSE_FW_MISMATCH;
  if (!committed)
    return PL5_REFUSE_NOT_COMMITTED;
  if (region == PL5_REG_TEXT && pl5_text_read_is_fatal(fwv))
    return PL5_REFUSE_FW_TEXT;
  return PL5_ALLOW;
}

/* Human-readable reason, for the notification the console prints. */
static inline const char *pl5_decision_text(enum pl5_decision d) {
  switch (d) {
  case PL5_ALLOW:
    return "allowed";
  case PL5_REFUSE_FW_TEXT:
    return "REFUSED: reading kernel .text on 13.60 powers this console off";
  case PL5_REFUSE_NOT_COMMITTED:
    return "dry run: no commit marker, nothing will be read";
  case PL5_REFUSE_FW_MISMATCH:
    return "REFUSED: firmware does not match this payload's offset tables";
  }
  return "REFUSED: unknown decision";
}

#endif /* PL5_DUMP_POLICY_H */
