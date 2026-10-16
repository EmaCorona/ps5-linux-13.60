# Post-resume contract — who owns control before, during and after standby

**Status:** the current implementation encodes an assumption the hardware has already contradicted.
This document states what is measured, what the code assumes, the model that does not depend on the
assumption, and how continuity gets verified without a live payload process.

## 1. What is measured

From [`1360-khook-death.md`](1360-khook-death.md) (run 2026-10-16 01:25, console 13.60.0007,
`PL5_DIAG=18` arm-late):

| observation | value |
| --- | --- |
| console reaches the standby request | yes |
| console enters rest mode | yes |
| console survives the resume | yes (ping OK after the operator woke it) |
| `/data/plinux5.log` after the wake | ends at `high-FW: sceSystemStateMgrEnterStandby()...` — no `[W0]`, no `[W]`, no post-resume marker |
| `elfldr`, `ps5upload` helper after the wake | gone |

The second reading is the decisive one: **the payload process did not survive the sleep**, and
neither did anything else in userland. The log file itself survives (it is on disk), which is why the
absence of new lines is evidence rather than a lost artifact.

It also contradicts an earlier observation where `PL5_DIAG=5` (escape only) reported the payload
continuing after the resume. The prime suspect is the switch to the official
`sceSystemStateMgrEnterStandby()` path for `fw >= 0x0800` — chosen because it actually invalidates the
TLB across the cycle, which the escape needs — versus the legacy event-flag rest mode. That
contradiction is not resolved by this document; it is listed as the experiment to run first.

## 2. What the code assumes today

```c
/* source/main.c, after the wake */
if (is_1320) hv_defeat_1320_post_resume();
if (is_1360) hv_defeat_1360_post_resume();
```

`hv_defeat_1360_post_resume()` waits for the trap, and afterwards writes the takeover blob to the
hook site and continues the takeover (`13.60: [P1] writing takeover blob`). Every one of those steps
runs in **userland, after the resume** — i.e. in a process the measurement says is not there.

The staging that does happen before the sleep is already kernel-side and survives by construction:
`stage_hv_boot()` writes the identity page tables, `shellcode_hv`, `linux_info` and the bzImage into
the identity-mapped cave **before** the standby request.

So the design contains both kinds of work and puts the wrong half on the wrong side of the sleep.

## 3. Ownership table (target)

| phase | owner | state | evidence it works |
| --- | --- | --- | --- |
| before standby | userland payload | stages page tables, `shellcode_hv`, `linux_info`, images into the cave; saves the gate/IST; **arms nothing yet** | already demonstrated (`diag18` reaches standby) |
| at the standby request | userland payload | arms the hook (gate + IST) as the last action, then asks for standby | `arm-late: kh_arm rc=0` observed |
| during the sleep | nobody | — | — |
| first #DB after the wake | **kernel context**, via the hook chain | decides ours/foreign, then runs the takeover | *not yet demonstrated* |
| takeover | **kernel context** | patches the VMMCALL handler, then enters `shellcode_hv` in the cave | *not yet demonstrated* |
| after the handoff | `shellcode_hv` → Linux | boots | *not yet demonstrated* |

The only thing userland needs to have done correctly is the pre-sleep staging and the arming. After
that, userland liveness is irrelevant.

## 4. The change this implies

1. Move the takeover-blob write from `post_resume()` into `stage_hv_boot()` (pre-sleep staging). The
   blob's destination is known before the sleep; nothing about it needs the post-resume process.
2. Make the trap chain do what `post_resume()` does today: after the ownership check
   ([`1360-khook-design.md`](1360-khook-design.md)), run the takeover and enter `shellcode_hv`.
   The chain already runs in kernel context with kernel read/write available.
3. Delete the dependency, not just the symptom: `hv_defeat_1360_post_resume()` must not be the only
   path that continues the boot. If the process *does* survive, it may observe and log; it must not
   be required.
4. Keep the standby mechanism as a separate variable: the `sceSystemStateMgrEnterStandby()` vs
   legacy event-flag difference is what decides whether *any* userland survives, and it is the one
   thing worth measuring on its own (below).

None of this is done yet. Task 15 stops at the contract because the change depends on the hook
design (Task 13) being approved first — a chain that misroutes foreign traps must not be the thing
that takes over the boot.

## 5. How continuity is verified without a live payload

The verification cannot be "the payload logged something after the wake", because that is exactly
what is in doubt. What can be checked, in increasing strength:

| level | what it shows | how |
| --- | --- | --- |
| standby reached | the payload's last line is the standby request | `/data/plinux5.log` (survives) |
| trap taken after the wake | a marker the **chain** writes into the kernel cave changes | read the cave marker on the next run, or let the chain print through a kernel channel |
| escape still in effect | the `.text` PTE has no XOTEXT after the wake | page-table read (allowed region), not a `.text` read |
| boot attempt started | the console leaves the guest — screen/reset behaviour, `shellcode_hv`'s checkpoint | planned `PL5_HV_STOP` checkpoints |
| Linux reached | the kernel entry evidence in Task 30 | serial/GUI output, not a payload log |

Levels 2–3 are what the design must provide before any hardware session: they are readable without a
live userland process.

**Do not** verify continuity by raising a timeout. A longer wait does not create a process.

## 6. The one experiment to run first (when hardware testing resumes)

Single variable, one session, per [`1360-khook-design.md`](1360-khook-design.md) §7 gates:

> On the same firmware and the same build, run the **same** sleep cycle once through
> `sceSystemStateMgrEnterStandby()` and once through the legacy event-flag rest mode, with the hook
> **not armed** in both, and compare what userland is alive after the wake.

That answers "does anything userland survive at all, and does the mechanism decide it" — a fact the
whole design turns on — without arming anything. Everything else in this document is downstream of
that answer.
