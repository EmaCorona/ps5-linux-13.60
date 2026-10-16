# 13.60 khook design — how the `#DB` hook must behave before it is armed again

**Status:** design for review. **No console test may use this hook until this document is approved
and the static checks below pass.** The measurements that force the design are in
[`1360-khook-death.md`](1360-khook-death.md) and [`1360-port-status.md`](1360-port-status.md).

## 1. What is actually installed today

`source/byepervisor/khook.c` (vendored, AGPL-3.0-or-later) does two writes to shared, global state:

| write | effect |
| --- | --- |
| `IDT[1]` (#DB), low+high qword, in `kh_install()` / `kh_arm()` | the #DB gate now points at `KERNEL_GADGET_PIVOT_ADD_RSP28_RET` with `ist_index` |
| `TSS.IST[ist_index]` | the IST entry now points at `scratch + KH_OFF_CHAIN_ARM` |

Both are global to the machine (per core only in the sense that each core has its own TSS/IST, but the
IDT is shared). There is nothing in the gate that identifies *whose* trap it is: the gate is taken by
**any** #DB on that core — another process single-stepping, a debugger, an unrelated kernel `#DB` —
and the chain then runs against a frame it did not expect.

The chain itself assumes that assumption: `kh_install()` builds the dispatcher chain for
`frame_base = disp_chain - 0x28`, a **fixed** address in the scratch page, because the trigger is the
payload's own single-step (`kh_trigger()`: `pushfq; orq $0x100,(%rsp); popfq; nop` → #DB at a known
RIP). A foreign trap does not produce that frame, so the chain rewrites RIP/RSP of an unrelated
context. That is the mechanism behind the observed collateral damage: services disappearing, and one
run powering the console off.

`kh_restore()` writes the saved gate and IST back, which bounds the window but does not close the
race: an unrelated #DB arriving between arm and restore is still misrouted.

## 2. Invariants the design must establish

1. **A trap that is not ours never enters the takeover chain.** Not "rarely" — the chain must be
   unreachable unless the interrupted context is the one the payload created.
2. **A foreign trap is forwarded, not swallowed.** The original `#DB` handler address is known
   (`saved_gate_lo/hi`), and the CPU frame on the IST stack is the same shape as the one the original
   handler expects, so forwarding is possible: undo the gate's own stack consumption and jump to the
   original handler.
3. **Fail-closed on every inconsistency.** Any check that cannot be completed (unreadable gate,
   unknown handler, cookie mismatch, unexpected core) results in forwarding and disarming, never in
   running the chain.
4. **Bounded armed window.** The hook is armed for the shortest span that works and disarms at the
   first trap (`oneshot`), not "until someone calls `kh_restore()`".
5. **Always restorable.** The pre-arm gate, IST and DR7 values are saved before any write and are
   written back on every exit path, including the failure paths of `kh_arm`/`kh_install`.
6. **One core at a time.** The takeover runs on the core that was armed; other cores keep their
   original gate and IST.
7. **No live `#DB` diagnosis by trial.** A build that arms the hook is not a "routine" test
   (see [`LIVE-READ-POLICY.md`](LIVE-READ-POLICY.md) for the same reasoning about reads).

## 3. State model

Shared with Task 14, which turns it into code and host tests:

```
UNINITIALIZED --kh_init--> STAGED --kh_install(SKIP_IST|SKIP_GATE)--> STAGED(ready)
STAGED(ready) --kh_arm--> ARMED --#DB(ours)--> TRIGGERED --oneshot--> DISARMED
ARMED --#DB(foreign)--> FORWARDED --restore--> DISARMED
ARMED --error/timeout--> DISARMED (restore of gate+IST+DR7)
any --kh_restore--> DISARMED ;  DISARMED --kh_arm--> ARMED
```

`RESTORED`/`DISARMED` are the only states in which payload code may run for a long time. An inherited
`ARMED` marker from an earlier run must never be adopted as "the hook is live": the marker is a claim
about memory that may since have been reassigned (this already caused one invalidated diagnostic —
`ba69afa` in the history).

## 4. Proposed chain: two stages, one owner check

**Stage 0 — arming (payload, per core).**
Save `IDT[1]` and `TSS.IST[ist]`. Write a per-core cookie into the scratch page
(`{magic, core_id, seq, expected_rip, gate_snapshot_hash}`) and set `DR7` so the breakpoint fires on
the intended instruction only. Then arm.

**Stage 1 — gate trampoline (first thing the CPU runs on #DB).**
It must decide before it touches the frame:

| test | source of truth | on failure |
| --- | --- | --- |
| the gate is the one we wrote | re-read `IDT[1]`, compare against our encoding | forward + restore |
| our core and our cookie | scratch page, per-core, written immediately before arming | forward |
| the trap is the expected one | `DR6.BS` set, and the interrupted RIP is the recorded `expected_rip` | forward |
| the frame is where we expect it | the IST frame's CS/RIP match the armed context | forward |
| a previous trap did not already run | the cookie's `seq` and the `oneshot` disarm flag | forward + restore |

**Forwarding = `add rsp, 0x28+8; jmp <saved_gate_handler>`.** The gate's pivot gadget consumed
`0x28` and `pop rbp` consumed another 8, so adding `0x30` puts the stack back to the layout the
original handler expects, and the original handler runs exactly as if we had never been installed.

**Stage 2 — takeover chain (only after Stage 1 says yes).** Unchanged from today: the dispatcher
chain, the handler chain, `emit_resume_tail()`, `oneshot` → `DR7 = 0`.

The important property is that Stage 1 is a *separate, small, verifiable* piece: it can be written in
freestanding C, unit-tested on the host against a synthetic gate/frame, and reviewed without reading
the ROP chain.

## 5. Alternatives considered

| option | why not (yet) |
| --- | --- |
| **Leave the global gate and add a longer timeout** | the failure is a race, not a duration; a longer timeout widens the exposure |
| **Arm the IST only, leave `IDT[1]` alone** | the CPU enters the original handler, not our chain; nothing is gained |
| **Hook a kernel function instead of the exception gate** (the 13.20 shape, `khook` on `KERNEL_SYM_HV_MP_STARTUP_CALL`) | this is the direction most likely to be safe and is what the 13.20 path does; on 13.60 the hook target's role and the resume contract still have to be established (Task 15). Worth prototyping behind a build flag with Stage 1 as the fallback. |
| **Per-task `DR` breakpoints only (no IDT change)** | `DR7` is per-CPU, not per-thread, when set from the kernel; the same misrouting applies to `#DB` handling |
| **Do nothing and document the hazard** | acceptable only if the port is declared non-viable on 13.60; not the current goal |

## 6. Fail-safe behaviour

- `kh_arm()` verifies by read-back that the gate and IST are exactly the values it wrote; on any
  mismatch it restores and returns an error (`-5`, `-6` today) instead of continuing.
- The trampoline's default path is **forward**, so a bug in the ownership check degrades to "the hook
  does nothing", not to "an unrelated process is hijacked".
- `oneshot` disarms in the first trap; a second trap can only occur if the first one did not run,
  which is itself an error state.
- Every error path restores gate, IST and `DR7` before returning to payload code.
- If the console survives but the hook did not fire, the diagnostic must say so — a completed
  heartbeat is not evidence that the hook worked (`Task 26`).

## 7. Static checks required before the next console session

1. The ownership test is exercised by host unit tests with synthetic frames: ours, foreign,
   wrong core, stale cookie, gate changed underneath us, second trap after disarm.
2. The forward path is verified to leave the frame exactly as the original handler expects
   (offset arithmetic asserted in the test, not by inspection).
3. `docs/1360-khook-death.md`'s signature is re-read and each of its stopped-orderings is mapped to
   the invariant it violates.
4. A build with `PL5_DIAG` set to a value that arms the hook cannot be produced by accident: the
   arming stage must be behind an explicit flag with its own `#error` guard, and a default build must
   leave the hook unarmed (same pattern as `PL5_1360_TAKEOVER`).
5. `tools/check_payload_static.py` extended to assert that a default build contains no arming marker.

Until 1–5 pass, the answer to "can we try the hook on the console?" is **no**.

## 8. Open questions this document does not answer

- Which kernel function is the 13.60 equivalent of the 13.20 hook target, and whether the same
  function is reached on this firmware (Analysis: Task 15 / Task 23 style, no console).
- Whether the `rdrand`/`oneshot` disarm is atomic enough with respect to a second core entering the
  gate at the same time (the gate is shared; the disarm is per-core).
- Whether the console's `#DB` vector is used by anything else in the guest at all, which would
  decide between "harden the gate" and "abandon the gate".
