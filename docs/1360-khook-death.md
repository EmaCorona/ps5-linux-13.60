# Why the armed khook kills this console (13.60)

**Status: cause identified, fix not implemented.** This document is the evidence trail for the
single problem that currently blocks 13.20-style escapes from surviving on 13.60. It is written so
the conclusion can be re-checked, not taken on trust.

## The symptom

With the escape armed (`.text` writable, `XOTEXT` cleared, khook installed on the S3-resume
`HV_MP_STARTUP_CALL` path, no RSI redirect), the console:

* **powers off cleanly** — LED off, no panic screen, no sound, no restart loop (operator
  observation);
* the network drops with it, so it is a real power-off and not rest mode;
* the payload's own log stops after the install has already reported success.

So the failure is **not** a faulting `#DB`, a bad vector or garbage payload — those hang or panic.
An *orderly* shutdown is what a supervisor or a watchdog decides.

## Timing: it is not the suspend

The first instinct — "DR7 does not survive S3" — does not fit. The console dies **before
`sceSystemStateMgrEnterStandby()` is ever called**: that log line is absent, and a run that
installs and then simply waits dies too.

The last log line of the most explicit run (`PL5_DIAG=15`, read from `/data/plinux5.log` on disk
after the power-off):

```text
[000028] [E] core=15 ktext=0xffffffff9de60000 scratch=0xffffffffa0b99000 tgt=0xffffffff9ea76ee0 idt=0xffffffffa1a14300 tss=0xffffffffa1a16fe0
[000029] [F] triggered                 <- the #DB chain ran and returned
[000030] hypervisor escape armed (diag=15). Rest mode -> payload.
[000032] P4 diag=15 — install done; heartbeat, standby SKIPPED
[000033] [hb 00]                       <- last line, then the console powered off
```

The chain executes successfully and the console keeps running for about a second afterwards. **The
death is deferred, not synchronous with the chain.**

## Bisection (one variable per run, power-cycle between)

The diagnostic skip-mask (`kh_diag_skip_mask`, `KH_SKIP_{BIG,SCRATCH,IST,GATE,DR7}` in
`include/byepervisor/khook.h`) lets each install-time write be turned off on its own, and
`PL5_DIAG >= 10` runs "install + heartbeat, never enter standby" so a test costs seconds instead of
a rest-mode cycle. That also removes the TV/CEC variable entirely.

| run | single variable | console | what it shows |
| --- | --- | --- | --- |
| `diag13` | control: escape only, `kh_install` skipped | **survives** | the escape alone is harmless |
| `diag11` | full install **minus the #DB IDT gate write** | **survives** | the loader/helper stay alive; only our own process dies with `SIGTRAP`, because its #DB went to the **original** handler |
| `diag16` | gate written, `kh_trigger()` never called | **survives**, but | `elfldr` **and** the `ps5upload` helper are both gone afterwards (`helper_not_ava1`) |
| `diag15` | gate written, full install, `DR7 = 0` | **dies** | the debug-register *value* is not the trigger |

Two conclusions come straight out of the table:

* **`DR7` is not the cause.** With the gate in place but `DR7 = 0`, the console still powers off.
* **What separates surviving from dying is whether the `#DB` is routed into our chain.** No gate
  write -> nothing else in the system is affected. Gate present -> unrelated processes start dying,
  and with the trap exercised a critical victim takes the console down.

## The mechanism

`kh_install()` replaces, **globally**:

* the **`#DB` IDT gate** (vector 1) with our ROP chain, and
* the **TSS `IST1` slot** with the arm chain,

and the chain resumes through `resumectx`/`DBREG_RESUME` with a context built for **our own**
trigger. After install, a `#DB` belonging to *any other* process or thread is therefore dispatched
into our chain and resumed against a context that is not its own.

Victims die. `diag16` shows it directly: with the hijack live but no trap of our own, `elfldr` and
the helper both disappear while the console stays up. `diag15` shows the same thing with a victim
important enough that the console performs an orderly power-off.

## Reproduction

```bash
# build one stage (PL5_DIAG >= 10 = install + heartbeat, never enter standby)
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make PL5_DIAG=16 offsets      # full install, kh_trigger() never called
# send bin/pLinux5-NG-offsets.elf with scripts/send.sh, then watch the console
```

`diag11` = `KH_SKIP_GATE`, `diag12` = `KH_SKIP_IST|KH_SKIP_GATE`, `diag13` = control (no install),
`diag14` = only the `#DB` gate, `diag15` = full install with `DR7 = 0`, `diag16` = no trigger.

Console state to check after a run: `ping` (is it alive?) and ports `9021`/`9120` (are the loader
and the helper alive?). A surviving console with closed ports is a *different* outcome from a dead
console, and the distinction is what located the cause.

## Next step (design, not more bisection)

The chain must make sure the trap is ours before it runs: compare the interrupted RIP or the trap
frame against the expected trigger, or keep the original gate for foreign `#DB`s and divert only our
own. Until then, an armed run is expected to disturb other payloads — which is exactly what the
console measured.

---

## P4.4 — first fix attempt: shrink the hijack window

The bisection says the damage comes from the **window** during which the `#DB` gate and the TSS
`IST1` slot are ours, not from `DR7` and not from the suspend. So the cheapest fix is to make that
window as short as the trigger itself.

`kh_restore()` already exists and puts both back (`saved_gate_lo/hi` into the gate, `saved_ist`
into the IST slot). The change is to call it **immediately after our own trigger returns**, instead
of leaving the hijack installed for the rest of the session.

* stage `PL5_DIAG=17`: full install -> `kh_trigger()` -> `kh_restore()` -> heartbeat.
* stage `PL5_DIAG=16` (unchanged) is the comparison point: same install, no trigger, hijack left
  live for the whole run.

What the pair should show, if the window is really the mechanism:

| stage | hijack window | expected |
| --- | --- | --- |
| `diag16` | whole run (already measured: `elfldr` + helper died, console survived) | victims die |
| `diag17` | the trigger only (microseconds) | no victims, console survives |

### Why this is the first attempt and not the whole fix

* It is a **mitigation**, not a proof: a foreign `#DB` landing inside the now-tiny window is still
  captured. It removes the systematic damage, not the raciness.
* It applies to the **diagnostic path** today. The real escape *must* keep the hook armed across the
  suspend — that is the entire mechanism — so for the production path the equivalent change is to
  **arm late**: stage everything early (scratch, chains, big blob — proven harmless by `diag11`) and
  write the gate and the IST slot as the very last step before requesting standby. That keeps the
  hijack alive only across the sleep, which is the minimum the design allows.
* The thorough fix remains **scoping the chain**: verify the trap is ours (interrupted `RIP` or trap
  frame) and hand anything else to the original handler, so an armed hook can never capture a
  foreign trap at all. That needs a hand-written stub in the staged page, since the dispatch path is
  a ROP chain and has no conditional branch.

`diag17` is built (`bin/p4-diag17.elf`) and not yet measured: the console currently has no loader
(`9021` closed) after `diag16`, so the chain has to be re-established first.

### P4.4 — MEASURED: the window was the mechanism

Run 2026-10-16 01:16, console `13.60.0007`, both stages measured against the same indicators
(`ping` for the console, ports `9021`/`9120` for the loader and the helper).

`diag17` log, verbatim:

```text
[000023] 13.60: P4 diag=17 skip_mask=0
[000028] 13.60: [E] core=15 ktext=0xffffffff93e30000 scratch=0xffffffff96b69000 tgt=0xffffffff94a46ee0 idt=0xffffffff979e4300 tss=0xffffffff979e6fe0
[000029] 13.60: P4 diag17: kh_restore rc=0 (gate+IST restored right after the trigger)
[000030] 13.60: [F] triggered
[000031] 13.60: hypervisor escape armed (diag=17). Rest mode -> payload.
[000033] 13.60: P4 diag=17 — install done; heartbeat, standby SKIPPED
[000053] 13.60: [hb 19]
```

| stage | hijack window | payload output | console | `9021` loader | `9120` helper |
| --- | --- | --- | --- | --- | --- |
| `diag16` | whole run | stops at `[hb 00]` | alive | **closed** | **closed** |
| `diag17` | trigger only | completes `[hb 00] … [hb 19]` | alive | **open** | **open** |

So: the same install, the same trigger, the same heartbeat — the only difference is whether the
`#DB` gate and the `IST1` slot are handed back immediately. With them handed back, nothing else in
the system is disturbed: the payload finishes its run, the loader and the helper are still there,
and the console is untouched.

**The hijack window is the mechanism, and shrinking it is enough to stop the collateral damage.**

This also validates the production variant by inference: staging early is harmless (`diag11`), and
the arm is the part that must be short, so writing the gate and the `IST1` slot as the **last** step
before requesting standby should behave like `diag17` does here — the hook stays armed only across
the sleep, which is the minimum the design permits.

The residual race is still open and is what the scoped chain would close: a foreign `#DB` arriving
inside the shortened window is still captured.

### P4.4b — arm-late, first attempt: invalidated by inherited state

`PL5_DIAG=18` stages everything (skipping the gate and the IST slot) and arms just before the
standby request. The first run reported `arm-late: no staged hook` and left the console alive but
with `elfldr` and the helper gone.

The cause is not the arm-late code: `hv_defeat_1360()` has an **adopt shortcut** — if the earlier
escape left its `ARMED` mark in the kernel data cave and `.text` still looks open, it logs
`hook armed and .text already open; adopting it` and returns **before** installing anything. The
previous `diag17` run had armed it minutes earlier, so `diag18` inherited that state and skipped the
install entirely. The run therefore measured a rest-mode cycle with **nothing armed**, not arm-late.

Fix, so diagnostics cannot inherit state: for `PL5_DIAG >= 10` the adopt shortcut is bypassed and
the escape is forced. Re-run `diag18` on a fresh snapshot for a valid measurement.

### P4.4b — arm-late MEASURED: the console reaches standby and survives the cycle

Run 2026-10-16 01:25, console `13.60.0007`. The adopted armed mark was present
(`0x4b484f4f4b454401`) and deliberately ignored, so the escape ran for real:

```text
13.60: P4 diag=18: ignoring the adopted armed mark; forcing the escape.
13.60: [A] payload staged @ cave+0x1000, hv_base=0x62800000 cr3=0x17c84000 redirect=1
13.60: P4 diag18: staging only (gate+IST deferred to arm-late)
13.60: [D] kh_install rc=0
13.60: [E] core=15 ktext=0xffffffff93e30000 scratch=0xffffffff96b69000 tgt=0xffffffff94a46ee0 idt=0xffffffff979e4300 tss=0xffffffff979e6fe0
13.60: P4 diag18: self-test trigger deferred to arm-late
Finished preparation. Going to rest mode in 5 seconds.
13.60: arm-late: kh_arm rc=0 (gate+IST written now)
```

What happened next:

| | armed at install (old) | **armed late (diag18)** |
| --- | --- | --- |
| reaches the standby request | **no** — dies ~1 s after install | **yes** |
| enters rest mode | — | **yes** (console unreachable while asleep) |
| survives the resume | — | **yes** (ping OK at 01:26:37 after the operator woke it) |

Two observations worth separating:

* **The early death is gone.** Staging everything without the gate/IST is harmless (`diag11`) and
  arming immediately before the standby request is enough — the console asked for standby and
  entered rest mode, which the install-time arm never managed.
* **The loader and the helper are gone after the wake**, but so they were in the *previous* cycle in
  which **nothing** was armed, so their loss is not attributable to the hijack; it is how this rest
  mode cycle treats payload processes.

Not yet confirmed: whether `post_resume()` actually ran, because `/data/plinux5.log` needs the
helper to be read. The file is on disk and survives the power state, so the marker
(`P4 diag18: post-resume reached; dump SKIPPED on purpose.`) can still be checked once the chain is
re-established — that is the next reading, before any new payload run.
