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
