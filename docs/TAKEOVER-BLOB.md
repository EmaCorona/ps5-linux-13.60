# The shared takeover blob — what is verified, and what is not

`source/shellcode/hv_takeover/takeover.S` is built into one blob that is written into the live kernel
by the post-resume takeover. Two things are easy to conflate and must stay separate:

| claim | what checks it |
| --- | --- |
| **the blob assembly conforms**: no firmware literal in the body, the right firmware's constants selected by macro, the size fits its staging slot, and it writes the bytes the C side expects | `tools/verify_takeover_param.py` (every push) |
| **the target addresses are verified for the firmware in question** | the offset registry and the capture analysis — **not** this verifier |

A conforming blob with a wrong address is a conforming blob. The verifier says so explicitly so that a
green run on 13.20 is never read as progress on the 13.60 address problem.

## What the verifier checks

1. **No firmware literal in the instruction body.** The body starts after the `--- end firmware
   config ---` marker; every address must arrive through a macro. Any of the 13.20 *or* 13.60
   constants appearing there is a failure — that is the mechanism by which one firmware's address
   would silently be applied to another.
2. **13.60 is refused by the build**, naming the unknown `HV_VMMCALL_HANDLER_PA`, instead of
   inheriting 13.20's.
3. **13.20 still builds and encodes exactly its own constants** (HV handler PA, CFI, smp_rendezvous,
   hc4), and does **not** encode any of the 13.60 ones. The blob is 144 bytes today; the committed
   check pins the *structure* (size + encoded immediates), not the file hash, because the generated
   header is not tracked.
4. **The C expectation matches the blob**: the 25-byte stub `takeover_stub[]` in
   `hv_defeat_1320.c` / `hv_defeat_1360.c` must appear verbatim in the blob. A change on either side
   breaks this, which is the point.
5. **The blob fits its staging slot** — one page (`STARTUP_MP_PAYLOAD_PAGE`, written by
   `g_payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE)`), so 4096 bytes.

## What it does not check

- whether the addresses are right for the running firmware (registry + capture, not this tool);
- whether the patched code behaves as expected at runtime (hardware, Task 29);
- whether the blob is *safe to run* — that is the hook design and the post-resume contract, and both
  are still open.

## Related gates

`tests/run_tests.py` runs this verifier as part of the suite, so a change to the blob or to the C
expectation fails the host tests before CI does. Phase B remains disabled: the 13.60 blob cannot be
built at all while its hypervisor reference is a placeholder (Task 16).
