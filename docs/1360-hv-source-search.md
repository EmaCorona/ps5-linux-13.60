# 13.60 hypervisor reference — source search verdict

**Verdict: BLOCKED.** No verified source for the 13.60 hypervisor-side addresses (`HV_VMMCALL_HANDLER_PA`
and the other `HV_*_PA` values) exists in what was examined. Phase B therefore stays disabled, and
`PL5_1360_HV_VMMCALL_HANDLER_PA` stays a placeholder that refuses the build.

This is a *result*, not an unfinished search. The plan says explicitly: a negative outcome is accepted
as the outcome; what is not accepted is inventing a value, reusing 13.20's, or substituting the
guest-side wrapper.

## What was examined

| source | how | result |
| --- | --- | --- |
| Byepervisor-Reborn `include/offsets/13_60.h` | primary check of the file contents via the GitHub API (the project that the port's escape is derived from, and the one whose 13.60 support is public) | contains **kernel** values and two HV-image-*relative* symbols (`HV_SYM_HEAP_BASE = 0x83028`, `HV_SYM_PCPUS = 0x82A60`). It contains **no** hypervisor physical address: no VMMCALL handler PA, no VMEXIT handler PA, no HV code cave |
| the 13.60 kernel capture (`k1360.bin`, sha256 `c3f745e2…cddd`) analysed in [`1360-offsets-from-dump.md`](1360-offsets-from-dump.md) | offline disassembly | holds the **guest** side of the interface (37 `vmmcall` wrappers, one of them at `0xC16A10`). A kernel capture cannot contain the hypervisor implementation, by construction |
| the 13.60 Recovery PUP | container inspection, recorded in [`1360-hv-pas-offline-verdict.md`](1360-hv-pas-offline-verdict.md) | two nested PUPs found; the payload stayed encrypted; the console-side decryption path returned `EPERM` |
| public material (web search) | titles/snippets only | describes the 13.60 escape being public and the hypervisor being discussed, but nothing that publishes a 13.60 HV image or an HV-side address table with an artifact and a hash. Not usable as evidence |

## Why the guest wrapper is not a substitute

`0xC16A10` is `push rbp; mov rbp,rsp; mov eax,4; vmmcall; pop rbp; ret` **in the guest kernel**. It is
the instruction that *requests* the hypercall; the handler that receives it lives in the hypervisor
image at a physical address the guest does not map. Adding one to the other is exactly the class of
error the registry's namespace rule exists to prevent, and it is what the `#error` in
`hv_defeat_1360.c` refuses.

## What would change the verdict

A value is acceptable only with **all** of:

1. the artifact itself (a decrypted 13.60 HV image, or a published table) with its provenance;
2. a hash of that artifact;
3. the layout/mapping that makes the value an address in the namespace it claims;
4. the identification method (which signature, which instruction sequence, which jump table);
5. an independent second check (a second tool, or a byte-level cross-check), because a single match
   in a large binary is easy to find by accident.

Until then: phase B off, and the pursuit of the Linux boot stays on the parts that do not need it —
the hook design, the post-resume contract, the boot-data work, and (as a recorded design option in
[`SUBSYSTEM-MATRIX-1360.md`](SUBSYSTEM-MATRIX-1360.md)) a single-core variant that avoids the part of
the takeover needing the rendezvous.
