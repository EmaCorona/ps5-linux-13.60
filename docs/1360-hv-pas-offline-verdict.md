# 13.60 hypervisor PAs — offline verdict (PUP + kernel capture)

**Date:** 2026-10-16
**Question:** identify/verify `HV_VMMCALL_HANDLER_PA`, `HV_CODE_CAVE_PA`,
`HV_HANDLE_VMEXIT_PA` for firmware **13.60**, starting from the official update file
`~/Downloads/PS5UPDATE.PUP` — static analysis of public artifacts only, no invented addresses.

**Answer:** the three values are **not obtainable from the PUP, nor from any other static
artifact available here.** The PUP payload is encrypted with keys that live in the console's
security processor; the kernel capture cannot contain them; the public per-firmware tables stop
at 7.61 (plus a single 13.20 entry in the vendor repo). Every claim below is reproducible with
the commands in the last section.

---

## 1. Per-reference state on 13.60

| reference | what it is | public values | 13.60 value |
| --- | --- | --- | --- |
| `HV_VMMCALL_HANDLER_PA` | SVM `VMMCALL`-exit (intercept `0x81`) jump-table target **inside the HV image**, as a physical address | name is project-local; the vendor repo publishes it **for 13.20 only** (`pLinux5-NG`, `takeover.c`: `0x62847375`) | **unknown** — not public, not in the PUP, not in the kernel capture |
| `HV_CODE_CAVE_PA` | HV-side code cave used by the ≤7.61 VMEXIT vector | `0x62806F00`, **constant** for 3.00→7.61 (21 tables in `source/offsets.c` / `ps5linux_offsets.c`) | **unknown** (and unused by the Byepervisor vector: 13.20 leaves it `0` with the comment "runs from `startup_mp`, not a fixed VMEXIT cave") |
| `HV_HANDLE_VMEXIT_PA` | HV VMEXIT handler entry, physical | per firmware, ≤7.61 only: `0x6282CBCB` (3.00–3.21), `0x6282B45D` (4.xx), `0x6282EBD0` (5.0x), `0x6282DFEB` (5.50), `0x62841CE0` (6.0x), `0x62841D50` (6.50), `0x6283D800` (7.0x–7.61) | **unknown** |

No 8.00–14.xx value for any of the three exists in the ps5-linux-loader / Byepervisor-Reborn /
Relapse / HV-Bypass-13.60 trees (checked by `include/offsets/*.h`, `source/offsets/*.c` and a
GitHub code search for the literal identifiers).

## 2. Why the PUP cannot answer it (measured on the file itself)

`PS5UPDATE.PUP` sha256 `e210451f789ebe46f55b13ae049894663b796163f7b094ab993218f1cb20aa97`
(1,404,953,088 B, 13.60.00 Recovery).

* Outer container = **SLB2** (`0x32424C53`, version 3, 2 entries), names in clear:
  `PS5UPDATE1.PUP` @ `0x400`, size `0x4A5AE195`; `PS5UPDATE2.PUP` @ `0x4A5AE600`, size `0x0962FAB5`
  (byte offset = entry `block_offset` × 512: `0x2 × 0x200 = 0x400`, `0x252D73 × 0x200 = 0x4A5AE600`).
* Each nested PUP has only its **16-byte file header in clear** (`magic 0xEEF51454`,
  `headerSize 0x5b0`, `hashSize 0xde0`); the extended header **and every segment are encrypted**.
  Confirmed by raw scan: the magic `54 14 f5 ee` occurs exactly twice in the whole file, at the
  two payload starts.
* `grep` for ELF magic over the full 1.4 GB: **zero hits** — no plaintext module of any kind.
* Decryption is done by the console's **EncryptService** (`/dev/pup_update0`, ioctls
  `0xC0184402` / `0xC0184405`, zecoxao/ps5-pup-decrypt) or needs the container key from the
  security processor (TitaniaPy). Both are console-side. On this console that route is already
  closed with **EPERM** (see *1360-offsets-from-dump.md*). No public key material exists for it.
* The publicly documented PS5 PUP segment-name map (`TitaniaPy/keys.py`) contains no
  "hypervisor"/"hv" segment at all — the HV image is not a named, extractable PUP artifact.

## 3. What the kernel capture can and cannot show

Input: `~/src/ps5-dumps/k1360.bin` (community 13.60 capture, sha256
`c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`), text VA base
`0xffffffff9e3f0000`.

* **Can show — the guest side of the HV interface exists and is verified:**
  the kernel text holds **37 `vmmcall` (`0f 01 d9`) opcodes**, including the hypercall wrapper
  family. Ghidra 12.1.4 (REA), on a 64 KiB slice of the capture mapped at its real VA, decodes
  `0xC16A10` as the **hypercall-4 wrapper**:

  ```
  0xffffffff9f006a10: PUSH RBP / MOV RBP,RSP / MOV EAX,0x4 / VMMCALL / POP RBP / RET
  ```

  Evidence `ev_a21ba545392eec92601b2192a43a7fbecb27ab3556647ab86cbab08b19052e7f`
  (subject: `k1360_sliceC1.elf`, sha256 `860d800c…324a`). `HV_VMMCALL_HANDLER_PA` is the *other*
  end of this instruction: it lives in HV memory, not in this image.
* **Cannot show — any HV address.** An independent u64 scan of the whole capture finds **0**
  values in the old HV carve-out `0x62800000..0x62B00000`; there is no `vmrun`/`vmload`/`vmsave`
  anywhere in `.text`. The HV is not in a kernel capture — the same negative result was obtained
  three times in the project's own research (`kernel/VMCB_PA.md`, `HV_LAYOUT.md`, `HV_RESEARCH.md`).

## 4. How the reference vector reaches the HV (why a PA is needed at all)

`Byepervisor-Reborn`'s break payload (`break_hv_payload/break_hv.c`, 13.20) does **not** need a
hard-coded HV PA to reach HV memory: it walks guest kernel R/W → HV heap base (`HV_SYM_HEAP_BASE`
`0x83028`) → `pcpus` (`HV_SYM_PCPUS` `0x82A60`) → `VMCB = [pcpu + 0xa8]`, then patches
`VMCB_NESTED_CTRL` (`+0x90`, clear bit 0) and `VMCB_CLEAN` (`+0xC0`) to force a reload on the next
`VMRUN`. The *takeover* path is what needs the HV-resident PAs (`VMMCALL` jump-table target, VMEXIT
entry, code cave), and those are per-firmware facts of the **HV image** — which no guest capture
contains.

## 5. What would actually settle the three values

From the project's own HV lane (all console-time, none runnable offline):

1. read the AMD-Vi MMIO base registers (`Device Table Base` +0x00, `Command Buffer Base` +0x08) at
   VA `0xffffec8c01130000 + N*0x4000` — either value lands inside the HV carve-out and pins the HV
   host-PA region (`HV_LAYOUT.md` §4);
2. dump the HV code through the **root-0 NPT alias** (lead: the guest NPT maps the HV's own
   physical pages on ≤13.60; patched in 14.10) and disassemble for the moved anchors;
3. or wait for a public 8.00+ HV offset table.

Until one of those runs, `off_1360.c` keeps `HV_CODE_CAVE_PA = 0` / `HV_HANDLE_VMEXIT_PA = 0`
(by design for this vector) and `PL5_1360_HV_VMMCALL_HANDLER_PA = 0` behind its `#error` guard.

## 6. Reproduce

```bash
# container: names, sizes, offsets
python3 - <<'PY'
import struct
f=open('/home/emacorona/Downloads/PS5UPDATE.PUP','rb'); h=f.read(0x80)
magic,ver,flags,cnt=struct.unpack_from('<IIII',h,0); print(hex(magic),ver,flags,cnt)
for i in (0,1):                      # entry = {block_offset u32, size u32, reserved[8], name[32]}
    e=0x20+i*0x30
    blk,size=struct.unpack_from('<II',h,e)
    print(h[e+0x10:e+0x30].split(b'\x00')[0], hex(blk*512), hex(size))
PY
# nested PUP magic (only two hits in the whole 1.4 GB)
grep -abo $'\x54\x14\xf5\xee' /home/emacorona/Downloads/PS5UPDATE.PUP
# no plaintext module anywhere
grep -abo $'\x7fELF' /home/emacorona/Downloads/PS5UPDATE.PUP | head   # empty
# kernel capture: guest side of the HV interface
python3 -c "d=open('/home/emacorona/src/ps5-dumps/k1360.bin','rb').read(0xCC0000);print('vmmcall sites:',d.count(b'\x0f\x01\xd9'))"
```

The kernel slice used for the Ghidra evidence is built by mapping `k1360.bin[0xC10000:0xC20000]`
at VA `0xffffffff9f000000` in a one-PT_LOAD ELF (data at file offset `0x1000`, so the program
headers stay inside the padding).
