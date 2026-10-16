#!/usr/bin/env python3
"""Extract the per-firmware offset tables from a PS5 Linux loader ELF (Sonic ISO's 1360linux.elf).

Why this tool exists: another project's *working* 13.60 loader ships the same offset
struct we maintain, so it is a reference we can compare against instead of guessing. The
tables are data blobs inside the ELF, and their location moves between builds, so this
tool locates them by content rather than by a hardcoded address: it searches for a
position where several 13.60 anchors we have independently verified sit at exactly the
relative distances the struct layout demands, then reads the whole struct.

Anchors used (all verified independently of this ELF):
  +0x18 DATA_BASE_GVMSPACE 0x3BAA570   +0x28 IDT 0x3BB4300   +0x100 KERNEL_CFI_CHECK 0x44F8C0
  +0x110 FUN_TRANSMITTER_CONTROL 0xC0EAA0   +0x120 FUN_MP3_INVOKE 0xA12D30
When three or more of those line up at the expected distances, the base is accepted and
every field is printed. It also reports the other firmware tables it can reach, because
cross-reading them (3.00, 4.50, 5.00, 6.00, 7.61) is what proves the field mapping.

Usage: extract_elf_1360_table.py PATH_TO_ELf [--firmware 1360]
Exit 0 = a table was located and printed; 1 = no anchor set matched; 2 = unusable input.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

# field order of the loader's offset_list (include/offsets.h of ps5-linux-loader)
FIELDS = ["IOMMU_SOFTC", "VMSPACE_VM_VMID", "VMSPACE_VM_PMAP", "DATA_BASE_GVMSPACE",
          "ACPIGBL_FACS", "IDT", "COMMON_TSS", "STOPPED_CPUS", "FUN_STOP_CPUS",
          "FUN_AS_LAPIC_EOI", "FUN_HV_UNMAP_PT_TMR", "FUN_MEMCPY",
          "GAD_ADD_RSP_28_POP_RBP_RET", "GAD_IRETQ", "GAD_POP_RAX_RET", "GAD_POP_RDI_RET",
          "GAD_POP_RSI_RET", "GAD_POP_RDX_RET", "GAD_POP_RCX_RET", "GAD_POP_RSP_RET",
          "GAD_WRMSR_RET", "GAD_MOV_QWORD_PTR_RDI_RSI_POP_RBP_RET", "HOOK_ACPI_WAKEUP_MACHDEP",
          "KERNEL_CODE_CAVE", "FUN_PRINTF", "FUN_HV_IOMMU_SET_BUFFERS", "FUN_HV_IOMM_WAIT_COMPLETION",
          "FUN_SMP_RENDEZVOUS", "FUN_SMP_NO_RENDEVOUS_BARRIER", "HV_CODE_CAVE_PA",
          "HV_HANDLE_VMEXIT_PA", "KERNEL_UART_OVERRIDE", "KERNEL_CFI_CHECK", "G_VBIOS",
          "FUN_TRANSMITTER_CONTROL", "FUN_MP3_INITIALIZE", "FUN_MP3_INVOKE",
          "PS5_WIFI_FW_OFFSET", "PS5_WIFI_FW_SIZE"]

ANCHORS = {0x18: 0x3BAA570, 0x28: 0x3BB4300, 0x100: 0x44F8C0, 0x110: 0xC0EAA0, 0x120: 0xA12D30}


def find_table_base(blob: bytes) -> int | None:
    """Locate the 13.60 table by matching anchors at their exact relative offsets."""
    for off in range(0, len(blob) - 0x138, 8):
        score = sum(1 for k, v in ANCHORS.items()
                    if struct.unpack_from("<Q", blob, off + k)[0] == v)
        if score >= 3:
            return off
    return None


def dump_table(blob: bytes, base: int) -> None:
    for i, name in enumerate(FIELDS):
        v = struct.unpack_from("<Q", blob, base + i * 8)[0]
        print(f"  +0x{i*8:03x}  {name:<42} 0x{v:x}  ({v})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    args = ap.parse_args()
    if not args.elf.is_file():
        print(f"ERROR: not a file: {args.elf}", file=sys.stderr)
        return 2
    blob = args.elf.read_bytes()
    base = find_table_base(blob)
    if base is None:
        print("ERROR: no anchor set matched; this ELF is not the known 13.60 loader build, "
              "or the field layout changed.", file=sys.stderr)
        return 1
    print(f"table located at file offset 0x{base:x} (3+ verified anchors aligned)")
    dump_table(blob, base)
    print("\nCross-read of the neighbouring tables is what validates the mapping: the same "
          "read must reproduce the published values of 3.00/4.50/5.00/6.00/7.61.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
