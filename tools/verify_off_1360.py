#!/usr/bin/env python3
"""Static validation of off_1360.c against Byepervisor-Reborn's 13_60.h.

Checks that:
  1. every symbol/gadget published in 13_60.h is mapped into off_1360.c with the
     exact same value;
  2. off_1360.c initialises exactly the same offset_list fields as off_1320.c
     and only fields that exist in include/offsets/offsets.h;
  3. the 13.60 routing exists (utils.c case, main.c branch + calls).

No compiler/SDK needed. Exits non-zero on any mismatch.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/13_60.h")

# 13_60.h comment symbol -> off_1360.c designated initializer field
MAP = {
    "KERNEL_SYM_DMPML4I": ["KERNEL_SYM_DMPML4I"],
    "KERNEL_SYM_DMPDPI": ["KERNEL_SYM_DMPDPI"],
    "KERNEL_SYM_PML4PML4I": ["KERNEL_SYM_PML4PML4I"],
    "KERNEL_SYM_SYS_GETUID": ["KERNEL_SYM_SYS_GETUID"],
    "KERNEL_SYM_PRINTF": ["FUN_PRINTF"],
    "KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK": ["HOOK_ACPI_WAKEUP_MACHDEP"],
    "KERNEL_SYM_HV_MP_STARTUP_CALL": ["KERNEL_SYM_HV_MP_STARTUP_CALL"],
    "KERNEL_SYM_MP_STARTUP_INIT_VECTOR": ["KERNEL_SYM_MP_STARTUP_INIT_VECTOR"],
    "KERNEL_SYM_PMAP_STORE": ["KERNEL_SYM_PMAP_STORE"],
    "KERNEL_SYM_DATA_CAVE": ["KERNEL_SYM_DATA_CAVE", "KERNEL_CODE_CAVE"],
    "KERNEL_SYM_IDT_ARRAY": ["IDT"],
    "KERNEL_SYM_COMMON_TSS": ["COMMON_TSS"],
    "HV_SYM_HEAP_BASE": ["HV_SYM_HEAP_BASE"],
    "HV_SYM_PCPUS": ["HV_SYM_PCPUS"],
    "KERNEL_GADGET_PIVOT_ADD_RSP28_RET": ["GAD_ADD_RSP_28_POP_RBP_RET"],
    "KERNEL_GADGET_IRETQ": ["GAD_IRETQ"],
    "KERNEL_GADGET_POP_RAX": ["GAD_POP_RAX_RET"],
    "KERNEL_GADGET_POP_RCX": ["GAD_POP_RCX_RET"],
    "KERNEL_GADGET_POP_RDI": ["GAD_POP_RDI_RET"],
    "KERNEL_GADGET_POP_RSI": ["GAD_POP_RSI_RET"],
    "KERNEL_GADGET_POP_RDX": ["GAD_POP_RDX_RET"],
    "KERNEL_GADGET_POP_R8": ["GAD_POP_R8"],
    "KERNEL_GADGET_POP_RSP": ["GAD_POP_RSP_RET"],
    "KERNEL_GADGET_STORE_RCX_R8": ["GAD_STORE_RCX_R8"],
    "KERNEL_GADGET_STORE_RDI8_RCX": ["GAD_STORE_RDI8_RCX"],
    "KERNEL_GADGET_OR_RCX_EAX": ["GAD_OR_RCX_EAX"],
    "KERNEL_GADGET_SET_DR7": ["GAD_SET_DR7"],
    "KERNEL_GADGET_ST_RCX_RDX": ["GAD_ST_RCX_RDX"],
    "KERNEL_GADGET_ST_RCX_RAX": ["GAD_ST_RCX_RAX"],
    "KERNEL_GADGET_MOV_RAX_RSI": ["GAD_MOV_RAX_RSI"],
    "KERNEL_GADGET_MOV_RAX_RDI": ["GAD_MOV_RAX_RDI"],
    "KERNEL_GADGET_REP_MOVSB": ["GAD_REP_MOVSB"],
    "KERNEL_GADGET_CLD": ["GAD_CLD"],
    "KERNEL_GADGET_RET_TRAMP": ["GAD_RET_TRAMP"],
    "KERNEL_GADGET_DBREG_RESUME": ["GAD_DBREG_RESUME"],
}

errors = []

# ---- 1. header values vs off_1360.c -----------------------------------------
header_vals = {}
for line in HEADER.read_text().splitlines():
    m = re.match(r"\s*0x([0-9A-Fa-f]+),\s*//\s*(\S+)", line)
    if m:
        header_vals[m.group(2)] = int(m.group(1), 16)

off_src = (ROOT / "source/offsets/off_1360.c").read_text()
off_vals = {}
for m in re.finditer(r"\.(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,", off_src):
    off_vals[m.group(1)] = int(m.group(2), 16)

for sym, fields in MAP.items():
    if sym not in header_vals:
        errors.append(f"13_60.h is missing expected symbol {sym}")
        continue
    for f in fields:
        if f not in off_vals:
            errors.append(f"{f} not set in off_1360.c (source: {sym})")
        elif off_vals[f] != header_vals[sym]:
            errors.append(
                f"{f} mismatch: off_1360.c=0x{off_vals[f]:X} "
                f"13_60.h({sym})=0x{header_vals[sym]:X}")

unmapped = set(header_vals) - set(MAP)
if unmapped:
    errors.append(f"13_60.h symbols not mapped: {sorted(unmapped)}")

# ---- 2. field sets ----------------------------------------------------------
struct_src = (ROOT / "include/offsets/offsets.h").read_text()
body = struct_src.split("typedef struct _offset_list {", 1)[1].split("} offset_list;", 1)[0]
struct_fields = set(re.findall(r"uint64_t\s+(\w+);", body))

# Fields the 13.xx vector does not use (legacy 5.00-6.02 entries) are omitted
# from the initializer on purpose; keep the 13.20 and 13.60 field sets identical.
off1320_src = (ROOT / "source/offsets/off_1320.c").read_text()
fields_1320 = set(re.findall(r"\.(\w+)\s*=", off1320_src))
fields_1360 = set(re.findall(r"\.(\w+)\s*=", off_src))
if fields_1320 != fields_1360:
    errors.append(
        "off_1360.c initializer differs from off_1320.c "
        f"(only-1360={sorted(fields_1360 - fields_1320)}, "
        f"only-1320={sorted(fields_1320 - fields_1360)})")

unknown = sorted(fields_1360 - struct_fields)
if unknown:
    errors.append(f"off_1360.c sets fields not in offset_list: {unknown}")

# ---- 3. routing wiring ------------------------------------------------------
utils = (ROOT / "source/core/utils.c").read_text()
if not re.search(r"case\s+0x1360:\s*env_offset\s*=\s*off_1360;", utils):
    errors.append("utils.c: no `case 0x1360: env_offset = off_1360;`")
main_c = (ROOT / "source/main.c").read_text()
if "hv_defeat_1360(" not in main_c or "hv_defeat_1360_post_resume()" not in main_c:
    errors.append("main.c: 13.60 defeat calls missing")
if '#include "hv_defeat_1360.h"' not in main_c:
    errors.append("main.c: hv_defeat_1360.h not included")
if "extern offset_list off_1360;" not in struct_src:
    errors.append("offsets.h: off_1360 not declared")

# ---- report ------------------------------------------------------------------
print(f"header symbols mapped : {len(MAP)} / {len(header_vals)}")
print(f"offset_list fields    : {len(struct_fields)} total; 13.60 sets "
      f"{len(fields_1360)}, 13.20 sets {len(fields_1320)}, "
      f"same set: {fields_1320 == fields_1360}")
print(f"values checked        : {len(off_vals)}")
if errors:
    print("\nFAIL:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("\nPASS: off_1360.c matches 13_60.h and the offset_list layout.")
