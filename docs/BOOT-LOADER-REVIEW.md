# Boot load path review — kernel/initrd staging and the Linux hand-off

Scope: `source/boot/loader.c` (`fetch_linux`), `source/boot/prepare_resume.c`, `include/core/linux.h`,
and the `boot_params`/e820 construction that the shellcode performs later. Offline review plus host
tests; no console.

## 1. What the path does

1. `fetch_linux()` resolves `bzImage` and `initrd.img` from the configured search paths, `mmap`s a
   buffer for each, reads them, and records where a later stage must place them:
   `bzImage` at `kernel_cave_bzImage`, `initrd` immediately after it at
   `ALIGN_UP(bzimage_size, PAGE_SIZE)`.
2. It also resolves `vram.txt` and `cmdline.txt` and falls back to constants when absent, and dumps
   the device firmwares it can.
3. The Linux side (`prepare_sck_args()` for legacy firmware, `stage_hv_boot()` for high firmware)
   copies the images into the kernel cave and builds the `struct linux_info` the shellcode reads.
4. The shellcode builds `boot_params`: copies the bzImage setup header, fills `hdr.code32_start`,
   `hdr.cmd_line_ptr`, `hdr.initrd_addr_max`, the e820 table, and jumps to
   `kernel_pa + 0x200` (`startup_64`).

## 2. Defects found and fixed

| defect | effect | fix |
| --- | --- | --- |
| `size_t bzimage_size = find_and_get_size_of_file(...)` then `if (bzimage_size < 0)` | the return type is `long` and `-1` means "not found"; stored in an unsigned type, the value became `SIZE_MAX` and the comparison was **always false**, so "not found" was never detected at that point — the failure surfaced later as a misleading allocation error | keep the `long` result, check it, then narrow (`long bzimage_size_l`) |
| the initrd check tested `bzimage_size` and printed `"File bzImage not found"` | a missing `initrd.img` was not detected at all, and a missing `bzImage` would have been reported twice | the initrd check now tests `initrd_size_l` and names `initrd.img` |

Both are in the shared path, so they affected the working 13.20 flow too (as confusing errors rather
than as a wrong boot).

## 3. New: the hand-off is validated before anything is staged

`include/boot/boot_data.h` (`pl5_boot_check_data`) checks, in one place and before staging:

- sizes present and non-zero, and the bzImage at least as large as a setup-header area;
- the bzImage setup header really is one: magic `HdrS` at `0x202` and boot flag `0xAA55` at `0x1FE`;
- boot protocol >= 2.00 (the shellcode uses `setup_sects`, `syssize`, `code32_start`);
- the command line fits `PL5_CMDLINE_CAP`;
- the layout: the initrd starts exactly at the page-aligned end of the bzImage and is page-granular;
- the images fit between `kernel_cave_bzImage` and `kernel_cave_files_end`
  (`kernel_cave + 0x1B600000`, i.e. below the kernel image itself);
- overflow is treated as failure, not wrapped.

It **refuses** instead of clamping: a clamped size produces a boot that half-works, which is worse to
diagnose on a console than a named refusal printed before anything is written.

## 4. Checkable offline vs hardware-only

| requirement | offline? | how |
| --- | --- | --- |
| size/alignment/overflow arithmetic | **yes** | host tests (see `tests/run_tests.py`, boot data lane) |
| setup-header magic, protocol, boot flag | **yes**, with a real bzImage | the check reads the file's header; the host test uses a synthetic header |
| command line length | **yes** | host test |
| cave layout fits | **yes** | the bound is derived from `KERNEL_ADDRESS_TEXT_BASE` |
| a missing file is detected | **yes** | host test of the `long` handling; the I/O itself is not exercised |
| file read actually succeeds from the console's storage | **no** | hardware: `find_and_read_file` against the real paths |
| `install_page_syscore()` maps the staged pages for the sleep | **no** | hardware: the mapping is what survives S3 |
| the shellcode's `boot_params` copy lands correctly | **no** | hardware: needs the boot attempt |
| e820 entries describe the console's real memory map | **no** | hardware |

The last four are carried into the hardware acceptance matrix (Task 25) as the things a boot session
must show, rather than being asserted here.

## 5. Still open

- `prepare_resume.c` builds the same information for the legacy vectors; it is not reachable on
  13.60 (see [`BOOT-REQUIREMENTS-1360.md`](BOOT-REQUIREMENTS-1360.md)), so it was reviewed but not
  changed.
- The initrd is optional in the validation (`initrd_size == 0` passes). Whether a console boot
  without an initrd is a supported configuration is a product decision, not a code one.
- `boot_params.hdr.cmdline_size`, `initrd_addr_max` and `kernel_alignment` are consumed by the
  shellcode; the values it writes are not checked here because they are computed in kernel context,
  where a host test cannot reach without a simulated shellcode.
