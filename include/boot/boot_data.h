/* boot_data — the arithmetic and the sanity of a Linux hand-off, checkable on the host.
 *
 * The payload prepares `struct linux_info` (bzImage + initrd in the kernel cave) and the Linux
 * shellcode turns it into boot_params/e820. Both are unsafe places to discover that a size was
 * zero, that a file was missing, or that the two images overlap: the failure mode is a hang or a
 * wild write in kernel context, on a console, with no output.
 *
 * The checks live here so they can be run before anything is staged, and so the same code runs in
 * the host test suite (tests/run_tests.py) and in the payload. Freestanding: stdint only.
 */
#ifndef PL5_BOOT_DATA_H
#define PL5_BOOT_DATA_H

#include <stdint.h>

#define PL5_SETUP_HDR_MAGIC 0x53726448u /* "HdrS" */
#define PL5_BOOT_FLAG 0xAA55u
#define PL5_MIN_BOOT_PROTOCOL 0x0200u
#define PL5_CMDLINE_CAP 2048u
#define PL5_MIN_BZIMAGE 1024u

enum pl5_boot_check {
  PL5_BOOT_OK = 0,
  PL5_BOOT_MISSING,         /* a size of 0 or an unresolved file */
  PL5_BOOT_TOO_SMALL,       /* smaller than a setup header area */
  PL5_BOOT_BAD_MAGIC,       /* not a bzImage: no "HdrS" */
  PL5_BOOT_BAD_PROTOCOL,    /* boot protocol older than 2.00 */
  PL5_BOOT_CMDLINE_TOO_LONG,
  PL5_BOOT_NO_ROOM,         /* images do not fit in the cave */
  PL5_BOOT_INITRD_OVERLAP,  /* the two images are not laid out end-to-end */
  PL5_BOOT_UNALIGNED        /* a size that must be page-granular is not */
};

struct pl5_boot_facts {
  uint64_t bzimage_size;   /* bytes actually read */
  uint64_t initrd_size;    /* bytes actually read, 0 if none was provided */
  uint64_t cmdline_len;    /* strlen of the command line */
  uint32_t hdr_magic;      /* setup_header.header, read from the file */
  uint16_t hdr_version;    /* setup_header.version */
  uint16_t boot_flag;      /* setup_header.boot_flag */
  uint64_t cave_start;     /* first byte of the staging area */
  uint64_t cave_end;       /* one past the last usable byte */
  uint64_t initrd_offset;  /* initrd start relative to cave_start */
  int page_size;           /* 4096 on this platform; taken as a parameter so the test can vary it */
};

static inline const char *pl5_boot_check_text(enum pl5_boot_check r) {
  switch (r) {
  case PL5_BOOT_OK:               return "ok";
  case PL5_BOOT_MISSING:          return "a required file is missing or empty";
  case PL5_BOOT_TOO_SMALL:        return "the bzImage is smaller than a setup header area";
  case PL5_BOOT_BAD_MAGIC:        return "the bzImage setup header magic is not HdrS";
  case PL5_BOOT_BAD_PROTOCOL:     return "the boot protocol is older than 2.00";
  case PL5_BOOT_CMDLINE_TOO_LONG: return "the command line does not fit the buffer";
  case PL5_BOOT_NO_ROOM:          return "the images do not fit in the staging area";
  case PL5_BOOT_INITRD_OVERLAP:   return "the initrd is not placed after the bzImage";
  case PL5_BOOT_UNALIGNED:        return "a size that must be page-granular is not";
  }
  return "?";
}

/* Validate a hand-off description before anything is staged.
 *
 * Deliberately refuses rather than clamps: a clamped size produces a boot that
 * half-works, which is harder to diagnose on a console than a refusal with a
 * reason.
 */
static inline enum pl5_boot_check pl5_boot_check_data(const struct pl5_boot_facts *f) {
  if (!f || f->page_size <= 0)
    return PL5_BOOT_MISSING;
  if (f->bzimage_size == 0)
    return PL5_BOOT_MISSING;
  if (f->bzimage_size < PL5_MIN_BZIMAGE)
    return PL5_BOOT_TOO_SMALL;
  if (f->hdr_magic != PL5_SETUP_HDR_MAGIC)
    return PL5_BOOT_BAD_MAGIC;
  if (f->boot_flag != PL5_BOOT_FLAG)
    return PL5_BOOT_BAD_MAGIC;
  if (f->hdr_version < PL5_MIN_BOOT_PROTOCOL)
    return PL5_BOOT_BAD_PROTOCOL;
  if (f->cmdline_len >= PL5_CMDLINE_CAP)
    return PL5_BOOT_CMDLINE_TOO_LONG;

  uint64_t aligned_bz = (f->bzimage_size + (uint64_t)f->page_size - 1) /
                        (uint64_t)f->page_size * (uint64_t)f->page_size;
  if (aligned_bz < f->bzimage_size)
    return PL5_BOOT_NO_ROOM; /* overflow */

  if (f->initrd_size) {
    if (f->initrd_offset != aligned_bz)
      return PL5_BOOT_INITRD_OVERLAP;
    if (f->initrd_size % (uint64_t)f->page_size != 0)
      return PL5_BOOT_UNALIGNED;
    uint64_t end = f->initrd_offset + f->initrd_size;
    if (end < f->initrd_offset)
      return PL5_BOOT_NO_ROOM; /* overflow */
    if (f->cave_start + end > f->cave_end)
      return PL5_BOOT_NO_ROOM;
  } else {
    if (f->cave_start + aligned_bz > f->cave_end)
      return PL5_BOOT_NO_ROOM;
  }
  return PL5_BOOT_OK;
}

#endif /* PL5_BOOT_DATA_H */
