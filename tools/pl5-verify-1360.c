/* pl5-verify-1360 — hardened offset validator for the 13.60 port.
 *
 * Safety rules (docs/analyst-recap-1360.md, Priority 0):
 *   1. an offset below TEXT_END (0xCC0000) is refused: ktext-relative space
 *      starts after .text, and .text is fatal to read on this console;
 *   2. every constant carries a namespace and namespaces are never mixed;
 *   3. dry-run is the default; --commit is required to actually read;
 *   4. exactly one spec per invocation.
 *
 * usage:
 *   pl5-verify-1360 KTEXT:0x3B48FF8            # dry run
 *   pl5-verify-1360 KTEXT:0x3B48FF8 --commit   # read 8 bytes
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ps5/kernel.h>

#define TEXT_END  0xCC0000UL                  /* .text size in the image */
#define IMAGE_END (TEXT_END + 0x55FA000UL)    /* text + captured data    */

enum ns { NS_KTEXT, NS_HV, NS_DATA, NS_PHYS, NS_BAD };

static const char *ns_name(enum ns n) {
  switch (n) {
  case NS_KTEXT: return "KTEXT";
  case NS_HV:    return "HV";
  case NS_DATA:  return "DATA";
  case NS_PHYS:  return "PHYS";
  default:       return "BAD";
  }
}

static const char *expected_section(unsigned long off) {
  if (off < TEXT_END)  return "TEXT  <-- FORBIDDEN, would power the console off";
  if (off < IMAGE_END) return "data";
  return "outside the captured image";
}

int main(int argc, char **argv) {
  const char *spec = NULL;
  int commit = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--commit")) commit = 1;
    else if (!spec) spec = argv[i];
    else { printf("REFUSED: more than one spec per invocation\n"); return 2; }
  }
  static char spec_buf[128];
  if (!spec) {
    /* elfldr hands a payload_args struct, not argv: read the spec from a file.
     * line 1 = NS:OFFSET, optional line 2 containing "commit". */
    FILE *f = fopen("/data/pl5-verify-spec.txt", "r");
    if (f) {
      if (fgets(spec_buf, sizeof spec_buf, f)) {
        char *nl = strpbrk(spec_buf, "\r\n");
        if (nl) *nl = 0;
        spec = spec_buf;
      }
      char l2[64];
      if (fgets(l2, sizeof l2, f) && strstr(l2, "commit")) commit = 1;
      fclose(f);
    }
  }
  if (!spec || !*spec) {
    printf("usage: pl5-verify-1360 <NS:OFFSET> [--commit]\n"
           "  or write the spec to /data/pl5-verify-spec.txt\n"
           "  NS in {KTEXT,HV,DATA,PHYS}; one offset per run\n");
    return 2;
  }

  enum ns ns = NS_BAD;
  const char *colon = strchr(spec, ':');
  if (!colon || colon == spec) { printf("REFUSED: namespace required (NS:OFFSET)\n"); return 2; }
  if      (!strncmp(spec, "KTEXT:", 6)) ns = NS_KTEXT;
  else if (!strncmp(spec, "HV:",    3)) ns = NS_HV;
  else if (!strncmp(spec, "DATA:",  5)) ns = NS_DATA;
  else if (!strncmp(spec, "PHYS:",  5)) ns = NS_PHYS;
  else { printf("REFUSED: unknown namespace in '%s'\n", spec); return 2; }

  unsigned long off = strtoul(colon + 1, NULL, 0);
  uint64_t ktext = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;

  printf("fw=%08x\n", kernel_get_fw_version());
  printf("namespace        : %s\n", ns_name(ns));
  printf("base             : ktext=%#lx\n", (unsigned long)ktext);
  printf("offset           : %#lx\n", off);
  printf("expected section : %s\n", expected_section(off));

  if (ns != NS_KTEXT) {
    printf("REFUSED: namespace %s is not ktext-relative; this tool only reads\n"
           "         ktext-relative addresses. HV values must never be added to\n"
           "         ktext (that is what powered the console off).\n", ns_name(ns));
    return 3;
  }
  if (off < TEXT_END) {
    printf("REFUSED: offset %#lx < %#lx (.text). Reading .text powers this console off.\n",
           off, (unsigned long)TEXT_END);
    return 4;
  }

  uint64_t va = ktext + off;
  printf("resulting VA     : %#lx\n", (unsigned long)va);

  if (!commit) {
    printf("DRY RUN — nothing read. Re-run with --commit to read 8 bytes.\n");
    return 0;
  }

  uint64_t v = 0;
  int rc = kernel_copyout((intptr_t)va, &v, 8);
  if (rc == 0) {
    printf("COMMIT RESULT: off=%#lx raw=%016lx value=%#lx\n",
           off, (unsigned long)v, (unsigned long)v);
  } else {
    printf("COMMIT RESULT: off=%#lx READ_FAIL rc=%d\n", off, rc);
  }
  fflush(stdout);
  return 0;
}
