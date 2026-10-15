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

#include <fcntl.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"

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
  notify("gpuprobe: done (no retarget, no DMA submitted)\n");
  return 0;
}
