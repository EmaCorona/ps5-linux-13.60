.PHONY: all clean version offsets clean-objs

# The configuration-stamp rule below defines a target before `all`, so the
# default goal is stated explicitly instead of being "whichever target came
# first".
.DEFAULT_GOAL := all

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/pLinux5-NG.elf
SRC := $(wildcard source/*.c source/byepervisor/*.c source/core/*.c source/hw/*.c source/boot/*.c source/manifest/*.c source/offsets/*.c source/hv/defeat/*.c)
OBJS := $(SRC:.c=.o)

# Project identity lives in source/manifest/manifest.c (see include/manifest.h).
# Its .version is the single source of truth - CI reads the same field to name
# releases, so the ELF and the release cannot disagree.
MANIFEST_C := source/manifest/manifest.c
manifest-field = $(shell sed -n 's/^[[:space:]]*\.$(2)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' $(1))
PL5_VERSION := $(call manifest-field,$(MANIFEST_C),version)
ifeq ($(strip $(PL5_VERSION)),)
$(error could not read .version from $(MANIFEST_C))
endif

# Diagnostic bisection stage (see source/hv/defeat/hv_defeat_1320.c). Override on the
# command line, e.g. `make PL5_DIAG=1`. Remember to clear the objects first
# (the flag does not retrigger a rebuild on its own): `make -C . clean-objs`.
PL5_DIAG ?= 4
# Takeover-blob step selector (see source/shellcode/hv_takeover/takeover.S).
PL5_TAKEOVER_STAGE ?= 3
# Pre-rest-mode resume_rip probe (source/hv/defeat/hv_defeat_1320.c). Off by default so
# PL5_DIAG=4 runs the real post-resume flow; set to 1 for the probe build.
PL5_PROBE ?= 0
# shellcode_hv checkpoint bisection (source/shellcode/hv/boot_linux.c): freeze at a
# checkpoint instead of booting. 0=full boot, 1=entry, 2=post-configure_vram,
# 3=post-barrier.
PL5_HV_STOP ?= 0
# 13.60 post-resume takeover (phase B, source/hv/defeat/hv_defeat_1360.c).
# Off by default: an ordinary build must leave phase B disabled. This MUST be
# forwarded to the compiler, otherwise `make PL5_1360_TAKEOVER=1` is a silent
# no-op (the in-source default is 0) and the build would ship the phase-A-only
# binary while the operator believes the takeover is enabled.
PL5_1360_TAKEOVER ?= 0
# Firmware the shared takeover blob (source/shellcode/hv_takeover/takeover.S)
# is built for. It carries exactly one firmware's constants; the blob itself
# refuses a firmware whose values are not all known (13.60's HV handler PA is
# HV-resident). Forwarded to both the blob and the C side so they cannot
# disagree.
PL5_TAKEOVER_FW ?= 1320
# Arming the experimental #DB hook: doubly gated, off by default (Task 13.3).
# A build that sets the first must also acknowledge the second, otherwise
# hv_defeat_1360.c fails the compile on purpose.
PL5_1360_ARM_HOOK ?= 0
PL5_1360_ACK_EXPERIMENTAL_ARMING ?= 0
# Pre-sleep staging of the Linux hand-off (Task 15): off by default, because the
# ~64 MB cave write at arm time is still a suspect for the wake crash.
PL5_1360_STAGE_PRE_SLEEP ?= 0

CFLAGS  := -std=c23 -Wall -DPL5_DIAG=$(PL5_DIAG) -DPL5_TAKEOVER_STAGE=$(PL5_TAKEOVER_STAGE) -DPL5_PROBE=$(PL5_PROBE) -DPL5_1360_TAKEOVER=$(PL5_1360_TAKEOVER) -DPL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW) -DPL5_1360_ARM_HOOK=$(PL5_1360_ARM_HOOK) -DPL5_1360_ACK_EXPERIMENTAL_ARMING=$(PL5_1360_ACK_EXPERIMENTAL_ARMING) -DPL5_1360_STAGE_PRE_SLEEP=$(PL5_1360_STAGE_PRE_SLEEP) -Iinclude -Iinclude/core -Iinclude/hw -Iinclude/boot -Iinclude/byepervisor -Iinclude/hv/defeat -Iinclude/manifest -Iinclude/offsets -Isource/shellcode/hv -Isource/shellcode/kernel -Isource/shellcode/break_hv -Isource/shellcode/hv_boot -Isource/shellcode/hv_takeover

# Configuration stamp. The flags above are compiler options, not inputs of any
# rule, so make would happily reuse objects built with different ones. The stamp
# file stores every flag that reaches the compiler and is rewritten only when
# one of those values changes: the objects depend on it, so a flag switch
# rebuilds them (and re-enters the shellcode sub-makes, which stamp themselves)
# without needing an explicit clean.
PL5_CONFIG_STAMP := .pl5-config.stamp
PL5_CONFIG_VALUE := PL5_DIAG=$(PL5_DIAG) PL5_TAKEOVER_STAGE=$(PL5_TAKEOVER_STAGE) PL5_PROBE=$(PL5_PROBE) PL5_1360_TAKEOVER=$(PL5_1360_TAKEOVER) PL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW) PL5_HV_STOP=$(PL5_HV_STOP) PL5_1360_ARM_HOOK=$(PL5_1360_ARM_HOOK) PL5_1360_STAGE_PRE_SLEEP=$(PL5_1360_STAGE_PRE_SLEEP)

.PHONY: FORCE
FORCE:
$(PL5_CONFIG_STAMP): FORCE
	@printf '%s\n' '$(PL5_CONFIG_VALUE)' | cmp -s - $@ \
		|| printf '%s\n' '$(PL5_CONFIG_VALUE)' > $@
# pLabs5 toolchain override (see PORTING.md). Pass LLVM_CONFIG in the environment:
#   export LLVM_CONFIG=/nyaa/coding/public/PS5/dRPC5/pLabs5-SDK/tools/nixos/llvm-config
LDFLAGS := -lSceSystemService

SC_0607_H := source/shellcode/0607/shellcode_0607.h
SC_HV_H := source/shellcode/hv/shellcode_hv.h
SC_K_H  := source/shellcode/kernel/shellcode_kernel.h
SC_BREAK_H := source/shellcode/break_hv/break_hv.h
SC_BOOT_H := source/shellcode/hv_boot/hv_boot.h
SC_TAKEOVER_H := source/shellcode/hv_takeover/takeover.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(BIN)

# Every generated header follows the configuration stamp, so a flag change
# re-enters the sub-make, whose own stamp then rebuilds the blob.
$(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H): $(PL5_CONFIG_STAMP)

# Print the manifest version (read from source/manifest/manifest.c).
version:
	@printf '%s\n' '$(PL5_VERSION)'

# Offsets-dump payload (tools/pl5-offsets.c): runs the same 13.20 Byepervisor
# escape as the main payload + enters rest mode, but on resume (XOM on kernel
# .text now cleared) it dumps every offset to /data/pl5-<fw>.zip instead of
# taking over / booting Linux. Same entrypoint, just -DPL5_OFFSETS_MODE.
offsets: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H)
	$(CC) $(CFLAGS) -DPL5_OFFSETS_MODE $(SRC) tools/pl5-offsets.c $(LDFLAGS) \
		-o bin/pLinux5-NG-offsets.elf
	@echo "built bin/pLinux5-NG-offsets.elf"

$(SC_0607_H):
	$(MAKE) -C source/shellcode/0607

$(SC_HV_H):
	$(MAKE) -C source/shellcode/hv PL5_HV_STOP=$(PL5_HV_STOP)

$(SC_K_H): $(SC_HV_H)
	$(MAKE) -C source/shellcode/kernel

$(SC_BREAK_H):
	$(MAKE) -C source/shellcode/break_hv

$(SC_BOOT_H):
	$(MAKE) -C source/shellcode/hv_boot

$(SC_TAKEOVER_H):
	$(MAKE) -C source/shellcode/hv_takeover PL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# The userland objects include the generated shellcode headers; make the
# dependency explicit so `make -j` cannot compile them before the blobs exist.
$(OBJS): $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(PL5_CONFIG_STAMP)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean-objs:
	rm -f $(OBJS)

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C source/shellcode/0607 clean
	$(MAKE) -C source/shellcode/hv clean
	$(MAKE) -C source/shellcode/kernel clean
	$(MAKE) -C source/shellcode/break_hv clean
	$(MAKE) -C source/shellcode/hv_boot clean
	$(MAKE) -C source/shellcode/hv_takeover clean
