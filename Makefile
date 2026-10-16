.PHONY: all clean version offsets verify-offsets verify-resume verify-offsets-text disarm gpu-textverify t5-report-only t5b-install-no-arm clean-objs

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
# T5 report-only resume diagnostic: stage the escape, enter standby, and on the
# wake *report* the state instead of arming anything or running the post-resume
# takeover. Off by default, and hv_defeat_1360.c fails the compile unless every
# arming / takeover / pre-sleep-staging flag is 0 as well (fail-closed).
PL5_1360_RESUME_REPORT_ONLY ?= 0
# T5b: install the resume chain but never make the hijack live. Requires
# PL5_1360_RESUME_REPORT_ONLY=1 and the four arming/takeover/staging flags at 0;
# hv_defeat_1360.c refuses the combination otherwise. Off by default.
PL5_1360_INSTALL_NO_ARM ?= 0
# Commit the artifact was built from, printed in the log header so a run's log
# can be tied back to a revision. It changes no code path, but it is part of the
# stamp so a binary can never be attributed to the wrong revision.
PL5_BUILD_COMMIT ?= unknown

CFLAGS  := -std=c23 -Wall -DPL5_DIAG=$(PL5_DIAG) -DPL5_TAKEOVER_STAGE=$(PL5_TAKEOVER_STAGE) -DPL5_PROBE=$(PL5_PROBE) -DPL5_1360_TAKEOVER=$(PL5_1360_TAKEOVER) -DPL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW) -DPL5_1360_ARM_HOOK=$(PL5_1360_ARM_HOOK) -DPL5_1360_ACK_EXPERIMENTAL_ARMING=$(PL5_1360_ACK_EXPERIMENTAL_ARMING) -DPL5_1360_STAGE_PRE_SLEEP=$(PL5_1360_STAGE_PRE_SLEEP) -DPL5_1360_RESUME_REPORT_ONLY=$(PL5_1360_RESUME_REPORT_ONLY) -DPL5_1360_INSTALL_NO_ARM=$(PL5_1360_INSTALL_NO_ARM) -DPL5_BUILD_COMMIT='"$(PL5_BUILD_COMMIT)"' -Iinclude -Iinclude/core -Iinclude/hw -Iinclude/boot -Iinclude/byepervisor -Iinclude/hv/defeat -Iinclude/manifest -Iinclude/offsets -Isource/shellcode/hv -Isource/shellcode/kernel -Isource/shellcode/break_hv -Isource/shellcode/hv_boot -Isource/shellcode/hv_takeover -Isource/shellcode/db_trampoline

# Configuration stamp. The flags above are compiler options, not inputs of any
# rule, so make would happily reuse objects built with different ones. The stamp
# file stores every flag that reaches the compiler and is rewritten only when
# one of those values changes: the objects depend on it, so a flag switch
# rebuilds them (and re-enters the shellcode sub-makes, which stamp themselves)
# without needing an explicit clean.
PL5_CONFIG_STAMP := .pl5-config.stamp
# It must carry *every* flag that reaches the compiler through CFLAGS, because a
# stale object built with a different value is exactly how `make
# PL5_1360_ARM_HOOK=1` could ship an unacknowledged arming build: with PL5_DIAG
# hard-wired to 16 in the environment, the ack guard would never be re-evaluated.
# tests/run_tests.py checks that no -D flag in CFLAGS is missing from this list.
PL5_CONFIG_VALUE := PL5_DIAG=$(PL5_DIAG) PL5_TAKEOVER_STAGE=$(PL5_TAKEOVER_STAGE) PL5_PROBE=$(PL5_PROBE) PL5_1360_TAKEOVER=$(PL5_1360_TAKEOVER) PL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW) PL5_HV_STOP=$(PL5_HV_STOP) PL5_1360_ARM_HOOK=$(PL5_1360_ARM_HOOK) PL5_1360_ACK_EXPERIMENTAL_ARMING=$(PL5_1360_ACK_EXPERIMENTAL_ARMING) PL5_1360_STAGE_PRE_SLEEP=$(PL5_1360_STAGE_PRE_SLEEP) PL5_1360_RESUME_REPORT_ONLY=$(PL5_1360_RESUME_REPORT_ONLY) PL5_1360_INSTALL_NO_ARM=$(PL5_1360_INSTALL_NO_ARM) PL5_BUILD_COMMIT=$(PL5_BUILD_COMMIT)

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
# Stage-1 #DB trampoline. Built and validated on every build, but only staged into the
# scratch page when the hook is armed (PL5_1360_ARM_HOOK=1) -- so a default build
# carries it as an artifact, not as live code.
SC_TRAMPOLINE_H := source/shellcode/db_trampoline/db_trampoline.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H) $(BIN)

# Every generated header follows the configuration stamp, so a flag change
# re-enters the sub-make, whose own stamp then rebuilds the blob.
$(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H): $(PL5_CONFIG_STAMP)

# Print the manifest version (read from source/manifest/manifest.c).
version:
	@printf '%s\n' '$(PL5_VERSION)'

# Offsets-dump payload (tools/pl5-offsets.c): runs the same 13.20 Byepervisor
# escape as the main payload + enters rest mode, but on resume (XOM on kernel
# .text now cleared) it dumps every offset to /data/pl5-<fw>.zip instead of
# taking over / booting Linux. Same entrypoint, just -DPL5_OFFSETS_MODE.
offsets: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	$(CC) $(CFLAGS) -DPL5_OFFSETS_MODE $(SRC) tools/pl5-offsets.c $(LDFLAGS) \
		-o bin/pLinux5-NG-offsets.elf
	@echo "built bin/pLinux5-NG-offsets.elf"

# WS2: diagnostica di verifica degli offset. Stesso entrypoint del payload, ma
# -DPL5_VERIFY_MODE esce subito dopo setup_env(): nessun escape, nessun armo,
# nessuno standby. Serve a confrontare i valori risolti con la tabella in uso e
# con il kernel vivo, senza toccare nulla.
# WS3: payload di ripristino. -DPL5_DISARM_MODE esce subito dopo setup_env() e
# chiama hv_defeat_1360_restore(): XOTEXT su .text, RW giu', marker ARMED a 0.
disarm: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DPL5_DISARM_MODE $(SRC) $(LDFLAGS) -o bin/pl5-disarm.elf
	@echo "built bin/pl5-disarm.elf"

# WS2b: come verify-offsets ma legge anche i sei valori in .text via direct map.
verify-offsets-text: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DPL5_VERIFY_MODE -DPL5_VERIFY_TEXT=1 $(SRC) tools/pl5-verify-offsets.c $(LDFLAGS) \
		-o bin/pl5-verify-offsets-text.elf
	@echo "built bin/pl5-verify-offsets-text.elf"

# WS2b: .text attraverso la GPU (la via documentata). Esclude source/main.c
# perche' il tool ha un main() proprio, come i probe storici.
gpu-textverify: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(filter-out source/main.c,$(SRC)) tools/pl5-gpu-textverify.c $(LDFLAGS) \
		-o bin/pl5-gpu-textverify.elf
	@echo "built bin/pl5-gpu-textverify.elf"

verify-offsets: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DPL5_VERIFY_MODE $(SRC) tools/pl5-verify-offsets.c $(LDFLAGS) \
		-o bin/pl5-verify-offsets.elf
	@echo "built bin/pl5-verify-offsets.elf"

# T5 (analyst plan, phase 5): read-only post-resume state check. Same entrypoint
# and same guarantees as verify-offsets (no escape, no arming, no standby, no
# write of any kind): it only *reads* the .text page-table bits, the cave marker
# and the IDT gate, so it can be run after a staging run on the same power-up
# without spending that power-up's single writing action.
verify-resume: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DPL5_VERIFY_MODE -DPL5_VERIFY_RESUME=1 $(SRC) tools/pl5-verify-offsets.c $(LDFLAGS) \
		-o bin/pl5-verify-resume.elf
	@echo "built bin/pl5-verify-resume.elf"

# T5: build the report-only resume diagnostic under its own name, and refuse to
# do it unless the flag was actually requested. The four ways of confounding the
# measurement (arm / ack / takeover / pre-sleep staging) are refused by the
# compile-time guard in hv_defeat_1360.c; this target only pins the artefact name
# to the configuration so a binary and its recorded flags cannot disagree.
t5-report-only: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	@test "$(PL5_1360_RESUME_REPORT_ONLY)" = "1" \
		|| { echo "t5-report-only: run as 'make PL5_DIAG=4 PL5_1360_RESUME_REPORT_ONLY=1 PL5_BUILD_COMMIT=<sha> t5-report-only'"; exit 2; }
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o bin/pl5-t5-report-only.elf
	@echo "built bin/pl5-t5-report-only.elf (diag=$(PL5_DIAG) report_only=$(PL5_1360_RESUME_REPORT_ONLY) build_commit=$(PL5_BUILD_COMMIT))"

# T5b: install the chain without arming it. Refuses to build unless both flags
# were requested, so the artefact name and the configuration cannot disagree; the
# other preconditions are refused by the compile-time guards in hv_defeat_1360.c.
t5b-install-no-arm: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H)
	@mkdir -p bin
	@test "$(PL5_1360_RESUME_REPORT_ONLY)" = "1" -a "$(PL5_1360_INSTALL_NO_ARM)" = "1" \
		|| { echo "t5b-install-no-arm: run as 'make PL5_DIAG=4 PL5_1360_RESUME_REPORT_ONLY=1 PL5_1360_INSTALL_NO_ARM=1 PL5_BUILD_COMMIT=<sha> t5b-install-no-arm'"; exit 2; }
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o bin/pl5-t5b-install-no-arm.elf
	@echo "built bin/pl5-t5b-install-no-arm.elf (diag=$(PL5_DIAG) report_only=$(PL5_1360_RESUME_REPORT_ONLY) install_no_arm=$(PL5_1360_INSTALL_NO_ARM) build_commit=$(PL5_BUILD_COMMIT))"


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

$(SC_TRAMPOLINE_H):
	$(MAKE) -C source/shellcode/db_trampoline

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# The userland objects include the generated shellcode headers; make the
# dependency explicit so `make -j` cannot compile them before the blobs exist.
$(OBJS): $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_TRAMPOLINE_H) $(PL5_CONFIG_STAMP)

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
	$(MAKE) -C source/shellcode/db_trampoline clean
