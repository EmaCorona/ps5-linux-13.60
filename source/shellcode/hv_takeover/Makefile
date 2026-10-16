ifeq ($(shell uname -m),aarch64)
CC      = x86_64-linux-gnu-gcc
LD      = x86_64-linux-gnu-ld
OBJCOPY = x86_64-linux-gnu-objcopy
else
CC      = gcc
LD      = ld
OBJCOPY = objcopy
endif
# Firmware the shared takeover blob is built for. The blob carries one
# firmware's constants (the HV handler PA is not derivable from a kernel dump),
# so it must be selected explicitly and never assumed.
PL5_TAKEOVER_FW ?= 1320
CFLAGS  = -O2 -fno-stack-protector -ffreestanding -nostdlib -fcf-protection=none -fomit-frame-pointer -mno-sse -mno-sse2 -m64 -DPL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW)
LDFLAGS = -T linker.ld
TARGET  = takeover.elf
TEXT_BIN = takeover.bin
dump = takeover.h

SRC = takeover.S
OBJ = $(SRC:.S=.o)

all: $(dump)

# Configuration stamp: the blob carries one firmware's constants, so switching
# PL5_TAKEOVER_FW must rebuild it even without an explicit clean. The stamp file
# holds the flag value and is rewritten only when that value changes. Stated
# after `all`/OBJ so the default goal stays `all` and OBJ is defined.
STAMP := .pl5-config.stamp

.PHONY: FORCE
FORCE:
$(STAMP): FORCE
	@printf '%s\n' 'PL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW)' | cmp -s - $@ \
		|| printf '%s\n' 'PL5_TAKEOVER_FW=$(PL5_TAKEOVER_FW)' > $@
$(OBJ): $(STAMP)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(TARGET)

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $(TARGET) $(TEXT_BIN)

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(dump)

$(dump): $(TEXT_BIN) ../../../scripts/bin2c.py
	python3 ../../../scripts/bin2c.py $(TEXT_BIN) > $(dump)
