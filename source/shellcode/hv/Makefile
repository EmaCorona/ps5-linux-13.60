ifeq ($(shell uname -m),aarch64)
CC      = x86_64-linux-gnu-gcc
LD      = x86_64-linux-gnu-ld
OBJCOPY = x86_64-linux-gnu-objcopy
else
CC      = gcc
LD      = ld
OBJCOPY = objcopy
endif
PL5_HV_STOP ?= 0
CFLAGS  = -O2 -fno-stack-protector -ffreestanding -nostdlib -fcf-protection=none -fomit-frame-pointer -mno-sse -mno-sse2 -m64 -DPL5_HV_STOP=$(PL5_HV_STOP)
LDFLAGS = -T linker.ld
TARGET  = shellcode_hv.elf
TEXT_BIN = shellcode_hv.bin
dump = shellcode_hv.h

SRC = main.c utils.c boot_linux.c
OBJ = $(SRC:.c=.o)

all: $(dump)

# Configuration stamp: CFLAGS is not an input of any rule, so a changed flag
# would otherwise reuse objects built with the previous value. The stamp file
# holds the flag value and is rewritten only when that value changes, which
# makes the objects depend on it and rebuild exactly then. Stated after
# `all`/OBJ so the default goal stays `all` and OBJ is defined.
STAMP := .pl5-config.stamp

.PHONY: FORCE
FORCE:
$(STAMP): FORCE
	@printf '%s\n' 'PL5_HV_STOP=$(PL5_HV_STOP)' | cmp -s - $@ \
		|| printf '%s\n' 'PL5_HV_STOP=$(PL5_HV_STOP)' > $@
$(OBJ): $(STAMP)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $(TARGET) $(TEXT_BIN)

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(dump)

$(dump): $(TEXT_BIN) ../../../scripts/bin2c.py
	python3 ../../../scripts/bin2c.py $(TEXT_BIN) > $(dump)
