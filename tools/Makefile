.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := pl5-offsets.elf
SIGTABLE ?= sigtable_1320.h

CFLAGS += -DPL5_SIGTABLE_HEADER='"$(SIGTABLE)"'
# The live-read policy header (include/tools/pl5_dump_policy.h) is included by
# pl5-offsets.c and by the host test suite, so the same decision code runs in
# both places.
CFLAGS += -I../include

all: $(BIN)

$(BIN): pl5-offsets.c $(SIGTABLE)
	$(CC) $(CFLAGS) pl5-offsets.c $(LDFLAGS) -o $@

clean:
	rm -f $(BIN)
