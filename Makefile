CC = gcc
CFLAGS = -O2 -g -Wall -Wextra -D_GNU_SOURCE -std=gnu11 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wno-format-truncation
LDFLAGS = -pie -Wl,-z,relro,-z,now
OBJS = core/main.o core/rules.o core/preflight.o core/ext.o core/cve.o core/hardening.o asm/scan_x86_64.o
GOV = gov/target/release/libgov.a
LIBS = $(GOV) -lpthread -ldl -lm -lrt -lutil -lgcc_s
BIN = deanbluntVulnSeeker19

$(BIN): $(OBJS) $(GOV)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

$(GOV): gov/src/lib.rs gov/Cargo.toml
	cd gov && cargo build --release

core/%.o: core/%.c core/common.h core/gov.h
	$(CC) $(CFLAGS) -c $< -o $@

asm/%.o: asm/%.S
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN)
	cd gov && cargo clean

.PHONY: clean

# build is make, cargo is invoked for the governor and linked as a static library
