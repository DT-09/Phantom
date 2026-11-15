AS ?= as
LD ?= ld
READELF ?= readelf
NM ?= nm
PYTHON ?= python3
BUILD := build
TARGET := $(BUILD)/phantom

.PHONY: all clean check test
all: $(TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/phantom.o: src/phantom.S | $(BUILD)
	$(AS) --64 -o $@ $<

$(TARGET): $(BUILD)/phantom.o
	$(LD) -z noexecstack -o $@ $<

check: $(TARGET)
	@$(READELF) -h $(TARGET) | grep -q 'Class:.*ELF64'
	@$(READELF) -h $(TARGET) | grep -q 'Machine:.*X86-64'
	@! $(READELF) -l $(TARGET) | grep -q INTERP
	@test -z "$$($(NM) -u $(TARGET))"
	@echo 'PHANTOM binary checks: PASS (ELF64, x86-64, static, no undefined symbols)'

test: check
	$(PYTHON) tests/test_phantom.py

clean:
	rm -rf $(BUILD)
