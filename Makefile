-include Makefile.in
include lua-profile.mk

EXAMPLES_ROOT ?= ./examples

SHARED_LIB_FILE = $(BUILD_DIR)/lib/unicorn$(LIBRARY_FILE_EXTENSION)
X86_BINARY_IMAGES = $(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES = $(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)

LUAROCKS_CPATH = $(shell $(LUAROCKS) path --lr-cpath)
LUAROCKS_LPATH = $(shell $(LUAROCKS) path --lr-path)


LUA_CPATH := $(INST_LIBDIR)/?$(LIBRARY_FILE_EXTENSION);$(LUAROCKS_CPATH);;
LUA_PATH := $(LUAROCKS_LPATH);;
export LUA_CPATH
export LUA_PATH


X86_ASM := $(or $(shell which nasm),$(shell which yasm))

.PHONY: all
all:
	$(MAKE) -C $(BUILD_DIR)


.PHONY: clean
clean:
	git clean -Xf
	$(RM) -r $(BUILD_DIR)


.PHONY: install
install: $(SHARED_LIB_FILE)
	sudo $(MAKE) -B -C $(BUILD_DIR) install


$(SHARED_LIB_FILE):
	$(MAKE) -C $(BUILD_DIR) unicornlua_library


.PHONY: test
test: $(BUSTED_EXE)
	$(MAKE) -C $(BUILD_DIR) cpp_test
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(UNICORN_LIBRARY_DIR) \
		$(MAKE) -B -C $(BUILD_DIR) test "ARGS=--output-on-failure -VV"


.PHONY: docs
docs:
	$(MAKE) -C $(BUILD_DIR) docs


.PHONY: examples
examples: $(X86_BINARY_IMAGES) $(SHARED_LIB_FILE)


$(BUSTED_EXE):
	$(LUAROCKS) install busted


.PHONY: run_example
run_example: examples
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(UNICORN_LIBRARY_DIR) ; \
		cd $(EXAMPLES_ROOT)/$(EXAMPLE) && $(LUA) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


%.mips32.bin : %.s
	mips-linux-gnu-as -o $@.o -mips32 -EB $<
	mips-linux-gnu-ld -o $@ --oformat=binary -e main -sN $@.o


%_const.cpp:
