include Makefile.in
include build-target.in

EXAMPLES_ROOT=$(REPO_ROOT)/examples
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)


.PHONY: all
all: $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)


.PHONY: clean
clean:
	$(RM) -r $(DOXYGEN_OUTPUT_BASE) $(BUILD_DIR) core*


$(BUILD_DIR):
	cmake -S . -B $(BUILD_DIR) -DCMAKE_VERBOSE_MAKEFILE=YES


$(SHARED_LIB_FILE): $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)


.PHONY: install
install: $(SHARED_LIB_FILE)
	$(MAKE) -C $(BUILD_DIR) install


.PHONY: docs
docs:
	$(MAKE) -C $(BUILD_DIR) docs


.PHONY: examples
examples: $(X86_BINARY_IMAGES) $(SHARED_LIB_FILE)


.PHONY: test
test: $(BUILD_DIR) $(SHARED_LIB_FILE) $(BUSTED_EXE)
	$(MAKE) -C $(BUILD_DIR) test "ARGS=--output-on-failure -VV"


$(BUSTED_EXE):
	$(LUAROCKS_EXE) install busted


.PHONY: run_example
run_example: examples
	cd $(EXAMPLES_ROOT)/$(EXAMPLE) &&                   \
	LUA_CPATH="$(BUILT_LIBRARY_DIRECTORY)/?$(LIBRARY_EXTENSION);$(LUAROCKS_CPATH);;"  \
	LUA_PATH="$(LUAROCKS_LPATH);;"    \
	$(LUA_EXE) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


%.mips32.bin : %.s
	mips-linux-gnu-as -o $@.o -mips32 -EB $<
	mips-linux-gnu-ld -o $@ --oformat=binary -e main -sN $@.o
