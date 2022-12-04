-include Makefile.in
include lua-profile.mk


REPO_ROOT ?= $(CURDIR)
BUILD_DIR ?= $(REPO_ROOT)/build
EXAMPLES_ROOT ?= $(REPO_ROOT)/examples
BUILD_TYPE ?= release

LUAROCKS_CPATH = $(shell $(LUAROCKS) path --lr-cpath)
LUAROCKS_LPATH = $(shell $(LUAROCKS) path --lr-path)

X86_BINARY_IMAGES = $(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES = $(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)
LIBRARY_SOURCES = $(wildcard src/*.cpp) $(wildcard include/unicornlua/*.h)
TEST_SOURCES = $(wildcard tests/c/*.cpp)   \
               $(wildcard tests/c/*.h)     \
               $(wildcard tests/lua/*.lua)
LIBRARY_FILENAME = unicorn$(LIBRARY_FILE_EXTENSION)
TEST_LIB_FILE = $(abspath $(BUILD_DIR)/lib/$(LIBRARY_FILENAME))
TEST_EXE_FILE = $(abspath $(BUILD_DIR)/tests_c/cpp_test)
INSTALL_TARGET = $(abspath $(INST_LIBDIR)/$(LIBRARY_FILENAME))


.PHONY: all
all: | $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)


.PHONY: clean
clean:
	git clean -Xf


.PHONY: install
install: config $(INSTALL_TARGET)


$(INSTALL_TARGET): $(LIBRARY_SOURCES) | $(BUILD_DIR)
	sudo $(MAKE) -C $(BUILD_DIR) install


$(BUILD_DIR): lua-profile.cmake
	cmake -S . -B $@                           \
		-DCMAKE_INSTALL_PREFIX=$(INST_LIBDIR)  \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE)       \
		-DCMAKE_VERBOSE_MAKEFILE=YES           \
		-DLUAROCKS=$(LUAROCKS)

$(TEST_LIB_FILE): $(LIBRARY_SOURCES) | $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR) unicornlua_library


$(TEST_EXE_FILE): $(TEST_LIB_FILE) $(TEST_SOURCES)
	$(MAKE) -C $(BUILD_DIR) cpp_test


.PHONY: test
test: $(TEST_EXE_FILE) $(TEST_SOURCES) $(BUSTED_EXE)
	$(MAKE) -C $(BUILD_DIR) test "ARGS=--output-on-failure -VV"


.PHONY: docs
docs:
	$(MAKE) -C $(BUILD_DIR) docs


.PHONY: examples
examples: $(X86_BINARY_IMAGES) $(SHARED_LIB_FILE)


$(BUSTED_EXE):
	$(LUAROCKS) install busted


.PHONY: run_example
run_example: examples
	cd $(EXAMPLES_ROOT)/$(EXAMPLE) &&                   \
	LUA_CPATH="$(INST_LIBDIR)/?$(LIBRARY_FILE_EXTENSION);$(LUAROCKS_CPATH);;"  \
	LUA_PATH="$(LUAROCKS_LPATH);;"    \
	$(LUA) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


%.mips32.bin : %.s
	mips-linux-gnu-as -o $@.o -mips32 -EB $<
	mips-linux-gnu-ld -o $@ --oformat=binary -e main -sN $@.o
