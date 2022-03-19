-include Makefile.in
-include lua-profile.mk

ifndef LUA
	LUA = lua
else
	LUA := $(realpath $(LUA))
endif

REPO_ROOT=$(CURDIR)
BUILD_DIR=$(join $(REPO_ROOT),build)
EXAMPLES_ROOT=$(REPO_ROOT)/examples
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)
LIBRARY_SOURCES=$(wildcard $(join src,*.cpp))	\
				$(wildcard $(join "include",unicornlua,*.h))
TEST_SOURCES=$(wildcard $(join tests,c,*.cpp))		\
				$(wildcard $(join tests,c,*.h))		\
				$(wildcard $(join tests,lua,*.lua))
LIBRARY_FILENAME = unicorn$(LIBRARY_FILE_EXTENSION)
TEST_LIB_FILE = $(abspath $(join "$(BUILD_DIR)",lib,$(LIBRARY_FILENAME)))
TEST_EXE_FILE = $(abspath $(join "$(BUILD_DIR)",tests_c,cpp_test))
INSTALL_TARGET = $(abspath $(join $(INST_LIBDIR),$(LIBRARY_FILENAME)))


ifndef BUILD_TYPE
	BUILD_TYPE = release
endif


.PHONY: all
all: | $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)


.PHONY: clean
clean:
	-$(MAKE) -C $(BUILD_DIR) clean
	cmake -E rm -rf $(DOXYGEN_OUTPUT_BASE) core*


.PHONY: pristine
pristine: clean
	cmake -E rm -rf *.in configuration.cmake lua-profile.*

$(BUILD_DIR): configuration.cmake
	cmake -S $(REPO_ROOT) -B $(BUILD_DIR) -DCMAKE_VERBOSE_MAKEFILE=YES


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


lua-profile.mk: tools/profile_lua.lua
	$(LUA) tools/profile_lua.lua $@ make $(MAKE_HOST)


lua-profile.cmake: tools/profile_lua.lua
	$(LUA) tools/profile_lua.lua $@ cmake $(MAKE_HOST)


lua-profile.json: tools/profile_lua.lua
	$(LUA) tools/profile_lua.lua $@ json $(MAKE_HOST)


.PHONY: configuration_files
configuration_files: lua-profile.mk lua-profile.cmake lua-profile.json


.PHONY: __internal_configure
__internal_configure:
	python3 configure	--lua-exe-path $(realpath $(LUA))			\
						--lua-headers $(realpath $(LUA_INCDIR))		\
						--lua-library $(realpath $(LUA_LIBDIR))		\
						--install-prefix $(realpath $(INST_LIBDIR))	\
						--build-type $(BUILD_TYPE)


configuration.cmake: configuration_files
	$(MAKE) __internal_configure

$(INSTALL_TARGET): $(LIBRARY_SOURCES)
	sudo $(MAKE) -C $(BUILD_DIR) install

.PHONY: install
install: $(INSTALL_TARGET)
