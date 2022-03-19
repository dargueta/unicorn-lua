-include Makefile.in
-include lua-profile.mk

ifndef LUA
	LUA = lua
else
	LUA := $(realpath $(LUA))
endif

REPO_ROOT=$(CURDIR)
BUILD_DIR=$(REPO_ROOT)/build
EXAMPLES_ROOT=$(REPO_ROOT)/examples
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)
LIBRARY_SOURCES=$(wildcard src/*.cpp) $(wildcard include/unicornlua/*.h)
TEST_SOURCES=$(wildcard tests/c/*.cpp)		\
				$(wildcard tests/c/*.h)		\
				$(wildcard tests/lua/*.lua)
LIBRARY_FILENAME = unicorn$(LIBRARY_FILE_EXTENSION)
TEST_LIB_FILE = $(abspath $(BUILD_DIR)/lib/$(LIBRARY_FILENAME))
TEST_EXE_FILE = $(abspath $(BUILD_DIR)/tests_c/cpp_test)
INSTALL_TARGET = $(abspath $(INST_LIBDIR)/$(LIBRARY_FILENAME))
PROFILE_LUA_SCRIPT = $(LUA) tools/profile_lua.lua


ifndef BUILD_TYPE
	BUILD_TYPE = release
endif


.PHONY: all
all: | $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)


.PHONY: clean
clean:
	git clean -Xf


lua-profile.mk: tools/profile_lua.lua
	$(PROFILE_LUA_SCRIPT) $@ make $(MAKE_HOST)


lua-profile.cmake: tools/profile_lua.lua
	$(PROFILE_LUA_SCRIPT) $@ cmake $(MAKE_HOST)


lua-profile.json: tools/profile_lua.lua
	$(PROFILE_LUA_SCRIPT) $@ json $(MAKE_HOST)


# This is a convenience target that groups all the profile files together.
.PHONY: configuration_files
configuration_files: lua-profile.mk lua-profile.cmake lua-profile.json


# Run the configuration script to generate the file CMake needs for building the
# library.
.PHONY: __internal_configure
__internal_configure:
#ifeq ($(realpath $(INST_LIBDIR)),)
#    $(error "Target installation directory `$(INST_LIBDIR)` doesn't exist. Maybe override `INST_LIBDIR`?")
#endif
	python3 configure	--lua-exe-path $(realpath $(LUA))			\
						--lua-headers $(realpath $(LUA_INCDIR))		\
						--lua-library $(realpath $(LUA_LIBDIR))		\
						--install-prefix $(realpath $(INST_LIBDIR))	\
						--build-type $(BUILD_TYPE)


# Run the configuration script and generate the CMake include file. We have to
# run a separate Make process to invoke it because we need to reload lua-profile.mk.
configuration.cmake: configuration_files
	$(MAKE) __internal_configure


$(INSTALL_TARGET): $(LIBRARY_SOURCES)
	sudo $(MAKE) -C $(BUILD_DIR) install


.PHONY: install
install: $(INSTALL_TARGET)


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
	LUA_CPATH="$(INST_LIBDIR)/?$(LIBRARY_FILE_EXTENSION);$(LUAROCKS_CPATH);;"  \
	LUA_PATH="$(LUAROCKS_LPATH);;"    \
	$(LUA) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


%.mips32.bin : %.s
	mips-linux-gnu-as -o $@.o -mips32 -EB $<
	mips-linux-gnu-ld -o $@ --oformat=binary -e main -sN $@.o
