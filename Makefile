-include Makefile.in
-include lua-profile.mk

EXAMPLES_ROOT=$(REPO_ROOT)/examples
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)
LIBRARY_SOURCES=$(wildcard src/*.cpp) $(wildcard include/unicornlua/*.h)
TEST_SOURCES=$(wildcard tests/c/*.cpp) $(wildcard tests/c/*.h) $(wildcard tests/lua/*.lua)


.PHONY: all
all: $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)


.PHONY: clean
clean:
	$(MAKE) -C $(BUILD_DIR) clean
	cmake -E rm -rf $(DOXYGEN_OUTPUT_BASE) core*


.PHONY: pristine
pristine: clean
	cmake -E rm -rf $(VIRTUALENV_DIR) *.in configuration.cmake

$(BUILD_DIR):
	cmake -S $(REPO_ROOT) -B $(BUILD_DIR) -DCMAKE_VERBOSE_MAKEFILE=YES


$(SHARED_LIB_FILE): $(LIBRARY_SOURCES) | $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR) unicornlua_library


$(TEST_EXE_FILE): $(SHARED_LIB_FILE) $(TEST_SOURCES)
	$(MAKE) -C $(BUILD_DIR) cpp_test


.PHONY: test
test: $(TEST_EXE_FILE) $(TEST_SOURCES) $(BUSTED_EXE)
	$(MAKE) -C $(BUILD_DIR) test "ARGS=--output-on-failure -VV"


.PHONY: install
install: $(SHARED_LIB_FILE)
	$(MAKE) -C $(BUILD_DIR) install


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
ifndef LUA_EXE
	$(error "You must provide the LUA_EXE variable")
endif
	$(LUA_EXE) tools/profile_lua.lua $@ make $(MAKE_HOST)

lua-profile.cmake: tools/profile_lua.lua
ifndef LUA_EXE
	$(error "You must provide the LUA_EXE variable")
endif
	$(LUA_EXE) tools/profile_lua.lua $@ cmake $(MAKE_HOST)

lua-profile.json: tools/profile_lua.lua
ifndef LUA_EXE
	$(error "You must provide the LUA_EXE variable")
endif
	$(LUA_EXE) tools/profile_lua.lua $@ json $(MAKE_HOST)


.PHONY: configuration_files
configuration_files: lua-profile.mk lua-profile.cmake lua-profile.json
