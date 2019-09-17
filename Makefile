include Makefile.in

vpath %.h $(INCLUDE_BASE) $(UNICORN_INCLUDE_PATH)
vpath %.o $(OBJECT_DIR)
vpath %.c $(SRC_ROOT)

INCLUDE_UC_BASE=$(INCLUDE_BASE)/unicornlua
EXAMPLES_ROOT=$(REPO_ROOT)/docs/examples
BUILD_LUA_CPATH=$(BUILD_DIR)/?.$(LIB_EXTENSION);$(BUILD_DIR)/?/init.$(LIB_EXTENSION)
BUILD_LUA_PATH=$(BUILD_DIR)/?.lua;$(BUILD_DIR)/?/init.lua

GLOBAL_HEADERS=$(wildcard $(INCLUDE_UC_BASE)/*.h)
OBJECTS=$(C_SOURCE_FILES:src/%.cpp=build/obj/%.o)
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)

TESTS_BASE=$(REPO_ROOT)/tests
TESTS_C_FILES=$(wildcard $(TESTS_BASE)/c/*.cpp)
TESTS_LUA_FILES=$(wildcard $(TESTS_BASE)/lua/*.lua)

CFLAGS ?=
LDFLAGS ?=
IS_DEBUG ?= true

ifeq ($(IS_DEBUG), true)
	CFLAGS += -Og -ggdb
	LDFLAGS += -O0
else
	CFLAGS += -Ofast
	LDFLAGS += --strip-all -O1
endif

CFLAGS += -c -fno-rtti -fpic -fvisibility=hidden -std=c++11 -Wall -Wextra -Werror -I$(INCLUDE_BASE) -I$(LUA_INCLUDE_PATH) -I$(UNICORN_INCLUDE_PATH)
LDFLAGS += -fno-rtti -fpic -shared -L$(LUA_LIB_PATH) -L$(UNICORN_LIB_PATH)

DOXYGEN_OUTPUT_BASE=$(REPO_ROOT)/docs/api

# These must come at the end of the link command, after the object files. Thus, we're
# forced to use a separate variable.
ifeq ($(DETECTED_PLATFORM), macosx)
	# OSX requires linking the Lua library to be able to use it from Lua.
	LINK_LIBRARIES = -llua -lunicorn -lpthread
else
	# Linux doesn't require linking with the Lua library. In fact, doing so breaks the
	# linker because it requires using -fPIC instead of -fpic.
	LINK_LIBRARIES = -lunicorn -lpthread
endif

SHARED_LIB_FILE=$(INSTALL_STAGING_DIR)/_clib.$(LIB_EXTENSION)

.PHONY: all
all: $(OBJECT_DIR) $(INSTALL_STAGING_DIR) $(SHARED_LIB_FILE) $(X86_BINARY_IMAGES) $(LUA_SOURCE_FILES) $(LUA_AUTOGEN_FILES)


.PHONY: clean
clean:
	rm -rf $(DOXYGEN_OUTPUT_BASE) $(BUILD_DIR)


.PHONY: docs
docs: $(DOXYGEN_OUTPUT_BASE)

$(DOXYGEN_OUTPUT_BASE): $(C_SOURCE_FILES) $(C_HEADER_FILES) Doxyfile
	doxygen

.PHONY: test_c
test_c: $(SHARED_LIB_FILE)


.PHONY: test_lua
test_lua: $(SHARED_LIB_FILE) $(TESTS_LUA_FILES)
	LD_LIBRARY_PATH="$(UNICORN_LIB_PATH):$(LD_LIBRARY_PATH)"    \
	LUA_CPATH="$(LUA_CUSTOM_CPATH);$(BUILD_LUA_CPATH)"          \
	LUA_PATH="$(LUA_CUSTOM_LPATH);$(BUILD_LUA_PATH)"            \
	PATH="$(LUA_CUSTOM_EXEPATH):$(PATH)"                        \
	$(BUSTED_EXE) $(BUSTED_CLI_ARGS)


.PHONY: test
test: test_c test_lua


.PHONY: examples
examples: $(X86_BINARY_IMAGES) $(SHARED_LIB_FILE)


.PHONY: run_example
run_example: examples
	cd $(EXAMPLES_ROOT)/$(EXAMPLE) &&                   \
	LUA_CPATH="$(LUA_CUSTOM_CPATH);$(BUILD_LUA_CPATH)"  \
	LUA_PATH="$(LUA_CUSTOM_LPATH);$(BUILD_LUA_PATH)"    \
	PATH="$(LUA_CUSTOM_EXEPATH):$(PATH)"                \
	$(LUA_EXE) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


build/obj/%.o : src/%.cpp
	$(CXX) $(CFLAGS) -o $@ $^


%.h: ;


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


%.mips32.bin : %.s
	mips-linux-gnu-as -o $@.o -mips32 -EB $<
	mips-linux-gnu-ld -o $@ --oformat=binary -e main -sN $@.o


$(BUILD_DIR) :
	mkdir -p $(BUILD_DIR)

$(OBJECT_DIR) :
	mkdir -p $(OBJECT_DIR)

$(INSTALL_STAGING_DIR) :
	mkdir -p $(INSTALL_STAGING_DIR)

$(INSTALL_STAGING_DIR)/%_const.lua : $(UNICORN_INCLUDE_PATH)/%.h | $(INSTALL_STAGING_DIR)
	python3 tools/generate_constants.py $^ $@

$(INSTALL_STAGING_DIR)/%.lua : $(SRC_ROOT)/%.lua | $(INSTALL_STAGING_DIR)
	cp $^ $@

$(OBJECT_DIR)/compat.o: $(SRC_ROOT)/compat.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/engine.o: $(SRC_ROOT)/engine.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/hooks.o: $(SRC_ROOT)/hooks.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/memory.o: $(SRC_ROOT)/memory.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/registers.o: $(SRC_ROOT)/registers.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/unicorn.o: $(C_SOURCES) | $(OBJECT_DIR)
$(OBJECT_DIR)/utils.o: $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)

$(SHARED_LIB_FILE): $(OBJECTS) | $(INSTALL_STAGING_DIR)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LINK_LIBRARIES)
