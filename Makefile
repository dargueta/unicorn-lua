include Makefile.in


INCLUDE_UC_BASE=$(INCLUDE_BASE)/unicornlua
EXAMPLES_ROOT=$(REPO_ROOT)/examples
BUILD_LUA_CPATH=$(BUILD_DIR)/?.$(LIB_EXTENSION);$(BUILD_DIR)/?/init.$(LIB_EXTENSION)
BUILD_LUA_PATH=$(BUILD_DIR)/?.lua;$(BUILD_DIR)/?/init.lua

GLOBAL_HEADERS=$(wildcard $(INCLUDE_UC_BASE)/*.h)
OBJECTS=$(C_SOURCE_FILES:src/%.cpp=build/obj/%.o)
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)

TESTS_BASE=$(REPO_ROOT)/tests
TESTS_C_FILES=$(wildcard $(TESTS_BASE)/c/*.cpp)
TESTS_H_FILES=$(wildcard $(TESTS_BASE)/c/*.h)
TESTS_LUA_FILES=$(wildcard $(TESTS_BASE)/lua/*.lua)
DOCTEST_HEADER=$(TESTS_BASE)/c/doctest.h

CFLAGS ?=
LDFLAGS ?=
IS_DEBUG ?= true

ifeq ($(IS_DEBUG), true)
	CFLAGS += -Og -ggdb -frtti -D DOCTEST_CONFIG_NO_COMPARISON_WARNING_SUPPRESSION
	LDFLAGS += -O0
else
	CFLAGS += -Ofast -D NDEBUG -D DOCTEST_CONFIG_DISABLE -fno-rtti -fvisibility=hidden
	LDFLAGS += --strip-all -O1
endif

INCLUDE_FLAGS=-I$(INCLUDE_BASE) -I$(LUA_INCLUDE_PATH) -I$(UNICORN_INCLUDE_PATH)
LIB_SEARCH_FLAGS=-L$(LUA_LIB_PATH) -L$(UNICORN_LIB_PATH)
W_FLAGS=-Wall -Wextra -Werror -Wpedantic

CFLAGS += -c -fpic -std=c++11 $(W_FLAGS) $(INCLUDE_FLAGS)
LDFLAGS += -fpic $(LIB_SEARCH_FLAGS)

DOXYGEN_OUTPUT_BASE=$(REPO_ROOT)/docs/api

ifeq ($(DETECTED_PLATFORM), macosx)
	# Apparently OSX requires this stuff: https://stackoverflow.com/q/42371892
	LDFLAGS += -dynamiclib -undefined dynamic_lookup
else
	LDFLAGS += -shared
endif

# These must come at the end of the link command, after the object files. Thus, we're
# forced to use a separate variable.
LINK_LIBRARIES = -lunicorn -lpthread

SHARED_LIB_FILE=$(INSTALL_STAGING_DIR)/init.$(LIB_EXTENSION)

.PHONY: all
all: $(OBJECT_DIR) $(INSTALL_STAGING_DIR) $(SHARED_LIB_FILE) $(X86_BINARY_IMAGES) $(LUA_SOURCE_FILES) $(LUA_AUTOGEN_FILES)


.PHONY: clean
clean:
	rm -rf $(DOXYGEN_OUTPUT_BASE) $(BUILD_DIR) $(DOCTEST_HEADER) core*


.PHONY: docs
docs: $(DOXYGEN_OUTPUT_BASE)

$(DOXYGEN_OUTPUT_BASE): $(C_SOURCE_FILES) $(C_HEADER_FILES) Doxyfile
	doxygen

$(DOCTEST_HEADER):
	curl -fG -o $@ https://raw.githubusercontent.com/onqtam/doctest/master/doctest/doctest.h


$(OBJECT_DIR)/cpp_tests: $(TESTS_C_FILES) $(TESTS_H_FILES) $(DOCTEST_HEADER)
	$(CXX) -std=c++11 $(W_FLAGS) $(INCLUDE_FLAGS) $(LIB_SEARCH_FLAGS) -L$(INSTALL_STAGING_DIR) \
	-DIS_LUAJIT=$(IS_LUAJIT) -o $@ $(TESTS_C_FILES) $(OBJECTS) $(LINK_LIBRARIES) -llua -ldl


.PHONY: test_c
test_c: $(SHARED_LIB_FILE) $(OBJECT_DIR)/cpp_tests
	LD_LIBRARY_PATH="$(UNICORN_LIB_PATH):$(LD_LIBRARY_PATH)"    \
	LUA_CPATH="$(LUA_CUSTOM_CPATH);$(BUILD_LUA_CPATH)"          \
	LUA_PATH="$(LUA_CUSTOM_LPATH);$(BUILD_LUA_PATH)"            \
	PATH="$(LUA_CUSTOM_EXEPATH):$(PATH)"                        \
	$(OBJECT_DIR)/cpp_tests


.PHONY: test_lua
test_lua: $(SHARED_LIB_FILE) $(TESTS_LUA_FILES)
	LUA_CPATH="$(LUA_CUSTOM_CPATH);$(BUILD_LUA_CPATH)"          \
	LUA_PATH="$(LUA_CUSTOM_LPATH);$(BUILD_LUA_PATH)"            \
	$(BUSTED_EXE) $(BUSTED_CLI_ARGS)


# TODO (dargueta): Somehow get OBJECT_DIR and INSTALL_STAGING_DIR out of the deps here.
.PHONY: test
test: $(OBJECT_DIR) $(INSTALL_STAGING_DIR) $(SHARED_LIB_FILE) test_lua test_c


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
$(OBJECT_DIR)/compat.o: $(SRC_ROOT)/context.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/errors.o: $(SRC_ROOT)/errors.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/engine.o: $(SRC_ROOT)/engine.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/hooks.o: $(SRC_ROOT)/hooks.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/memory.o: $(SRC_ROOT)/memory.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/registers.o: $(SRC_ROOT)/registers.cpp $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)
$(OBJECT_DIR)/unicorn.o: $(C_SOURCES) | $(OBJECT_DIR)
$(OBJECT_DIR)/utils.o: $(SRC_ROOT)/utils.cpp $(GLOBAL_HEADERS) | $(OBJECT_DIR)

$(SHARED_LIB_FILE): $(OBJECTS) | $(INSTALL_STAGING_DIR) $(LUA_AUTOGEN_FILES) $(LUA_SOURCE_FILES)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LINK_LIBRARIES)
