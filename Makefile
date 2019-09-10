include Makefile.in

vpath %.h $(INCLUDE_BASE) $(UNICORN_INCLUDE_PATH)
vpath %.o $(OBJECT_DIR)
vpath %.c $(SRC_ROOT)

INCLUDE_UC_BASE=$(INCLUDE_BASE)/unicornlua
EXAMPLES_ROOT=$(REPO_ROOT)/docs/examples

GLOBAL_HEADERS=$(wildcard $(INCLUDE_UC_BASE)/*.h)
OBJECTS=$(C_SOURCE_FILES:src/%.c=build/obj/%.o)
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.s=%.mips32.bin)

TESTS_BASE=$(REPO_ROOT)/tests
TESTS_C_FILES=$(wildcard $(TESTS_BASE)/c/*.c)
TESTS_LUA_FILES=$(wildcard $(TESTS_BASE)/lua/*.lua)

CFLAGS += -c -Wall -Werror -Wextra -std=c99 -fpic -I$(INCLUDE_BASE) -I$(LUA_INCLUDE_PATH) -I$(UNICORN_INCLUDE_PATH)
LDFLAGS += -L$(LUA_LIB_PATH) -L$(UNICORN_LIB_PATH)

DOXYGEN_OUTPUT_BASE=$(REPO_ROOT)/docs/api

ifeq ($(PLATFORM), macosx)
	LDFLAGS += -dylib
else
	LDFLAGS += -shared
endif

LDFLAGS += -lunicorn -lpthread

ARCH_FILE=$(BUILD_DIR)/unicornlua.a
SHARED_LIB_FILE=$(INSTALL_STAGING_DIR)/_clib.$(LIB_EXTENSION)

.PHONY: all
all: $(OBJECT_DIR) $(INSTALL_STAGING_DIR) $(SHARED_LIB_FILE) $(X86_BINARY_IMAGES) $(LUA_SOURCE_FILES) $(LUA_AUTOGEN_FILES)


.PHONY: clean
clean:
	rm -rf $(OBJECTS) $(DOXYGEN_OUTPUT_BASE) $(BUILD_DIR)


.PHONY: docs
docs: $(DOXYGEN_OUTPUT_BASE)

$(DOXYGEN_OUTPUT_BASE): $(C_SOURCE_FILES) $(C_HEADER_FILES) Doxyfile
	doxygen

.PHONY: test_c
test_c: $(SHARED_LIB_FILE)


.PHONY: test_lua
test_lua: $(SHARED_LIB_FILE) $(TESTS_LUA_FILES)
	PATH="$(PATH):$(OBJECT_DIR)" LD_LIBRARY_PATH="$(UNICORN_LIB_PATH):$(LD_LIBRARY_PATH)" $(BUSTED_EXE) $(BUSTED_CLI_ARGS)


.PHONY: test
test: test_c test_lua


.PHONY: examples
examples: $(X86_BINARY_IMAGES) $(SHARED_LIB_FILE)


.PHONY: run_example
run_example: examples
	cd $(EXAMPLES_ROOT)/$(EXAMPLE) && \
	LUA_CPATH="$(BUILD_DIR)/?.$(LIB_EXTENSION);$(LUA_CUSTOM_CPATH)" $(LUA_EXE) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


build/obj/%.o : src/%.c
	$(CC) $(CFLAGS) -o $@ $<


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

$(OBJECT_DIR)/arm.o: $(SRC_ROOT)/arm.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/arm64.o: $(SRC_ROOT)/arm64.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/globals.o: $(SRC_ROOT)/globals.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/m68k.o: $(SRC_ROOT)/m68k.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/mips.o: $(SRC_ROOT)/mips.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/sparc.o: $(SRC_ROOT)/sparc.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/x86.o: $(SRC_ROOT)/x86.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/compat.o: $(SRC_ROOT)/compat.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/engine.o: $(SRC_ROOT)/engine.c $(SRC_ROOT)/utils.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/hooks.o: $(SRC_ROOT)/hooks.c $(SRC_ROOT)/utils.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/memory.o: $(SRC_ROOT)/memory.c $(SRC_ROOT)/utils.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/registers.o: $(SRC_ROOT)/registers.c $(SRC_ROOT)/utils.c $(GLOBAL_HEADERS)
$(OBJECT_DIR)/unicorn.o: $(C_SOURCES)
$(OBJECT_DIR)/utils.o: $(SRC_ROOT)/utils.c $(GLOBAL_HEADERS)

$(SHARED_LIB_FILE): $(OBJECTS) | $(INSTALL_STAGING_DIR)
	$(LD) $(LDFLAGS) -o $@ $^
