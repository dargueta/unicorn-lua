include Makefile.in

INCLUDE_BASE=$(REPO_ROOT)/include
INCLUDE_UC_BASE=$(INCLUDE_BASE)/unicornlua
SRC_BASE=$(REPO_ROOT)/src
OBJECT_BASE=$(REPO_ROOT)/bin
EXAMPLES_ROOT=$(REPO_ROOT)/docs/examples

GLOBAL_HEADERS=$(wildcard $(INCLUDE_UC_BASE)/*.h)
OBJECTS=$(C_SOURCE_FILES:%.c=%.o)
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)
MIPS_BINARY_IMAGES=$(MIPS_ASM_SOURCE_FILES:%.S=%.mips32.bin)

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

ARCH_FILE=$(OBJECT_BASE)/unicornlua.a
SHARED_LIB_FILE=$(OBJECT_BASE)/unicorn.$(LIB_EXTENSION)

.PHONY: all
all: $(OBJECT_BASE) $(OBJECTS) $(ARCH_FILE) $(SHARED_LIB_FILE) $(X86_BINARY_IMAGES)


.PHONY: clean
clean:
	rm -rf $(OBJECT_BASE) $(OBJECTS) $(DOXYGEN_OUTPUT_BASE)


.PHONY: docs
docs: $(DOXYGEN_OUTPUT_BASE)

$(DOXYGEN_OUTPUT_BASE): $(C_SOURCE_FILES) $(C_HEADER_FILES) Doxyfile
	doxygen

.PHONY: test_c
test_c: $(SHARED_LIB_FILE)


.PHONY: test_lua
test_lua: $(SHARED_LIB_FILE) $(TESTS_LUA_FILES)
	PATH="$(PATH):$(OBJECT_BASE)" LD_LIBRARY_PATH="$(UNICORN_LIB_PATH):$(LD_LIBRARY_PATH)" $(BUSTED_EXE) $(BUSTED_CLI_ARGS)


.PHONY: test
test: test_c test_lua


.PHONY: examples
examples: $(X86_BINARY_IMAGES) $(SHARED_LIB_FILE)


.PHONY: run_example
run_example: examples
	cd $(EXAMPLES_ROOT)/$(EXAMPLE) && \
	LUA_CPATH="$(OBJECT_BASE)/?.$(LIB_EXTENSION);$(LUA_CUSTOM_CPATH)" $(LUA_EXE) $(EXAMPLES_ROOT)/$(EXAMPLE)/run.lua


%.o : %.c
	$(CC) $(CFLAGS) -o $@ $<


%.h: ;


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


%.mips32.bin : %.s
	mips-linux-gnu-as -o $@.o -mips32 -EB $<
	mips-linux-gnu-ld -o $@ --oformat=binary -e main -sN $@.o


$(OBJECT_BASE) :
	mkdir -p $(OBJECT_BASE)


$(SRC_BASE)/arm.o: $(SRC_BASE)/arm.c $(GLOBAL_HEADERS)
$(SRC_BASE)/arm64.o: $(SRC_BASE)/arm64.c $(GLOBAL_HEADERS)
$(SRC_BASE)/globals.o: $(SRC_BASE)/globals.c $(GLOBAL_HEADERS)
$(SRC_BASE)/m68k.o: $(SRC_BASE)/m68k.c $(GLOBAL_HEADERS)
$(SRC_BASE)/mips.o: $(SRC_BASE)/mips.c $(GLOBAL_HEADERS)
$(SRC_BASE)/sparc.o: $(SRC_BASE)/sparc.c $(GLOBAL_HEADERS)
$(SRC_BASE)/x86.o: $(SRC_BASE)/x86.c $(GLOBAL_HEADERS)
$(SRC_BASE)/compat.o: $(SRC_BASE)/compat.c $(GLOBAL_HEADERS)
$(SRC_BASE)/engine.o: $(SRC_BASE)/engine.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/hooks.o: $(SRC_BASE)/hooks.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/memory.o: $(SRC_BASE)/memory.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/registers.o: $(SRC_BASE)/registers.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/unicorn.o: $(C_SOURCES)
$(SRC_BASE)/utils.o: $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)


$(ARCH_FILE): $(OBJECTS) | $(OBJECT_BASE)
	$(AR) -rc $@ $^


$(SHARED_LIB_FILE): $(OBJECTS) | $(OBJECT_BASE)
	$(LD) $(LDFLAGS) -o $@ $^
