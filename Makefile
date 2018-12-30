include Makefile.in

INCLUDE_BASE=include
INCLUDE_UC_BASE=$(INCLUDE_BASE)/unicornlua
SRC_BASE=src
CONST_SRC_BASE=$(SRC_BASE)/constants
CONST_HDR_BASE=$(INCLUDE_UC_BASE)/constants
OBJECT_BASE=bin

GLOBAL_HEADERS=$(wildcard $(INCLUDE_UC_BASE)/*.h)
OBJECTS=$(C_SOURCE_FILES:%.c=%.o)
X86_BINARY_IMAGES=$(X86_ASM_SOURCE_FILES:%.asm=%.x86.bin)

TESTS_BASE=tests
TESTS_C_FILES=$(wildcard $(TESTS_BASE)/c/*.c)
TESTS_LUA_FILES=$(wildcard $(TESTS_BASE)/lua/*.lua)

CFLAGS += -c -Wall -Werror -std=c99 -fpic -I$(INCLUDE_BASE) -I$(LUA_INCLUDE_PATH) -I$(UNICORN_INCLUDE_PATH)
LDFLAGS += -L$(LUA_LIB_PATH) -L$(UNICORN_LIB_PATH)

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
	rm -rf $(OBJECT_BASE) $(X86_BINARY_IMAGES) $(OBJECTS)

.PHONY: sterile
sterile: clean
	rm -rf .downloaded
	rm -f Makefile.in

.PHONY: test_c
test_c: $(SHARED_LIB_FILE)


.PHONY: test_lua
test_lua: $(SHARED_LIB_FILE) $(TESTS_LUA_FILES)
	PATH="$(PATH):$(OBJECT_BASE)" LD_LIBRARY_PATH="$(UNICORN_LIB_PATH):$(LD_LIBRARY_PATH)" $(BUSTED_EXE) $(BUSTED_CLI_ARGS)


.PHONY: test
test: test_c test_lua


.PHONY: examples
examples: $(X86_BINARY_IMAGES)


%.o : %.c
	$(CC) $(CFLAGS) -o $@ $<


%.h: ;


%.x86.bin : %.asm
	$(X86_ASM) $(X86_ASM_FLAGS) -o $@ $<


$(OBJECT_BASE) :
	mkdir -p $(OBJECT_BASE)


$(SRC_BASE)/constants/arm.o: $(CONST_SRC_BASE)/arm.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/arm.h
$(SRC_BASE)/constants/arm64.o: $(CONST_SRC_BASE)/arm64.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/arm64.h
$(SRC_BASE)/constants/globals.o: $(CONST_SRC_BASE)/globals.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/globals.h
$(SRC_BASE)/constants/m68k.o: $(CONST_SRC_BASE)/m68k.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/m68k.h
$(SRC_BASE)/constants/mips.o: $(CONST_SRC_BASE)/mips.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/mips.h
$(SRC_BASE)/constants/sparc.o: $(CONST_SRC_BASE)/sparc.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/sparc.h
$(SRC_BASE)/constants/x86.o: $(CONST_SRC_BASE)/x86.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/x86.h
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
