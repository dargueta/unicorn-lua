INCLUDE_BASE=include
INCLUDE_UC_BASE=$(INCLUDE_BASE)/unicornlua
SRC_BASE=src
CONST_SRC_BASE=$(SRC_BASE)/constants
CONST_HDR_BASE=$(INCLUDE_UC_BASE)/constants
OBJECT_BASE=bin

_CONSTANTS_HEADERS=$(wildcard $(CONST_HDR_BASE)/*.h)
_CONSTANTS_SOURCES=$(wildcard $(CONST_SRC_BASE)/*.c)

GLOBAL_HEADERS=$(wildcard $(INCLUDE_UC_BASE)/*.h)
GLOBAL_SOURCES=$(wildcard $(SRC_BASE)/*.c)
SOURCES=$(GLOBAL_SOURCES) $(_CONSTANTS_SOURCES)
HEADERS=$(GLOBAL_HEADERS) $(_CONSTANTS_HEADERS)
OBJECTS=$(SOURCES:%.c=%.o)

TESTS_BASE=tests
TESTS_C_FILES=$(wildcard $(TESTS_BASE)/c/*.c)
TESTS_LUA_FILES=$(wildcard $(TESTS_BASE)/lua/*.lua)

ARCH_FILE=$(OBJECT_BASE)/unicornlua.a
SHARED_LIB_FILE=$(OBJECT_BASE)/unicorn.$(LDEXT)

# FIXME: Lua search path is a temporary hack for search path issues
CFLAGS=-Wall -Werror -pedantic -pedantic-errors -fpic -I$(INCLUDE_BASE) -I/usr/include/lua5.3 -Ilibunicorn/include

OS=$(shell uname)

ifeq ($(OS), Darwin)
	LDEXT=dylib
	LDFLAGS=-dylib
else ifeq ($(OS), Windows_NT)
	# TODO
	LDEXT=dll
	LDFLAGS=-shared
else
	LDEXT=so
	LDFLAGS=-shared
endif


.PHONY: all
all: $(OBJECTS) $(ARCH_FILE) $(SHARED_LIB_FILE)


.PHONY: clean
clean:
	rm -rf bin
	mkdir bin
	find . -name '*.o' -delete
	find . -name '*.a' -delete
	find . -name '*.so' -delete
	find . -name '*.dylib' -delete


.PHONY: tests_c
tests_c: $(SHARED_LIB_FILE)

export LUA_CPATH=$(OBJECT_BASE)/?.dylib


.PHONY: tests_lua
tests_lua: $(SHARED_LIB_FILE) $(TESTS_LUA_FILES)


.PHONY: test
tests: tests_c tests_lua


%.o : %.c
	$(CC) -c $(CFLAGS) -o $@ $<


%.h: ;


%.lua:
	lua $@


$(SRC_BASE)/constants/arm.o: $(CONST_SRC_BASE)/arm.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/arm.h
$(SRC_BASE)/constants/arm64.o: $(CONST_SRC_BASE)/arm64.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/arm64.h
$(SRC_BASE)/constants/globals.o: $(CONST_SRC_BASE)/globals.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/globals.h
$(SRC_BASE)/constants/m68k.o: $(CONST_SRC_BASE)/m68k.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/m68k.h
$(SRC_BASE)/constants/mips.o: $(CONST_SRC_BASE)/mips.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/mips.h
$(SRC_BASE)/constants/sparc.o: $(CONST_SRC_BASE)/sparc.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/sparc.h
$(SRC_BASE)/constants/x86.o: $(CONST_SRC_BASE)/x86.c $(GLOBAL_HEADERS) $(CONST_HDR_BASE)/x86.h
$(SRC_BASE)/memory.o: $(SRC_BASE)/memory.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/numbers.o: $(SRC_BASE)/numbers.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/registers.o: $(SRC_BASE)/registers.c $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)
$(SRC_BASE)/unicornlua.o: $(GLOBAL_SOURCES)
$(SRC_BASE)/utils.o: $(SRC_BASE)/utils.c $(GLOBAL_HEADERS)

$(OBJECT_BASE)/unicornlua.a: $(OBJECTS)
	$(AR) -rc $@ $^

$(OBJECT_BASE)/unicorn.$(LDEXT): $(OBJECTS)
	$(LD) $(LDFLAGS) -llua5.3 -lc -lunicorn -o $@ $^
