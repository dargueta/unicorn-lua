# WARNING: This makefile is intended to be invoked by LuaRocks, not manually. Only use
# it form `clean`, `format` and if your IDE is grumpy, `autogen-files` might work.

# If we don't disable suffixes, Make fails to detect our default %.o rule because it has
# extra prerequisites. Because of this, it falls back to its internal built-in recipe for
# %.o from %.cpp. This default rule doesn't have any of the header search paths, and will
# fail.
.SUFFIXES:

.DELETE_ON_ERROR:

################################################################################
# DEFAULTS
# These are only used when this Makefile is run manually. You should only be
# doing that for `make clean`. Use `luarocks` for everything else.

CP = cp
CURL = curl
LIB_EXTENSION = so
LUAROCKS = luarocks
MKDIR = mkdir
OBJ_EXTENSION = o
UNICORN_INCDIR = /usr/include

BUSTED := $(shell $(LUAROCKS) config variables.SCRIPTS_DIR)/busted
LIBFLAG := $(shell $(LUAROCKS) config variables.LIBFLAG)
LUA := $(shell $(LUAROCKS) config variables.LUA)
LUA_DIR := $(shell $(LUAROCKS) config variables.LUA_DIR)
LUA_INCDIR = $(LUA_DIR)/include
LUA_LIBDIR = $(LUA_DIR)/lib
LUA_VERSION = $(shell $(LUA) -e 'print(_VERSION:sub(5))')

################################################################################

# Disable 64-bit integer tests for Lua <5.3
ifeq ($(LUA_VERSION),5.1)
    BUSTED_FLAGS = --exclude-tags="int64only"
else ifeq ($(LUA_VERSION),5.2)
    BUSTED_FLAGS = --exclude-tags="int64only"
else
    BUSTED_FLAGS =
endif


IS_LUAJIT = $(shell $(LUA) -e 'if _G.jit ~= nil then print(1) else print(0) end')
ifeq ($(IS_LUAJIT),1)
    # LuaJIT
    DEFAULT_LUA_LIB_NAME = luajit-$(LUA_VERSION)
    LUAJIT_VERSION = $(shell \
        $(LUA) -e 'print(string.format("%d.%d", jit.version_num / 10000, (jit.version_num / 100) % 100))' \
    )
    FALLBACK_LUA_INCDIR = $(LUA_DIR)/include/luajit-$(LUAJIT_VERSION)
else
    # Regular Lua
    DEFAULT_LUA_LIB_NAME = lua
    FALLBACK_LUA_INCDIR = $(LUA_DIR)/include
endif


ARCHITECTURES = arm64 arm m68k mips ppc riscv s390x sparc tricore x86

SOURCE_DIR = csrc
LUA_SOURCE_DIR = src/unicorn
CONSTANT_FILES = $(foreach s,registers unicorn $(ARCHITECTURES),$(LUA_SOURCE_DIR)/$(s)_const.lua)
LDOC_FILES = $(foreach s,unicorn $(ARCHITECTURES),$(LUA_SOURCE_DIR)/$(s)_const.luadoc)
AUTOGENERATED_LUA_FILES = $(CONSTANT_FILES)

CPP_TEMPLATE_SOURCES = $(wildcard $(SOURCE_DIR)/*.template)
AUTOGENERATED_CPP_FILES = $(CPP_TEMPLATE_SOURCES:.template=.cpp)

HEADER_TEMPLATE_SOURCES = $(wildcard $(SOURCE_DIR)/unicornlua/*.template)
AUTOGENERATED_HPP_FILES = $(HEADER_TEMPLATE_SOURCES:.template=.hpp)

LIB_BUILD_TARGET = $(SOURCE_DIR)/unicorn_c_.$(LIB_EXTENSION)
LIB_CPP_SOURCES = $(wildcard $(SOURCE_DIR)/*.cpp) $(AUTOGENERATED_CPP_FILES)
LIB_OBJECT_FILES = $(LIB_CPP_SOURCES:.cpp=.$(OBJ_EXTENSION))

TEST_EXECUTABLE = $(SOURCE_DIR)/cpp_test
TEST_CPP_SOURCES = $(wildcard tests/c/*.cpp)
TEST_LUA_SOURCES = $(wildcard tests/lua/*.lua)
TEST_HEADERS = $(wildcard tests/c/*.hpp)
TEST_CPP_OBJECT_FILES = $(TEST_CPP_SOURCES:.cpp=.$(OBJ_EXTENSION))

TEMPLATE_DATA_FILES = $(addprefix $(SOURCE_DIR)/template_data/,basic_control_functions.lua register_types.lua)

# Unicorn 1.x gets put into places not on the typical linker search path, so we need to
# hardcode these additional directories it could appear in.
LIBRARY_DIRECTORIES = $(strip $(LUA_LIBDIR) $(UNICORN_LIBDIR) $(PTHREAD_LIBDIR) /usr/lib64 /usr/local/lib)

# The hardcoded version-specific paths here are fallbacks because my IDE can't find the
# Lua headers without them. Is it necessary? No. Will it cause problems? Unlikely. But
# without it, every file is a sea of red squiggles and I'm. Losing. My. Mind.
HEADER_DIRECTORIES = $(strip \
	$(SOURCE_DIR) \
    $(LUA_INCDIR) \
    $(FALLBACK_LUA_INCDIR) \
    $(UNICORN_INCDIR) \
    /usr/local/include \
    /usr/include/lua$(LUA_VERSION) \
    /usr/local/include/lua$(LUA_VERSION))

INCLUDE_PATH_FLAGS = $(addprefix -I,$(HEADER_DIRECTORIES))
LIB_PATH_FLAGS = $(addprefix -L,$(LIBRARY_DIRECTORIES))
REQUIRED_LIBS = unicorn pthread stdc++
REQUIRED_LIBS_FLAGS = $(addprefix -l,$(REQUIRED_LIBS))

# LUALIB isn't always provided. This breaks building our tests on LuaJIT, which
# uses a filename other than liblua.a for its library. Thus, -llua won't work on
# LuaJIT (any platform) or Windows (any Lua version).
LINK_TO_LUA_FLAG = $(if $(LUALIB),-l:$(LUALIB),-l$(DEFAULT_LUA_LIB_NAME))

# https://github.com/PowerDNS/pdns/issues/4295
ifeq ($(shell uname -s),Darwin)
    ifeq ($(IS_LUAJIT),1)
        # This workaround isn't needed for LuaJIT 2.1+
        ifeq ($(LUAJIT_VERSION),2.0)
            LINK_TO_LUA_FLAG += -pagezero_size 10000 -image_base 100000000
        endif
    endif
endif


# On MacOS, we need to explicitly tell the compiler to use C++11 because it defaults to an
# older standard. GCC on Linux appears to work fine without it.
CXX_CMD = $(CXX) $(USER_CXX_FLAGS) $(INCLUDE_PATH_FLAGS) -std=c++11
LINK_CMD = $(LD) $(LIB_PATH_FLAGS) $(LDFLAGS)

DOCTEST_TAG = v2.4.11
DOCTEST_HEADER = tests/c/doctest.h

# Uncomment for debugging autogenerated files
# .PRECIOUS: $(AUTOGENERATED_CPP_FILES) $(AUTOGENERATED_HPP_FILES) $(CONSTANT_FILES) \
#            $(LUA_SOURCE_DIR)/%_extracted_consts.lua %_const_gen.c


# LIBRARY_DIRECTORIES is a list of the additional paths to search for libraries in at
# runtime. In Make, paths are separated by spaces. In environment variables, the paths are
# separated by colons. This means we need to replace spaces with colons.
#
# Throwaway variables to let us use spaces as an argument:
# https://www.gnu.org/software/make/manual/make.html#Syntax-of-Functions
_empty =
_space = $(_empty) $(_empty)

LIBRARY_COLON_PATHS = $(subst $(_space),:,$(LIBRARY_DIRECTORIES))

export LUA_PATH := $(shell $(LUAROCKS) path --lr-path)
export LUA_CPATH := $(shell $(LUAROCKS) path --lr-cpath)
export PATH := $(shell $(LUAROCKS) path --lr-bin):$(PATH)
# DYLD_FALLBACK_LIBRARY_PATH is for MacOS, LD_LIBRARY_PATH is for all other *NIX systems.
export LD_LIBRARY_PATH := $(LIBRARY_COLON_PATHS):$(LD_LIBRARY_PATH)
export DYLD_FALLBACK_LIBRARY_PATH := $(LIBRARY_COLON_PATHS):$(DYLD_FALLBACK_LIBRARY_PATH)


# This must be the first rule, don't move it.
$(LIB_BUILD_TARGET): $(LIB_OBJECT_FILES) $(CONSTANT_FILES)
	$(LINK_CMD) $(LIBFLAG) -o $@ $(filter-out %.lua,$^) $(REQUIRED_LIBS_FLAGS)


$(TEST_EXECUTABLE): $(TEST_CPP_OBJECT_FILES) $(LIB_OBJECT_FILES)
	$(LINK_CMD) -o $@ $^ $(REQUIRED_LIBS_FLAGS) $(LINK_TO_LUA_FLAG) -lm


tests/c/%.$(OBJ_EXTENSION): tests/c/%.cpp $(AUTOGENERATED_HPP_FILES) $(TEST_HEADERS) | $(DOCTEST_HEADER)
	$(CXX_CMD) $(CXXFLAGS) -c -o $@ $<


%.$(OBJ_EXTENSION): %.cpp $(AUTOGENERATED_HPP_FILES)
	$(CXX_CMD) $(CXXFLAGS) -c -o $@ $<


%.cpp: %.template $(TEMPLATE_DATA_FILES)
	$(LUA) tools/render_template.lua -o $@ $^


%.hpp: %.template $(TEMPLATE_DATA_FILES)
	$(LUA) tools/render_template.lua -o $@ $^


$(LUA_SOURCE_DIR)/%_extracted_consts.txt:
	$(LUA) tools/process_header.lua --missing-ok $(UNICORN_INCDIR)/unicorn/$*.h $@


%registers_const_gen.c: templates/registers_const_generator.template \
                        $(SOURCE_DIR)/template_data/register_types.lua \
                        $(SOURCE_DIR)/template_data/predefined_docstrings.lua \
                        $(SOURCE_DIR)/unicornlua/register_types.hpp
	$(LUA) tools/render_template.lua -o $@ $(filter-out %.hpp,$^)


%_const_gen.c: templates/arch_const_generator.template  %_extracted_consts.txt
	$(LUA) tools/render_template.lua -o $@ $^


%_const_gen: %_const_gen.c
	$(CC) $(INCLUDE_PATH_FLAGS) -o $@ $<


%_const.lua: %_const_gen
	$< > $@


%_const.luadoc: templates/arch_const_ldoc.template \
                %_extracted_consts.txt \
                $(SOURCE_DIR)/template_data/predefined_docstrings.lua
	$(LUA) tools/render_template.lua -e '#' -o $@ $^


$(DOCTEST_HEADER):
	$(CURL) -sSo $@ https://raw.githubusercontent.com/doctest/doctest/$(DOCTEST_TAG)/doctest/doctest.h


.PHONY: __install
__install: $(LIB_BUILD_TARGET) $(AUTOGENERATED_LUA_FILES)
	$(CP) $(LIB_BUILD_TARGET) $(INST_LIBDIR)
	$(CP) -r $(LUA_SOURCE_DIR) $(INST_LUADIR)


.PHONY: all
all: $(LIB_BUILD_TARGET) $(AUTOGENERATED_LUA_FILES) $(TEST_EXECUTABLE)


.PHONY: clean
clean:
	$(RM) $(LIB_OBJECT_FILES) $(LIB_BUILD_TARGET) \
	    $(TEST_EXECUTABLE) $(TEST_CPP_OBJECT_FILES) $(DOCTEST_HEADER) \
	    $(AUTOGENERATED_CPP_FILES) $(AUTOGENERATED_HPP_FILES) $(AUTOGENERATED_LUA_FILES) \
	    $(LDOC_FILES)


.PHONY: format
format:
	@clang-format --Werror -i --verbose \
	    $(filter-out $(AUTOGENERATED_CPP_FILES),$(wildcard $(SOURCE_DIR)/*.cpp)) \
	    $(filter-out $(AUTOGENERATED_HPP_FILES),$(wildcard $(SOURCE_DIR)/unicornlua/*.hpp)) \
	    $(wildcard tests/c/*.cpp) \
	    $(wildcard tests/c/*.hpp)


.PHONY: docs
docs: $(LDOC_FILES) $(LUA_SOURCE_DIR)/registers_const.lua
	ldoc .


# Convenience target for generating all templated files. This is mostly for
# making IDEs and linters shut up about "missing" files.
.PHONY: autogen-files
autogen-files: $(AUTOGENERATED_CPP_FILES) $(AUTOGENERATED_HPP_FILES) $(CONSTANT_FILES)


.PHONY: __test
__test: $(TEST_EXECUTABLE) $(TEST_LUA_SOURCES) | $(BUSTED)
	$(TEST_EXECUTABLE)
	$(BUSTED) $(BUSTED_FLAGS) --lua=$(LUA) --shuffle --pattern lua tests/lua
