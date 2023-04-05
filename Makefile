# WARNING: This makefile is intended to be invoked by LuaRocks, not manually.

# Disable 64-bit integer tests for Lua <5.3
LUA_VERSION = $(shell $(LUA) -e 'print(_VERSION:sub(5))')
ifeq ($(LUA_VERSION),5.1)
    BUSTED_FLAGS := --exclude-tags="int64only"
else ifeq ($(LUA_VERSION),5.2)
    BUSTED_FLAGS := --exclude-tags="int64only"
else
    BUSTED_FLAGS :=
endif


IS_LUAJIT = $(shell $(LUA) -e 'if _G.jit ~= nil then print(1) else print(0) end')
ifeq ($(IS_LUAJIT),1)
    DEFAULT_LUA_LIB_NAME := luajit-5.1
    # FIXME (dargueta): This will break on LuaJIT 2.1
    FALLBACK_LUA_INCDIR := $(LUA_DIR)/include/luajit-2.0
else
    DEFAULT_LUA_LIB_NAME := lua
    FALLBACK_LUA_INCDIR := $(LUA_DIR)/include
endif

FALLBACK_LUA_LIBDIR := $(LUA_DIR)/lib

BUILD_DIR := $(CURDIR)/build

ARCHITECTURE_HEADERS = $(wildcard $(UNICORN_INCDIR)/unicorn/*.h)
ARCHITECTURE_SLUGS = $(filter-out platform,$(basename $(notdir $(ARCHITECTURE_HEADERS))))

CONSTS_DIR = src/constants
CONSTANT_FILES = $(foreach s,$(ARCHITECTURE_SLUGS),$(CONSTS_DIR)/$(s)_const.cpp)

LIB_BUILD_TARGET := $(BUILD_DIR)/unicorn.$(LIB_EXTENSION)
LIB_CPP_SOURCES = $(wildcard src/*.cpp) $(CONSTANT_FILES)
LIB_OBJECT_FILES = $(LIB_CPP_SOURCES:.cpp=.$(OBJ_EXTENSION)) \
                   $(CONSTANT_FILES:.cpp=.$(OBJ_EXTENSION))

TEST_EXECUTABLE := $(BUILD_DIR)/cpp_test
TEST_CPP_SOURCES = $(wildcard tests/c/*.cpp)
TEST_LUA_SOURCES = $(wildcard tests/lua/*.lua)
TEST_HEADERS = $(wildcard tests/c/*.h)
TEST_CPP_OBJECT_FILES = $(TEST_CPP_SOURCES:.cpp=.$(OBJ_EXTENSION))

LIBRARY_DIRECTORIES := $(strip $(LUA_LIBDIR) $(FALLBACK_LUA_LIBDIR) $(UNICORN_LIBDIR) $(PTHREAD_LIBDIR) /usr/lib64 /usr/local/lib)
HEADER_DIRECTORIES := $(strip $(CURDIR)/include $(LUA_INCDIR) $(FALLBACK_LUA_INCDIR) $(UNICORN_INCDIR))

USER_CXX_FLAGS ?=
OTHER_CXXFLAGS := -std=c++11
WARN_FLAGS := -Wall -Wextra -Werror -Wpedantic -pedantic-errors
INCLUDE_PATH_FLAGS := $(addprefix -I,$(HEADER_DIRECTORIES))
LIB_PATH_FLAGS := $(addprefix -L,$(LIBRARY_DIRECTORIES))
REQUIRED_LIBS := unicorn pthread stdc++
REQUIRED_LIBS_FLAGS := $(addprefix -l,$(REQUIRED_LIBS))

# LUALIB isn't always provided. This breaks building our tests on LuaJIT, which
# uses a filename other than liblua.a for its library. Thus, -llua won't work on
# LuaJIT (any platform) or Windows (any Lua version).
LINK_TO_LUA_FLAG := $(if $(LUALIB),-l:$(LUALIB),-l$(DEFAULT_LUA_LIB_NAME))

CXX_CMD = $(CC) $(OTHER_CXXFLAGS) $(USER_CXX_FLAGS) $(WARN_FLAGS) $(INCLUDE_PATH_FLAGS)
LINK_CMD = $(LD) $(LIB_PATH_FLAGS) $(LDFLAGS)

# DYLD_FALLBACK_LIBRARY_PATH is for MacOS, LD_LIBRARY_PATH is for all other *NIX
# systems.
SET_SEARCH_PATHS = eval "$$($(LUAROCKS) path)" ; \
		export LD_LIBRARY_PATH="$(addsuffix :,$(LIBRARY_DIRECTORIES))$$LD_LIBRARY_PATH" ; \
		export DYLD_FALLBACK_LIBRARY_PATH="$(addsuffix :,$(LIBRARY_DIRECTORIES))$$DYLD_FALLBACK_LIBRARY_PATH"

DOCTEST_TAG := v2.4.11
DOCTEST_HEADER := tests/c/doctest.h


.PHONY: all
all: $(LIB_BUILD_TARGET) $(TEST_EXECUTABLE)


.PHONY: install
install: $(LIB_BUILD_TARGET)
	install $^ $(INST_LIBDIR)


.PHONY: clean
clean:
	git clean -Xfd
	$(RM) $(LIB_OBJECT_FILES) $(CONSTANT_FILES) $(LIB_BUILD_TARGET)
	$(RM) $(TEST_EXECUTABLE) $(TEST_CPP_OBJECT_FILES) $(DOCTEST_HEADER)
	$(RM) -r $(BUILD_DIR) $(CONSTS_DIR)


.PHONY: test
test: $(TEST_EXECUTABLE) $(TEST_LUA_SOURCES)
	$(SET_SEARCH_PATHS); $(TEST_EXECUTABLE)
	$(SET_SEARCH_PATHS); \
		$(BUSTED) $(BUSTED_FLAGS)                           \
		          --cpath="$(BUILD_DIR)/?.$(LIB_EXTENSION)" \
		          --lua=$(LUA)                              \
		          --shuffle                                 \
		          -p lua                                    \
		          tests/lua


$(DOCTEST_HEADER):
	$(CURL) -sSo $@ https://raw.githubusercontent.com/doctest/doctest/$(DOCTEST_TAG)/doctest/doctest.h


$(LIB_BUILD_TARGET): $(LIB_OBJECT_FILES) | $(BUILD_DIR)
	$(LINK_CMD) $(LIBFLAG) -o $@ $^ $(REQUIRED_LIBS_FLAGS)


$(TEST_EXECUTABLE): $(DOCTEST_HEADER) $(TEST_CPP_OBJECT_FILES) $(LIB_OBJECT_FILES) $(TEST_HEADERS)
	$(LINK_CMD) -o $@ $(filter-out %.h,$^) $(REQUIRED_LIBS_FLAGS) $(LINK_TO_LUA_FLAG) -lm


$(CONSTS_DIR)/%_const.cpp: $(UNICORN_INCDIR)/unicorn/%.h | $(CONSTS_DIR)
	python3 tools/generate_constants.py $< $@


# We're deliberately omitting CXXFLAGS as provided by LuaRocks because it includes
# "-fPIC" and we don't want that for the test binary.
tests/c/%.$(OBJ_EXTENSION): tests/c/%.cpp
	$(CXX_CMD) -c -o $@ $^


src/%.$(OBJ_EXTENSION): src/%.cpp
	$(CXX_CMD) $(CXXFLAGS) -c -o $@ $^


$(CONSTS_DIR) $(BUILD_DIR):
	$(MKDIR) $@
