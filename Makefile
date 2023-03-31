# WARNING: This makefile is intended to be invoked by LuaRocks, not manually.

# DEFAULTS -------------------------------------------------------------------->
# Not all commands pass all the variables we need. These provide defaults in the
# event that we need one of them.

LUA_INCDIR ?= $(shell $(LUAROCKS) config variables.LUA_INCDIR)
LUA_LIBDIR ?= $(shell $(LUAROCKS) config variables.LUA_LIBDIR)
LUA_LIBDIR_FILE ?= $(or $(shell $(LUAROCKS) config variables.LUALIB),$(shell $(LUAROCKS) config variables.LUA_LIBDIR_FILE))
UNICORN_INCDIR ?=
PTHREAD_LIBDIR ?=

ifeq ($(UNICORN_LIBDIR),)
	UNICORN_LIBDIR := $(if $(shell stat /usr/lib64),/usr/lib64,)
endif

# <-----------------------------------------------------------------------------

BUILD_DIR := $(CURDIR)/build

ARCHITECTURE_HEADERS = $(wildcard $(UNICORN_INCDIR)/unicorn/*.h)
ARCHITECTURE_SLUGS = $(filter-out platform,$(basename $(notdir $(ARCHITECTURE_HEADERS))))

CONSTS_DIR = src/constants
CONSTANT_FILES = $(foreach s,$(ARCHITECTURE_SLUGS),$(CONSTS_DIR)/$(s)_const.cpp)

LIB_CPP_SOURCES = $(wildcard src/*.cpp) $(CONSTANT_FILES)
LIB_OBJECT_FILES = $(LIB_CPP_SOURCES:.cpp=.$(OBJ_EXTENSION)) \
                   $(CONSTANT_FILES:.cpp=.$(OBJ_EXTENSION))

TEST_CPP_SOURCES = $(wildcard tests/c/*.cpp)
TEST_LUA_SOURCES = $(wildcard tests/lua/*.lua)
TEST_HEADERS = $(wildcard tests/c/*.h)
TEST_CPP_OBJECT_FILES = $(TEST_CPP_SOURCES:.cpp=.$(OBJ_EXTENSION))
TEST_EXECUTABLE := $(BUILD_DIR)/cpp_test

LIB_BUILD_TARGET := $(BUILD_DIR)/unicorn.$(LIB_EXTENSION)

LIBRARY_DIRECTORIES := $(UNICORN_LIBDIR) $(PTHREAD_LIBDIR) $(LUA_LIBDIR)
HEADER_DIRECTORIES := $(UNICORN_INCDIR) $(LUA_INCDIR) $(CURDIR)/include

USER_CXX_FLAGS ?=
OTHER_CXXFLAGS := -std=c++11
WARN_FLAGS := -Wall -Wextra -Werror -Wpedantic -pedantic-errors
INCLUDE_PATH_FLAGS := $(addprefix -I,$(HEADER_DIRECTORIES))
LIB_PATH_FLAGS := $(addprefix -L,$(LIBRARY_DIRECTORIES))

CXX_CMD = $(CXX) $(OTHER_CXXFLAGS) $(WARN_FLAGS) $(INCLUDE_PATH_FLAGS)
LINK_CMD = $(CXX) $(LIB_PATH_FLAGS) $(LDFLAGS)

SET_SEARCH_PATHS = eval "$$($(LUAROCKS) path)" ; \
		export LD_LIBRARY_PATH="$(addsuffix :,$(LIBRARY_DIRECTORIES))$$LD_LIBRARY_PATH"


.PHONY: build
build: $(LIB_BUILD_TARGET)


.PHONY: install
install: $(LIB_BUILD_TARGET)
	install $^ $(INST_LIBDIR)


.PHONY: clean
clean:
	$(RM) $(LIB_OBJECT_FILES) $(CONSTANT_FILES) $(LIB_BUILD_TARGET)
	$(RM) $(TEST_EXECUTABLE) $(TEST_CPP_OBJECT_FILES)
	$(RM) -r $(BUILD_DIR) $(CONSTS_DIR)


.PHONY: test
test: $(TEST_EXECUTABLE) $(TEST_LUA_SOURCES)
	$(SET_SEARCH_PATHS); $(TEST_EXECUTABLE)
	$(SET_SEARCH_PATHS); $(BUSTED) --cpath="$(BUILD_DIR)/?.$(LIB_EXTENSION)" -p lua tests/lua


$(LIB_BUILD_TARGET): $(LIB_OBJECT_FILES) | $(BUILD_DIR)
	$(LINK_CMD) $(LIBFLAG) -o $@ $^ -lunicorn -lpthread


$(TEST_EXECUTABLE): $(TEST_CPP_OBJECT_FILES) $(LIB_OBJECT_FILES) | $(TEST_HEADERS)
	$(LINK_CMD) -o $@ $^ -lunicorn -lpthread -lm -l:$(LUA_LIBDIR_FILE)


$(CONSTS_DIR)/%_const.cpp: $(UNICORN_INCDIR)/unicorn/%.h | $(CONSTS_DIR)
	python3 tools/generate_constants.py $< $@


# We're deliberately omitting CXXFLAGS as provided by LuaRocks because it includes
# "-fPIC" and we don't want that for the test binary.
tests/c/%.$(OBJ_EXTENSION): tests/c/%.cpp
	$(CXX_CMD) -c -o $@ $^


src/%.$(OBJ_EXTENSION): src/%.cpp
	$(CXX_CMD) $(CXXFLAGS) -c -o $@ $^


$(CONSTS_DIR):
	$(MKDIR) $@


# Provided for completeness; we should never need this as LuaRocks creates it
# for us.
$(BUILD_DIR):
	$(MKDIR) $@
