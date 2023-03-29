# WARNING: This makefile is intended to be invoked by LuaRocks, not manually.

BUILD_DIR := $(CURDIR)/build
OS = $(or $(shell uname -s),Windows_NT)
LUAROCKS ?= luarocks

OTHER_CXXFLAGS := -std=c++11
WARN_FLAGS := -Wall -Wextra -Werror -Wpedantic -pedantic-errors
INCLUDE_PATH_FLAGS := -Iinclude -I$(LUA_INCDIR) -I$(UNICORN_INCDIR)
LIB_PATH_FLAGS := -L$(LUA_LIBDIR) -L$(UNICORN_LIBDIR) -L$(PTHREAD_LIBDIR) -L$(BUILD_DIR)

CXX_CMD = $(CXX) $(OTHER_CXXFLAGS) $(WARN_FLAGS) $(INCLUDE_PATH_FLAGS)
LD_CMD = $(CXX) $(LIB_PATH_FLAGS) $(LDFLAGS)


ARCHITECTURE_HEADERS = $(wildcard $(UNICORN_INCDIR)/unicorn/*.h)
ARCHITECTURE_SLUGS = $(filter-out platform,$(basename $(notdir $(ARCHITECTURE_HEADERS))))

CONSTS_DIR = src/constants
CONSTANT_FILES = $(foreach s,$(ARCHITECTURE_SLUGS),$(CONSTS_DIR)/$(s)_const.cpp)

LIB_CPP_SOURCES = $(wildcard src/*.cpp) $(CONSTANT_FILES)
LIB_OBJECT_FILES = $(LIB_CPP_SOURCES:.cpp=.o) $(CONSTANT_FILES:.cpp=.o)

TEST_CPP_SOURCES = $(wildcard tests/c/*.cpp)
TEST_LUA_SOURCES = $(wildcard tests/lua/*.lua)
TEST_HEADERS = $(wildcard tests/c/*.h)
TEST_CPP_OBJECT_FILES = $(TEST_CPP_SOURCES:.cpp=.o)
TEST_EXECUTABLE := $(BUILD_DIR)/cpp_test

LIB_BUILD_TARGET := $(BUILD_DIR)/unicorn.$(LIB_EXTENSION)


.PHONY: build
build: $(LIB_BUILD_TARGET) $(TEST_EXECUTABLE)


.PHONY: install
install: $(LIB_BUILD_TARGET)
	install $^ $(INST_LIBDIR)


.PHONY: test
test: $(TEST_EXECUTABLE) $(TEST_LUA_SOURCES)
	$$(eval "$$($(LUAROCKS) path)") && $(TEST_EXECUTABLE)
	$$(eval "$$($(LUAROCKS) path)") && busted --cpath="$(BUILD_DIR)/?.$(LIB_EXTENSION)" tests/lua


.PHONY: clean
clean:
	$(RM) $(LIB_OBJECT_FILES) $(CONSTANT_FILES) $(LIB_BUILD_TARGET)
	$(RM) $(TEST_EXECUTABLE) $(TEST_CPP_OBJECT_FILES)
	$(RM) -r $(BUILD_DIR) $(CONSTS_DIR)


$(LIB_BUILD_TARGET): $(LIB_OBJECT_FILES) | $(BUILD_DIR)
	$(LD_CMD) $(LIBFLAG) -o $@ $^ -lunicorn -lpthread


$(TEST_EXECUTABLE): $(TEST_CPP_OBJECT_FILES) $(LIB_OBJECT_FILES) | $(TEST_HEADERS)
	$(LD_CMD) -o $@ $^ -lunicorn -lpthread -lm -llua


$(CONSTS_DIR)/%_const.cpp: $(UNICORN_INCDIR)/unicorn/%.h | $(CONSTS_DIR)
	python3 tools/generate_constants.py $< $@


# We're deliberately omitting CXXFLAGS as provided by LuaRocks because it includes
# "-fPIC" and we don't want that for the test binary.
tests/c/%.o: tests/c/%.cpp
	$(CXX_CMD) -c -o $@ $^


src/%.o: src/%.cpp
	$(CXX_CMD) $(CXXFLAGS) -c -o $@ $^


$(CONSTS_DIR):
	mkdir -p $@


# Provided for completeness; we should never need this as LuaRocks creates it
# for us.
$(BUILD_DIR):
	mkdir -p $@
