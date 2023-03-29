# The following variables must be defined beforehand:
#
#	- UNICORN_INCDIR
# 	- LIB_EXTENSION

BUILD_DIR := $(CURDIR)/build
LUAROCKS ?= luarocks

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
