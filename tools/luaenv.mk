ifndef LUA
    LUA = 5.4
endif

ifndef ROCKS
    ROCKS = 3.11.0
endif

# If only the major and minor version number was given, use the latest version
# of Lua for that series.
ifeq ($(LUA),5.4)
    LUA_VERSION = 5.4.7
else ifeq ($(LUA),5.3)
    LUA_VERSION = 5.3.6
else ifeq ($(LUA),5.2)
    LUA_VERSION = 5.2.4
else ifeq ($(LUA),5.1)
    LUA_VERSION = 5.1.5
else
    # No match, assume the user passed a full version number.
    LUA_VERSION = $(LUA)
endif

LUAROCKS_VERSION = $(ROCKS)

VENV_LUA = $(VENV_DIR)/bin/lua
VENV_LUAROCKS = $(VENV_DIR)/bin/luarocks
VENV_DIR = $(CURDIR)/.luaenv-$(LUA_VERSION)

LUA_ARCHIVE_DIRNAME = lua-$(LUA_VERSION)
LUA_ARCHIVE_FILENAME = $(LUA_ARCHIVE_DIRNAME).tar.gz
LUA_DOWNLOAD_URL = https://www.lua.org/ftp/$(LUA_ARCHIVE_FILENAME)
SRC_LUA_BIN = $(LUA_ARCHIVE_DIRNAME)/src/lua

VENV_LUAROCKS = $(VENV_DIR)/bin/luarocks
LUAROCKS_ARCHIVE_DIRNAME = luarocks-$(LUAROCKS_VERSION)
LUAROCKS_ARCHIVE_FILENAME = $(LUAROCKS_ARCHIVE_DIRNAME).tar.gz
LR_DOWNLOAD_URL = https://luarocks.github.io/luarocks/releases/$(LUAROCKS_ARCHIVE_FILENAME)

DOWNLOAD = cd '$(1)' && curl -sS '$(2)' | tar -xz --strip-components=1

unexport

UNAME = $(shell uname -s)
IS_WINDOWS = $(if $(findstring Windows_NT,$(OS)),1,0)
IS_CYGWIN = $(if $(findstring CYGWIN,$(UNAME)),1,0)


ifeq ($(UNAME),Linux)
    LUA_BUILD_TARGET = linux
else ifeq ($(UNAME),Darwin)
    LUA_BUILD_TARGET = macosx
else ifeq ($(IS_CYGWIN),1)
    LUA_BUILD_TARGET = mingw
else ifeq ($(IS_WINDOWS),1)
	$(error Windows is not supported yet.)
else
    LUA_BUILD_TARGET = posix
endif

.PHONY: all
all: lua luarocks

.PHONY: clean
clean:
	$(RM) -r $(VENV_DIR)

.PHONY: lua
lua: $(VENV_LUA)
	$(RM) -r $(LUA_ARCHIVE_DIRNAME)

.PHONY: luarocks
luarocks: $(VENV_LUAROCKS)
	$(RM) -r $(LUAROCKS_ARCHIVE_DIRNAME)

$(VENV_DIR):
	mkdir -p $@

################################################################################
# LUA

$(VENV_LUA): $(LUA_ARCHIVE_DIRNAME)/Makefile | $(VENV_DIR)
	$(MAKE) -C '$(<D)' $(LUA_BUILD_TARGET)
	$(MAKE) -C '$(<D)' 'test'
	$(MAKE) -C '$(<D)' install INSTALL_TOP=$(VENV_DIR)

$(LUA_ARCHIVE_DIRNAME)/Makefile:
	mkdir -p '$(@D)'
	$(call DOWNLOAD,$(@D),$(LUA_DOWNLOAD_URL))

################################################################################
# LUAROCKS

$(VENV_LUAROCKS): $(LUAROCKS_ARCHIVE_DIRNAME)/Makefile | $(VENV_LUA)
	cd $(<D) && ./configure --with-lua=$(VENV_DIR) --prefix=$(VENV_DIR)
	cd $(<D) && $(MAKE) && $(MAKE) install

$(LUAROCKS_ARCHIVE_DIRNAME)/Makefile:
	mkdir -p '$(@D)'
	$(call DOWNLOAD,$(@D),$(LR_DOWNLOAD_URL))
