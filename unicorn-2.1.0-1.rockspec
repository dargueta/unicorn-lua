rockspec_format = "3.0"
package = "unicorn"
version = "2.1.0-1"

source = {
    url = "git+ssh://git@github.com/dargueta/unicorn-lua.git",
    tag = "v2.1.0"
}

description = {
    homepage = "https://github.com/dargueta/unicorn-lua",
    license = "GNU GPL v2"
}

dependencies = {
    "lua >= 5.1"
}

supported_platforms = {
    "linux", "macos", "windows"
}

external_dependencies = {
    platforms = {
        linux = {
            PTHREAD = {
                library = "pthread"
            },
        },
    },
    UNICORN = {
        library = "unicorn",
        header = "unicorn/unicorn.h"
    }
}
external_dependencies.platforms.macos = external_dependencies.platforms.linux

test_dependencies = {
    "busted",
}

test = {
    type = "command",
    command = "make",
    flags = {
        "test",
        "BUSTED=$(SCRIPTS_DIR)/busted",
        "CC=$(CC)",
        "CXXFLAGS=$(CFLAGS)",
        "LD=$(LD)",
        "LIB_EXTENSION=$(LIB_EXTENSION)",
        "LUA=$(LUA)",
        "LUA_DIR=$(LUA_DIR)",
        "LUAROCKS=$(SCRIPTS_DIR)/luarocks",
        "OBJ_EXTENSION=$(OBJ_EXTENSION)",
        "SCRIPTS_DIR=$(SCRIPTS_DIR)",
        "MKDIR=$(MKDIR)",
        -- The following are needed but not provided by LuaRocks
        -- "LUA_INCDIR=$(LUA_INCDIR)",
        -- "LUA_LIBDIR=$(LUA_LIBDIR)",
        -- "LUA_LIBDIR_FILE=$(LUA_LIBDIR_FILE)",
        -- "UNICORN_INCDIR=$(UNICORN_INCDIR)",
        -- "UNICORN_LIBDIR=$(UNICORN_LIBDIR)",
        -- "PTHREAD_LIBDIR=$(PTHREAD_LIBDIR)",
    },
}
build = {
    type = "make",
    build_variables = {
        CC = "$(CC)",
        CXXFLAGS = "$(CFLAGS)",
        LD = "$(LD)",
        LIBFLAG = "$(LIBFLAG)",
        LUA = "$(LUA)",
        LUA_BINDIR = "$(LUA_BINDIR)",
        LUA_DIR = "$(LUA_DIR)",
        LUA_INCDIR="$(LUA_INCDIR)",
        LUAROCKS = "$(SCRIPTS_DIR)/luarocks",
        LIB_EXTENSION = "$(LIB_EXTENSION)",
        OBJ_EXTENSION = "$(OBJ_EXTENSION)",
        SCRIPTS_DIR = "$(SCRIPTS_DIR)",
        UNICORN_INCDIR = "$(UNICORN_INCDIR)",
        UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
        PTHREAD_LIBDIR = "$(PTHREAD_LIBDIR)",
        MKDIR = "$(MKDIR)"
    },
    install_variables = {
        INST_PREFIX = "$(PREFIX)",
        INST_BINDIR = "$(BINDIR)",
        INST_LIBDIR = "$(LIBDIR)",
        INST_LUADIR = "$(LUADIR)",
        INST_CONFDIR = "$(CONFDIR)",
        LIB_EXTENSION = "$(LIB_EXTENSION)",
        LUA = "$(LUA)",
        LUAROCKS = "$(SCRIPTS_DIR)/luarocks",
        OBJ_EXTENSION = "$(OBJ_EXTENSION)",
        SCRIPTS_DIR = "$(SCRIPTS_DIR)",
    },
}
