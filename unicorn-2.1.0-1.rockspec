rockspec_format = "3.0"
package = "unicorn"
version = "2.1.0-1"

source = {
    url = "git+ssh://git@github.com/dargueta/unicorn-lua.git",
    tag = "v2.1.0"
}

description = {
    summary = "Lua bindings for the Unicorn CPU emulator.",
    homepage = "https://github.com/dargueta/unicorn-lua",
    license = "GPL-2"
}

dependencies = {
    "lua >= 5.1"
}

supported_platforms = {
    "linux", "macos",
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
        "CURL=$(CURL)",
        "CXXFLAGS=$(CFLAGS)",
        "LD=$(LD)",
        "LIB_EXTENSION=$(LIB_EXTENSION)",
        "LUA=$(LUA)",
        "LUALIB=$(LUALIB)",  -- Always empty on *NIX systems
        "LUA_DIR=$(LUA_DIR)",
        "LUAROCKS=$(SCRIPTS_DIR)/luarocks",
        "OBJ_EXTENSION=$(OBJ_EXTENSION)",
        "MKDIR=$(MKDIR)",
        -- The following are needed but not provided by LuaRocks
        -- "LUA_INCDIR=$(LUA_INCDIR)",
        -- "LUA_LIBDIR=$(LUA_LIBDIR)",
        -- "UNICORN_INCDIR=$(UNICORN_INCDIR)",
        -- "UNICORN_LIBDIR=$(UNICORN_LIBDIR)",
        -- "PTHREAD_LIBDIR=$(PTHREAD_LIBDIR)",
    },
}
build = {
    type = "make",
    variables = {
        LIB_EXTENSION = "$(LIB_EXTENSION)",
        LUA = "$(LUA)",
        LUAROCKS = "$(SCRIPTS_DIR)/luarocks",
        OBJ_EXTENSION = "$(OBJ_EXTENSION)",
    },
    build_variables = {
        CC = "$(CC)",
        CURL = "$(CURL)",
        CXXFLAGS = "$(CFLAGS)",
        LD = "$(LD)",
        LIBFLAG = "$(LIBFLAG)",
        LUALIB = "$(LUALIB)",
        LUA_DIR = "$(LUA_DIR)",
        LUA_INCDIR="$(LUA_INCDIR)",
        LUA_LIBDIR = "$(LUA_LIBDIR)",
        UNICORN_INCDIR = "$(UNICORN_INCDIR)",
        UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
        PTHREAD_LIBDIR = "$(PTHREAD_LIBDIR)",
        MKDIR = "$(MKDIR)"
    },
    install_variables = {
        INST_LIBDIR = "$(LIBDIR)",
    },
}
