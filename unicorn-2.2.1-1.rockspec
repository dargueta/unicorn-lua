rockspec_format = "3.0"
package = "unicorn"
version = "2.2.1-1"

source = {
    url = "git+ssh://git@github.com/dargueta/unicorn-lua.git",
    tag = "v2.2.1"
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

build_dependencies = {
    "penlight >=1.8.1, <2.0",
}

build = {
    type = "make",
    variables = {
        LIB_EXTENSION = "$(LIB_EXTENSION)",
        LUA = "$(LUA)",
        LUAROCKS = "$(SCRIPTS_DIR)/luarocks",
        OBJ_EXTENSION = "$(OBJ_EXTENSION)",
        LUA_VERSION = "$(LUA_VERSION)",
        CALLED_FROM_LUAROCKS = "1",
    },
    build_variables = {
        CC = "$(CC)",
        CURL = "$(CURL)",
        CXXFLAGS = "$(CFLAGS)",
        LD = "$(LD)",
        LIBFLAG = "$(LIBFLAG)",
        LUA_DIR = "$(LUA_DIR)",
        LUA_INCDIR="$(LUA_INCDIR)",
        UNICORN_INCDIR = "$(UNICORN_INCDIR)",
        UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
        PTHREAD_LIBDIR = "$(PTHREAD_LIBDIR)",
        MKDIR = "$(MKDIR)",
        LUALIB = "$(LUALIB)",
    },
    install_variables = {
        INST_LIBDIR = "$(LIBDIR)",
    },
    platforms = {
        -- Clang on MacOS needs to be explicitly told to use the C++11 standard, since it
        -- defaults to an older standard.
        macos = {
            build_variables = {
                CXXFLAGS = "$(CFLAGS) -std=c++11"
            }
        }
    }
}


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
        "LUA_VERSION=$(LUA_VERSION)",
        "LUALIB=$(LUALIB)",  -- Always empty on *NIX systems
        "LUA_DIR=$(LUA_DIR)",
        "LUAROCKS=$(SCRIPTS_DIR)/luarocks",
        "OBJ_EXTENSION=$(OBJ_EXTENSION)",
        "MKDIR=$(MKDIR)",
        -- The following are needed for building the tests, but aren't provided by
        -- LuaRocks when testing.
        "LUA_INCDIR=$(LUA_DIR)/include",
        "LUA_LIBDIR=$(LUA_DIR)/lib",
        -- "UNICORN_INCDIR=$(UNICORN_INCDIR)",
        -- "UNICORN_LIBDIR=$(UNICORN_LIBDIR)",
        -- "PTHREAD_LIBDIR=$(PTHREAD_LIBDIR)",
        "CALLED_FROM_LUAROCKS=1",
    },

    platforms = {
        -- Clang on MacOS needs to be explicitly told to use the C++11 standard, since it
        -- defaults to an older standard.
        macos = {
            flags = {
                CXXFLAGS = "$(CFLAGS) -std=c++11"
            }
        }
    }
}
