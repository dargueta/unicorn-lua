rockspec_format = "3.0"
package = "unicorn"
version = "2.3.0-1"

source = {
    url = "git+ssh://git@github.com/dargueta/unicorn-lua.git",
    tag = "v2.3.0"
}

description = {
    summary = "Lua bindings for the Unicorn CPU emulator.",
    homepage = "https://github.com/dargueta/unicorn-lua",
    license = "GPL-2"
}

dependencies = {
    "lua >= 5.1",
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
        LUA_VERSION = "$(LUA_VERSION)",
        OBJ_EXTENSION = "$(OBJ_EXTENSION)",
    },
    build_variables = {
        CC = "$(CC)",
        CFLAGS = "$(CFLAGS)",
        LD = "$(LD)",
        LIBFLAG = "$(LIBFLAG)",
        LUA_DIR = "$(LUA_DIR)",
        LUA_INCDIR = "$(LUA_INCDIR)",
        UNICORN_INCDIR = "$(UNICORN_INCDIR)",
        UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
        PTHREAD_LIBDIR = "$(PTHREAD_LIBDIR)",
    },
    install_target = "__install",
    install_variables = {
        CP = "$(CP)",
        INST_LIBDIR = "$(LIBDIR)",
        INST_LUADIR = "$(LUADIR)",
    },
}


test_dependencies = {
    "busted",
    "penlight >=1.8.1, <2.0",
}
