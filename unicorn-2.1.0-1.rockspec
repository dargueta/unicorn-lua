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
   flags = {"test"},
}
--[[
build = {
   type = "cmake",
   variables = {
      CMAKE_BUILD_TYPE = "debug",
      CMAKE_CXX_FLAGS_INIT = "$(CFLAGS)",
      CMAKE_INSTALL_PREFIX = "$(PREFIX)",
      CMAKE_VERBOSE_MAKEFILE = "YES",
      LUA = "$(LUA)",
      LUA_BINDIR = "$(LUA_BINDIR)",
      LUA_INCDIR = "$(LUA_INCDIR)",
      UNICORN_INCDIR = "$(UNICORN_INCDIR)",
      UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
      LIB_EXTENSION = "$(LIB_EXTENSION)",
      CMAKE_INCLUDE_PATH = "$(UNICORN_INCDIR);$(LUA_INCDIR)",
   },
   platforms = {
      linux = {
         variables = {
            CMAKE_LIBRARY_PATH = "$(UNICORN_LIBDIR);$(PTHREAD_LIBDIR);$(LUA_LIBDIR)",
         },
      },
      windows = {
         variables = {
            CMAKE_LIBRARY_PATH = "$(UNICORN_LIBDIR);$(LUA_LIBDIR)",
         }
      },
   },
}]]
build = {
    type = "make",
    build_variables = {
       CXXFLAGS = "$(CFLAGS)",
       LIBFLAG = "$(LIBFLAG)",
       LUA_BINDIR = "$(LUA_BINDIR)",
       LUA_DIR = "$(LUA_DIR)",
       LUA_INCDIR="$(LUA_INCDIR)",
       -- FIXME (dargueta): This is a hack around LUA_LIBDIR being undefined
       -- Either there's a bug in LuaRocks or the documentation is out of date.
       LUA_LIBDIR = "$(LUA_DIR)/lib",
       LIB_EXTENSION = "$(LIB_EXTENSION)",
       UNICORN_INCDIR = "$(UNICORN_INCDIR)",
       UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
       PTHREAD_LIBDIR = "$(PTHREAD_LIBDIR)",
    },
    install_variables = {
       INST_PREFIX = "$(PREFIX)",
       INST_BINDIR = "$(BINDIR)",
       INST_LIBDIR = "$(LIBDIR)",
       INST_LUADIR = "$(LUADIR)",
       INST_CONFDIR = "$(CONFDIR)",
       LIB_EXTENSION = "$(LIB_EXTENSION)",
    },
}
