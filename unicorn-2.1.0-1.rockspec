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
   -- "lcurses",
}

test = {
   type = "command",
   command = "make",
   flags = { "-B", "-C", "build.luarocks", "cpp_test", "test", 'ARGS=--output-on-failure -VV' }
}

build = {
   type = "cmake",
   variables = {
      CMAKE_BUILD_TYPE = "debug",
      CMAKE_CXX_FLAGS_INIT = "$(CFLAGS)",
      CMAKE_INSTALL_PREFIX = "$(PREFIX)",
      CMAKE_VERBOSE_MAKEFILE = "YES",
      IS_LUAJIT = "0",  -- TODO (dargueta): Fix this
      LUA_INCDIR = "$(LUA_INCDIR)",
      LUA_LIBDIR = "$(LUA_LIBDIR)",
      UNICORN_INCDIR = "$(UNICORN_INCDIR)",
      UNICORN_LIBDIR = "$(UNICORN_LIBDIR)",
   },
   platforms = {
      linux = {
         variables = {
            LIBRARY_FILE_EXTENSION = ".so",
            CMAKE_LIBRARY_PATH = "$(UNICORN_LIBDIR);$(PTHREAD_LIBDIR);$(LUA_LIBDIR)",
         },
      },
      windows = {
         variables = {
            LIBRARY_FILE_EXTENSION = ".dll",
            CMAKE_LIBRARY_PATH = "$(UNICORN_LIBDIR);$(LUA_LIBDIR)",
         }
      },
   },
}
build.platforms.macos = build.platforms.linux
