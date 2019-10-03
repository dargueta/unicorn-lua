return {
  _all = {
    cpath = "@CMAKE_CURRENT_BINARY_DIR@/?@CMAKE_SHARED_LIBRARY_SUFFIX@;@CMAKE_CURRENT_BINARY_DIR@/?/init@CMAKE_SHARED_LIBRARY_SUFFIX@;@LUA_CUSTOM_CPATH@",
    lpath = "@CMAKE_CURRENT_BINARY_DIR@/?.lua;@CMAKE_CURRENT_BINARY_DIR@/?/init.lua;@LUA_CUSTOM_LPATH@",
    lua = "@LUA_EXE@",
    verbose = true,
    shuffle = true,
    directory = "@CMAKE_CURRENT_SOURCE_DIR@",
  },
  default = {
    pattern = "lua",
    ROOT = {"@CMAKE_CURRENT_SOURCE_DIR@/tests/lua"},
  }
}
