return {
  _all = {
    cpath = "@BUILT_LIBRARY_SEARCH_DIR@/?@CMAKE_SHARED_LIBRARY_SUFFIX@;@LUA_CUSTOM_CPATH@",
    lpath = "@CMAKE_CURRENT_BINARY_DIR@/?.lua;@CMAKE_CURRENT_BINARY_DIR@/?/init.lua;@LUA_CUSTOM_LPATH@",
    lua = "@LUA_EXE@",
    verbose = true,
    shuffle = true,
    directory = "@CMAKE_CURRENT_SOURCE_DIR@",
  },
  default = {
    pattern = "lua",
    ROOT = {"@CMAKE_CURRENT_SOURCE_DIR@"},
  }
}
