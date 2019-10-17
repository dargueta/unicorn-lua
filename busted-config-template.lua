return {
  _all = {
    cpath = "@BUILT_LIBRARY_DIRECTORY@/?@CMAKE_SHARED_LIBRARY_SUFFIX@;;",
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
