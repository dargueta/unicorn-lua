return {
  _all = {
    -- CMake on Windows cannot tolerate generator expressions so we can't use
    -- the usual $<TARGET_FILE...> here and must generate the path manually.
    cpath = "@CMAKE_CURRENT_BINARY_DIR@/lib/?.@LIB_EXTENSION@;;",
    lua = "@LUA@",
    verbose = true,
    shuffle = true,
    directory = "@CMAKE_CURRENT_SOURCE_DIR@",
  },
  default = {
    pattern = "lua",
    ROOT = {"@CMAKE_CURRENT_SOURCE_DIR@"},
  }
}
