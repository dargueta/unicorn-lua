return {
  _all = {
    cpath = "$<TARGET_FILE_DIR:unicornlua_library>/?@LIBRARY_FILE_EXTENSION@;;",
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
