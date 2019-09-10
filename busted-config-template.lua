return {
  _all = {
    cpath = "build/?.${LIB_EXTENSION};build/?/init.${LIB_EXTENSION};${LUA_CUSTOM_CPATH}",
    lpath = "build/?.lua;build/?/init.lua;${LUA_CUSTOM_LPATH}",
    lua = "${LUA_EXE}",
    verbose = true,
    shuffle = true,
  },
  default = {
    pattern = "lua",
    ROOT = {"./tests/lua"},
  }
}
