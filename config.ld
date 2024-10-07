project = "Unicorn"
title = "Unicorn CPU Engine"
description = "Lua bindings for the Unicorn CPU emulator"
file = {
    "src/unicorn",
    exclude = {
        -- Unfortunately LDoc can't handle globs
        "src/unicorn/arm64_const.lua",
        "src/unicorn/arm_const.lua",
        "src/unicorn/m68k_const.lua",
        "src/unicorn/mips_const.lua",
        "src/unicorn/ppc_const.lua",
        "src/unicorn/riscv_const.lua",
        "src/unicorn/s390x_const.lua",
        "src/unicorn/sparc_const.lua",
        "src/unicorn/tricore_const.lua",
        "src/unicorn/unicorn_const.lua",
        "src/unicorn/x86_const.lua",
    }
}
boilerplate = true
backtick_references = false
dir = "gendocs"
format = "markdown"
not_luadoc = true
sort = true
