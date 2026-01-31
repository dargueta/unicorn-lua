project = "Unicorn"
title = "Unicorn CPU Engine"
description = "Lua bindings for the Unicorn CPU emulator"
file = {
    -- Lua files must come first, as the C files reference them.
    "src/unicorn",
    exclude = {
        -- Unfortunately LDoc can't handle globs
        "src/unicorn/arm64_const.lua",
        "src/unicorn/arm64_extracted_consts.lua",
        "src/unicorn/arm_const.lua",
        "src/unicorn/arm_extracted_consts.lua",
        "src/unicorn/m68k_const.lua",
        "src/unicorn/m68k_extracted_consts.lua",
        "src/unicorn/mips_const.lua",
        "src/unicorn/mips_extracted_consts.lua",
        "src/unicorn/ppc_const.lua",
        "src/unicorn/ppc_extracted_consts.lua",
        "src/unicorn/riscv_const.lua",
        "src/unicorn/riscv_extracted_consts.lua",
        "src/unicorn/s390x_const.lua",
        "src/unicorn/s390x_extracted_consts.lua",
        "src/unicorn/sparc_const.lua",
        "src/unicorn/sparc_extracted_consts.lua",
        "src/unicorn/tricore_const.lua",
        "src/unicorn/tricore_extracted_consts.lua",
        "src/unicorn/unicorn_const.lua",
        "src/unicorn/unicorn_extracted_consts.lua",
        "src/unicorn/x86_const.lua",
        "src/unicorn/x86_extracted_consts.lua",
    }
}
boilerplate = true
backtick_references = false
dir = "gendocs"
format = "markdown"
no_space_before_args = true
not_luadoc = true
sort = true
wrap = true
