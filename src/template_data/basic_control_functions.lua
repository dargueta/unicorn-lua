--[[
This file contains manually-derived information on the arguments and return
values of simple control functions. "Simple" means that the function meets all
of the following criteria:

1. It always returns (unlike setjmp(), longjmp(), abort(), etc.)
2. It has a fixed number of arguments (no variadic functions)
3. None of the arguments (*except* the engine) are pointers.
4. It returns either void or a non-pointer value.

To add a function, put it in the appropriate section according to the number of
arguments and its return value. Remove the `uc_ctl_` prefix (uc_ctl_foo -> foo)
and don't count the pointer to the Unicorn engine as an argument.

    void uc_ctl_nanr(uc_engine *uc)

        This goes in `no_arguments_no_return` as "nanr".

    void uc_ctl_sanr(uc_engine *uc, size_t one, int two)

        This goes in `scalar_arguments_no_return` as "sanr"

Type information is the same for arguments and return values.
]]

--------------------------------------------------------------------------------
-- Functions that take no arguments (aside from the Unicorn engine) and return
-- nothing.
--
-- List your function here with the "uc_" prefix stripped. Please maintain
-- alphabetical order and add a trailing comma to minimize the size of the diff.
no_arguments_no_return = {
    "exits_disable",
    "exits_enable",
    "flush_tlb",
}

--------------------------------------------------------------------------------
-- Functions taking no arguments and returning a scalar value.
--
-- Each entry is the name of the function mapped to a table with the type
-- information of the return value.
no_arguments_scalar_return = {
    get_arch = { c_type = "int", lua_type = "integer" },
    get_cpu_model = { c_type = "int", lua_type = "integer" },
    get_exits_cnt = { c_type = "size_t", lua_type = "integer" },
    get_mode = { c_type = "int", lua_type = "integer" },
    get_page_size = { c_type = "uint32_t", lua_type = "integer" },
    get_timeout = { c_type = "uint64_t", lua_type = "number" },
}

--------------------------------------------------------------------------------
-- Functions taking one or more scalar arguments and returning nothing
--
-- Each entry is the name of the function mapped to an array table with the type
-- information of each argument, in order.
scalar_arguments_no_return = {
    remove_cache = {
        { c_type = "uint64_t", lua_type = "integer" },
        { c_type = "uint64_t", lua_type = "integer" },
    },
    set_cpu_model = {
        { c_type = "int", lua_type = "integer" },
    },
    set_page_size = {
        { c_type = "uint32_t", lua_type = "integer" },
    },
}

-- tb ctl_request_cache(address)
-- ctl_set_exits(exits)
