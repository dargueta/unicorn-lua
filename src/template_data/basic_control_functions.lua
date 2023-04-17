no_arguments_no_return = {
    "exits_disable",
    "exits_enable",
    "flush_tlb",
}

no_arguments_scalar_return = {
    get_arch = { c_type = "int", lua_type = "integer" },
    get_cpu_model = { c_type = "int", lua_type = "integer" },
    get_exits_cnt = { c_type = "size_t", lua_type = "integer" },
    get_mode = { c_type = "int", lua_type = "integer" },
    get_page_size = { c_type = "uint32_t", lua_type = "integer" },
    get_timeout = { c_type = "uint64_t", lua_type = "number" },
}

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
