basic_hook_functions = {
    code = {
        arguments = { "uint64_t", "uint32_t" },
    },

    port_out = {
        arguments = { "uint32_t", "int", "uint32_t" },
    },

    memory_access = {
        arguments = { "uc_mem_type", "uint64_t", "int", "int64_t" },
    },

    interrupt = {
        arguments = { "uint32_t" }
    },

    generic_no_arguments = {
        arguments = {},
    },
}
