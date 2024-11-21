basic_hook_functions = {
    code = {
        arguments = {
            { name = "address", type = "uint64_t" },
            { name = "size", type = "uint32_t" },
        },
    },

    port_out = {
        arguments = {
            { name = "port", type = "uint32_t" },
            { name = "size", type = "int" },
            { name = "value", type = "uint32_t" },
        },
    },

    memory_access = {
        arguments = {
            { name = "type", type = "uc_mem_type" },
            { name = "address", type = "uint64_t" },
            { name = "size", type = "int" },
            { name = "value", type = "int64_t" },
        },
    },

    interrupt = {
        arguments = {
            { name = "intno", type = "uint32_t" },
        }
    },

    generic_no_arguments = {
        arguments = {},
    },
}
