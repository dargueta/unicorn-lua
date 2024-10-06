-- These are docstrings defined for constants exported from Unicorn headers.
docstrings = {
    unicorn = {
        UC_ARCH_ARM = "Specifies the ARM architecture, used in @{unicorn.open}.",
        UC_ARCH_ARM64 = "Specifies the ARM64 architecture, used in @{unicorn.open}.",
        UC_ARCH_M68K = "Specifies the Motorola 68000 architecture, used in @{unicorn.open}.",
        UC_ARCH_MAX = "Internal to Unicorn. Do not use.",
        UC_ARCH_MIPS = "Specifies the MIPS architecture, used in @{unicorn.open}.",
        UC_ARCH_PPC = "Specifies the PowerPC architecture, used in @{unicorn.open}.",
        UC_ARCH_RISCV = "Specifies the RISC-V architecture, used in @{unicorn.open}.",
        UC_ARCH_S390X = "Specifies the s390x architecture, used in @{unicorn.open}.",
        UC_ARCH_SPARC = "Specifies the SPARC architecture, used in @{unicorn.open}.",
        UC_ARCH_TRICORE = "Specifies the Tricore architecture, used in @{unicorn.open}.",
        UC_ARCH_X86 = "Specifies the x86 architecture, used in @{unicorn.open}.",
        UC_ERR_ARCH = "Invalid/unsupported architecture",
        UC_ERR_ARG = "Invalid argument",
        UC_ERR_EXCEPTION = "Unhandled CPU exception",
        UC_ERR_FETCH_PROT = "Fetch from non-executable memory",
        UC_ERR_FETCH_UNALIGNED = "Fetch from unaligned memory",
        UC_ERR_FETCH_UNMAPPED = "Invalid memory fetch",
        UC_ERR_HANDLE = "Invalid handle",
        UC_ERR_HOOK = "Invalid hook type",
        -- UC_ERR_HOOK_EXIST = "Unknown",
        UC_ERR_INSN_INVALID = "Invalid instruction",
        UC_ERR_MAP = "Invalid memory mapping",
        UC_ERR_MODE = "Invalid mode",
        UC_ERR_NOMEM = "No memory available or memory not present",
        UC_ERR_OK = "OK",
        UC_ERR_READ_PROT = "Read from non-readable memory",
        UC_ERR_READ_UNALIGNED = "Read from unaligned memory",
        UC_ERR_READ_UNMAPPED = "Invalid memory read",
        UC_ERR_RESOURCE = "Insufficient resource",
        UC_ERR_VERSION = "Different API version between core & binding",
        UC_ERR_WRITE_PROT = "Write to write-protected memory",
        UC_ERR_WRITE_UNALIGNED = "Write to unaligned memory",
        UC_ERR_WRITE_UNMAPPED = "Invalid memory write",
    },
}

sections = {
    unicorn = {
        {
            slug = "architectures",
            title = "Architecture Codes.",
            description = [[
Pass one of these as the first argument to @{unicorn.open} to select the emulated
architecture.

@see unicorn.open
]],
            pattern = "UC_ARCH_"
        },
        {
            slug = "modes",
            title = "Engine Mode Flags.",
            description = [[
Pass one or more of these OR'ed together as the second argument to @{unicorn.open} in
order to control aspects of the engine such as its address width (@{UC_MODE_16},
@{UC_MODE_32}, etc.) or endianness (e.g. @{UC_MODE_BIG_ENDIAN}).

@see unicorn.open
]],
            pattern = "UC_MODE_"
        },
        {
            slug = "error_codes",
            title = "Error Codes.",
            description = "Error codes returned from Unicorn functions.",
            pattern = "UC_ERR_"
        },
        {
            slug = "protection",
            title = "Memory Protection Flags.",
            description = [[
These flags can be OR'ed together to define protections on memory mapped in to the engine.

@see Engine:mem_map
@see Engine:mem_protect
]],
            pattern = "UC_PROT_",
        },
        {
            slug = "hooks",
            title = "Hook Types.",
            description = [[
These are codes for different types of hooks one can set up in an engine.

@see Engine:hook_add
]],
            pattern = "UC_HOOK_",
        },
        {
            slug = "memory_hook_types",
            title = "Memory Access Types.",
            description = [[
When a memory access hook is added to an engine, the `access_type` argument of the callback
will be set to one of these constants to indicate the event that triggered the hook.

@see engine.Engine:hook_add
]],
            pattern = "UC_MEM_",
        },
        {
            slug = "control_functions",
            title = "Engine Control Functions.",
            description = [[
These codes are used with the ctl_* family of @{engine.Engine} methods. For the most part
you won't need these, as they're separated out into their own methods. You can use them
with @{Engine:do_ctl} to run a control function using only the code instead of invoking a
named method.]],
            pattern = "UC_CTL_",
        },
        {
            slug = "query_functions",
            title = "Engine Query Functions.",
            description = [[
Use these to query aspects of an open engine, such as its mode flags, page size, and more.

@see engine.Engine:query
]],
            pattern = "UC_QUERY_",
        },
    }
}
