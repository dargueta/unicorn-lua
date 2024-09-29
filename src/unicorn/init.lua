--- The main module for the Unicorn CPU Emulator.
--- @module unicorn

local uc_c = require("unicorn_c_")
local uc_engine = require("unicorn.engine")

local M = {
    --- Determine if the given architecture is supported by this engine.
    --- @tparam int architecture
    ---     An enum value indicating the architecture, from @{unicorn_const}.
    ---     These all start with "UC_ARCH_", e.g.
    ---     @{unicorn_const.UC_ARCH_X86}.
    --- @treturn bool  A boolean indicating if Unicorn supports the given architecture.
    arch_supported = uc.arch_supported,
    --- Return the error message corresponding to the given Unicorn error code.
    strerror = uc.strerror,
    version = uc.version,
}


--- Create a new Unicorn engine.
---
--- @tparam int architecture
---     An enum value indicating which architecture to emulate. The constants are
---     available in the @{unicorn_const} module and all start with "UC_ARCH_".
--- @tparam int flags
---     Architecture-specific flags that control the engine's behavior. These can be used
---     to select a specific version of an architecture, endianness (for bi-endian
---     architectures), and so on.
---
---     Flags are exposed in each architecture's `const` module. For example, the x86
---     architecture's flags are in @{x86_const}, ARM64 in @{arm64_const},
---     and so on.
--- @treturn Engine An initialized @{engine.Engine|Engine}.
function M.open(architecture, flags)
    local handle, err = uc_c.open(architecture, flags or 0)
    if err ~= nil then
        return nil, err
    end
    return uc_engine.Engine(handle), nil
end

return M
