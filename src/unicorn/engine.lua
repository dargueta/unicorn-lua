-- Copyright (C) 2017-2025 by Diego Argueta
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

--- @module engine

local uc_c = require("unicorn_c_")
local uc_context = require("unicorn.context")
local uc_hooks = require("unicorn.hooks")
local unicorn_const = require("unicorn.unicorn_const")

--- An object-oriented wrapper around an opened Unicorn engine.
---
--- **Garbage Collection**
---
--- The @{Engine} supports automatic cleanup in two situations: it gets garbage collected,
--- or it goes out of scope (its function returns, the `for` loop it was declared inside
--- exits, etc.). In both of these cases, @{Engine:close} is automatically called. Really,
--- though, you should call @{Engine:close} as soon as you don't need an engine, since
--- there are cases when automatic cleanup is *not* triggered.
---
--- See "To-be-closed Variables", section 3.3.8 of the Lua manual for details on scope and
--- caveats on when it doesn't work as expected. For similar caveats about when the `__gc`
--- metamethod isn't called, see *Programming in Lua*, 4th Edition, page 233.
---
--- @type Engine
local Engine = {}

local EngineMeta_ = {
    __index = Engine,
    __close = function(self)
        -- Only close the engine if it hasn't been closed already. We want to allow double-
        -- closing here because the user may want to explicitly close an engine on some
        -- control paths, but let Lua automatically close it on others.
        if self.handle_ ~= nil then
            self:close()
        end
    end
}

-- The garbage collection process is exactly the same as closing the engine, so we might
-- as well reuse that function.
EngineMeta_.__gc = EngineMeta_.__close


--- Create a new @{Engine} that wraps a raw engine handle from the C library.
---
--- @param handle  A userdata handle to an open engine returned by the Unicorn C library.
--- @treturn Engine  A class instance wrapping the handle.
function wrap_handle_(handle)
    local instance = {
        is_running_ = false,
        handle_ = handle,
        -- Once a context object is unreachable, it can't be used to restore the engine to
        -- the state the context describes. Since there's no point to holding onto a
        -- context the user can no longer use, we use a weak table to store them to allow
        -- them to be garbage collected once the user can't use them anymore.
        --
        -- We still need this table because if there are active contexts lying around when
        -- the engine is closed, we need to release those as well.
        contexts_ = setmetatable({}, {__mode = "kv"}),

        -- Hooks maintain strong references to their callbacks. When an engine is closed,
        -- we need to delete the strong references manually to release any remaining
        -- callbacks.
        -- TODO (dargueta): Keep strong references to callbacks here, not in C.
        hooks_ = {},
    }

    return setmetatable(instance, EngineMeta_)
end


--- Stop the emulator engine and free all resources.
---
--- This removes all hooks, frees contexts and memory, then closes the underlying Unicorn
--- engine. The object must not be used after this is called. If you only want to pause
--- emulation, use @{engine.Engine:emu_stop}.
function Engine:close()
    if self.handle_ == nil then
        error("Attempted to close an engine twice.")
    end

    if self.is_running_ then
        self:emu_stop()
    end

    for _, context in pairs(self.contexts_) do
        -- If a context is freed, the wrapper object will still remain in this table until
        -- the next collection cycle. Thus, we need to check to see if the handle is nil
        -- before attempting to free it.
        if context.handle_ ~= nil then
            context:free()
        end
    end
    self.contexts_ = nil

    uc_c.close(self.handle_)

    -- While the Unicorn library doesn't require us to remove hooks before closing an
    -- engine, because hooks keep strong references to their callbacks we need to at least
    -- release the callbacks.
    if table.unpack then
        -- Lua >=5.3
        uc_c.ulinternal_release_hook_callbacks(table.unpack(self.hooks_))
    else
        -- Lua <= 5.2
        uc_c.ulinternal_release_hook_callbacks(unpack(self.hooks_))
    end
    self.hooks_ = nil

    -- We need to delete the handle so that when the garbage collector runs, we don't try
    -- closing an already deallocated engine.
    self.handle_ = nil
end

--- Restore the engine's state to a previously-saved state.
---
--- @tparam context.Context context  The saved state to restore the engine to.
--- @see engine.Engine:context_save
function Engine:context_restore(context)
    return uc_c.context_restore(self.handle_, context.handle_)
end


--- Save the engine's current state.
---
--- @tparam[opt] context.Context context  An existing context object to reuse. If not
--- given, a new one is created.
--- @treturn context.Context  `context` if it was passed in, otherwise a new one.
--- @see context_restore
function Engine:context_save(context)
    if context ~= nil then
        context.handle_ = uc_c.context_save_reuse_existing(self.handle_, context.handle_)
        return context
    end

    local raw_context_handle = uc_c.context_save(self.handle_, nil)
    local wrapped_handle = uc_context.wrap_handle_(self, raw_context_handle)

    self.contexts_[wrapped_handle] = wrapped_handle
    return wrapped_handle
end


--- Asynchronously start execution at the given location.
---
--- @tparam[opt=0] int start_addr  The address to start execution at.
--- @tparam[opt] int end_addr  The highest address in memory to execute instructions to;
--- the engine will automatically halt once it reaches or exceeds this address. If not
--- given, there's no upper limit.
--- @tparam[opt] int timeout  The maximum amount of time to execute, in microseconds. If
--- not given or 0, there is no limit.
--- @tparam[opt] int n_instructions  The maximum number of instructions to execute. If not
--- given or 0, there is no limit.
---
---@see emu_stop
function Engine:emu_start(start_addr, end_addr, timeout, n_instructions)
    uc_c.emu_start(
        self.handle_,
        start_addr or 0,
        end_addr or 0,
        timeout or 0,
        n_instructions or 0
    )
    self.is_running_ = true
end

--- Pause emulation.
---
--- @see emu_start
--- @usage engine:emu_stop()
function Engine:emu_stop()
    uc_c.emu_stop(self.handle_)
    self.is_running_ = false
end

--- Get the status code of the last API operation on this engine.
---
--- @treturn int  One of the `UC_ERR_` constants, like @{unicorn_const.UC_ERR_OK}.
function Engine:errno()
    return uc_c.errno(self.handle_)
end

--- Add a new event hook to the engine.
---
--- The return value is a handle used to keep track of the hook. Unlike contexts, hooks
--- are not removed if the handle is garbage collected.
---
--- @tparam int hook_type  The type of hook to create. The constants are in @{unicorn_const}
--- and begin with `UC_HOOK_`.
--- @tparam function callback  The function to call when the hook is triggered. The
--- arguments passed to the callback depend on the type of hook.
--- @tparam[opt=0] int start_address  The lowest memory address this hook is be active for.
--- @tparam[opt] int end_address  The highest memory address this hook is active for. If
--- not given, defaults to the end of memory.
--- @param[opt] udata  An additional argument to pass to the hook for its use, such as a
--- file handle or a table. Unicorn keeps a hard reference to it in the registry until the
--- hook is deleted, but otherwise doesn't care what it is.
---
--- @treturn userdata  A handle to the hook that was just created.
--- @usage engine:hook_add(unicorn_const.UC_HOOK_MEM_WRITE, my_callback, 0xb8000, 0xbffff)
--- @see hook_del
function Engine:hook_add(hook_type, callback, start_address, end_address, udata, ...)
    local hook_handle = uc_hooks.create_hook(
        self,
        hook_type,
        callback,
        start_address,
        end_address,
        udata,
        ...
    )
    self.hooks_[hook_handle] = hook_handle
    return hook_handle
end

--- Remove a hook from the engine.
---
--- @tparam userdata hook  A hook handle returned from @{hook_add}.
--- @see hook_add
function Engine:hook_del(hook)
    uc_c.hook_del(self.handle_, hook)
    self.hooks_[hook] = nil
end

--- Create a new region of emulated RAM in the engine.
---
--- When it's first created, there's no emulated RAM for an engine to access. Any memory
--- needs to be declared explicitly.
---
--- @tparam int address  The address where the new block of memory will begin.
--- @tparam int size  The size of the memory block, in bytes.
--- @tparam[opt=UC_PROT_ALL] int perms  Access permissions for the memory block. These are
--- flags defined in @{unicorn_const} that start with ``UC_PROT_``. They can be OR'ed
--- together to set multiple permissions.
---
--- @usage engine:mem_map(0, 0x400, unicorn_const.UC_PROT_READ | unicorn_const.UC_PROT_WRITE)
---
--- @see mem_protect
--- @see mem_unmap
function Engine:mem_map(address, size, perms)
    if perms == nil then
        perms = unicorn_const.UC_PROT_ALL
    end

    uc_c.mem_map(self.handle_, address, size, perms)
end

--- Change access permissions on an existing block of memory.
---
--- @tparam int address  The address of the the memory block to modify.
--- @tparam int size  The size of the memory block, in bytes.
--- @tparam int perms  The new access permissions.
function Engine:mem_protect(address, size, perms)
    uc_c.mem_protect(self.handle_, address, size, perms)
end

--- Read a block of memory from the engine.
---
--- Permissions set in @{mem_map} or @{mem_protect} don't apply to this method, so it's
--- possible to read from memory that doesn't have @{unicorn_const.UC_PROT_READ} set.
---
--- @tparam int address  The address of the memory block to read.
--- @tparam int size  The number of bytes to read.
--- @treturn string  The contents of emulated memory.
function Engine:mem_read(address, size)
    return uc_c.mem_read(self.handle_, address, size)
end

--- Get an enumeration of all memory regions mapped into the engine.
---
--- @treturn {MemoryRegion, ...}  An array of each memory region. Order is not guaranteed.
function Engine:mem_regions()
    local regions = uc_c.mem_regions(self.handle_)
    local meta = {__index = MemoryRegion}

    for _, region in ipairs(regions) do
        setmetatable(region, meta)
    end
    return regions
end

--- Unmap a region of emulated RAM from the engine.
---
--- After a successful call, any attempt by the engine to access memory in this region
--- will cause an error.
---
--- @tparam int address  The address of the beginning of the block to unmap.
--- @tparam int size  The size of the memory block to unmap, in bytes.
function Engine:mem_unmap(address, size)
    uc_c.mem_unmap(self.handle_, address, size)
end

--- Set the contents of a mapped region of memory.
---
--- @tparam int address  The address of the beginning of the block of memory to write. It
--- must have already been mapped in using @{mem_map}.
--- @tparam string data  A byte string, the binary data to write to memory.
function Engine:mem_write(address, data)
    uc_c.mem_write(self.handle_, address, data)
end

--- Get information about an initialized engine, such as its page size, mode flags, etc.
---
--- @tparam int query_flag  Any `UC_QUERY_` constant like @{unicorn_const.UC_QUERY_MODE}.
---
--- @treturn int    The requested value.
function Engine:query(query_flag)
    return uc_c.query(self.handle_, query_flag)
end

--- Read the current value of a CPU register as a signed integer.
---
--- @tparam int register  An architecture-specific enum value indicating the register to
--- read. These are found in the const module for the relevant architecture, and are
--- always of the form `UC_<arch>_REG_<reg name>`. For example, @{ppc_const.UC_PPC_REG_CR5}
--- would read the CR5 register from a PowerPC engine. Passing a constant from the wrong
--- architecture has undefined behavior.
--- @tparam[opt] int x86_msr_id  If `register` is @{x86_const.UC_X86_REG_MSR}, this must
--- be the ID of the model-specific CPU register to read. Lists of these register IDs can
--- be found in "Intel 64 and IA-32 Software Developer's Manual", available on Intel's
--- website.
---
--- @treturn int  The register's value.
function Engine:reg_read(register, x86_msr_id)
    return uc_c.reg_read(self.handle_, register, x86_msr_id)
end

--- Read the current value of a CPU register as something other than an integer.
---
--- This is primarily useful for SIMD instructions, where a single register can be
--- interpreted as (for example) an array of two 64-bit integers, four 32-bit integers,
--- eight 16-bit integers, and so on. While especially useful for SIMD registers, any
--- registers, any register can be read from with this method.
---
--- @tparam int register  The ID of the register to read (same as @{Engine:reg_read}.
--- @tparam int type_id  An enum value indicating how to reinterpret the register. These
--- can be found in @{registers_const}.
function Engine:reg_read_as(register, type_id)
    return uc_c.reg_read_as(self.handle_, register, type_id)
end

function Engine:reg_read_batch(...)
    return uc_c.reg_read_batch(self.handle_, ...)
end

function Engine:reg_read_batch_as(registers)
    return uc_c.reg_read_batch_as(self.handle_, registers)
end

--- Set the current value of a CPU register to an integer value.
---
--- @tparam int register  An architecture-specific enum value indicating the register to
--- write to. The meaning is the same as in @{Engine:reg_read}.
--- @tparam int value  The value to write to the register.
function Engine:reg_write(register, value)
    return uc_c.reg_write(self.handle_, register, value)
end

--- Write a value to a register as anything other than a single integer.
---
--- This is the converse of @{Engine:reg_read_as}, and lets you set a non-integer-valued
--- register (like STx) or SIMD register (e.g. XMM0 to an array of eight 16-bit integers).
---
--- While especially useful for SIMD registers, any register can be written to with this
--- method. For example, you can set AX using two eight-bit values instead of having to
--- compute `(AH << 8) | AL` manually.
---
--- @tparam int register  An architecture-specific enum value indicating the register to
--- write to. The meaning is the same as in @{Engine:reg_read}.
--- @param value  The value to write to the register.
--- @tparam int as_type  An enum value indicating how to reinterpret the register. These
--- can be found in @{registers_const}.
function Engine:reg_write_as(register, value, as_type)
    return uc_c.reg_write_as(self.handle_, register, value, as_type)
end

--- Set the value of multiple CPU registers at once.
---
--- This should only be used when setting the value of integer registers. To set multiple
--- registers to non-integer values (e.g. setting ST0, or XMM0 as an array of 8-bit ints)
--- you must call @{Engine:reg_write_as} individually.
---
--- @param registers A table mapping register IDs to the values to assign them.
function Engine:reg_write_batch(registers)
    return uc_c.reg_write_batch(self.handle_, registers)
end

--- Disable setting multiple exit points (addresses that halt the engine if executed).
function Engine:ctl_exits_disable()
    return uc_c.ctl_exits_disable(self.handle_)
end

--- Enable setting multiple exit points (addresses that halt the engine if executed).
---
--- This must be called before @{Engine:emu_start}.
function Engine:ctl_exits_enable()
    return uc_c.ctl_exits_enable(self.handle_)
end

function Engine:ctl_flush_tlb()
    return uc_c.ctl_flush_tlb(self.handle_)
end

--- Get the architecture ID of the engine.
--- @treturn int  The architecture ID, e.g. @{unicorn_const.UC_ARCH_S390X}.
function Engine:ctl_get_arch()
    return uc_c.ctl_get_arch(self.handle_)
end

function Engine:ctl_get_cpu_model()
    return uc_c.ctl_get_cpu_model(self.handle_)
end

--- Get a list of all the addresses that halt the engine if executed.
---
--- @treturn {int, ...}  The addresses of all exit points.
--- @see Engine:ctl_exits_enable
--- @see Engine:ctl_set_exits
function Engine:ctl_get_exits()
    return uc_c.ctl_get_exits(self.handle_)
end

function Engine:ctl_get_exits_cnt()
    return uc_c.ctl_get_exits_cnt(self.handle_)
end

--- Get the mode flags the engine was created with.
--- @treturn int  The mode flags.
function Engine:ctl_get_mode()
    return uc_c.ctl_get_mode(self.handle_)
end

--- Get the size of a memory page.
---
--- @treturn int  The size of a memory page, in bytes.
function Engine:ctl_get_page_size()
    return uc_c:ctl_get_page_size(self.handle_)
end

function Engine:ctl_get_timeout()
    return uc_c.ctl_get_timeout(self.handle_)
end

function Engine:ctl_remove_cache()
    return uc_c.ctl_remove_cache(self.handle_)
end

--- Get information about the QEMU translation block for a specific address.
---
--- @tparam int address  The address in guest memory to get the corresponding translation
--- block for.
---
--- @treturn TranslationBlock  Information about the translation block.
function Engine:ctl_request_cache(address)
    return uc_c.ctl_request_cache(self.handle_, address)
end

--- Set the CPU model of the engine.
---
--- This must be called immediately after creating the engine.
function Engine:ctl_set_cpu_model(model)
    return uc_c.ctl_set_cpu_model(self.handle_, model)
end

--- Set multiple addresses that will halt the engine if executed.
---
--- @tparam {int, ...}  An array of addresses that will cause emulation to stop if
--- executed.
---
--- @see Engine:ctl_exits_enable
--- @see Engine:ctl_get_exits
function Engine:ctl_set_exits(addresses)
    return uc_c.ctl_set_exits(self.handle_, addresses)
end

--- Set the size of a memory page.
--- @tparam int  page_size  The size of a memory page.
function Engine:ctl_set_page_size(page_size)
    return uc_c.ctl_set_page_size(self.handle_, page_size)
end


--- A structure representing a block of emulated memory mapped into the engine.
---
--- @type MemoryRegion
--- @see Engine:mem_regions
local MemoryRegion = {
    --- @field begins  The base address of this block of memory.

    --- @field ends  The last valid address in this block of memory.

    --- @field perms Permission flags.
}


--- Determine if the memory can be read from.
--- @treturn bool  `true` if this block of memory is readable, `false` otherwise.
 function MemoryRegion:can_read()
    return uc_c.bitwise_and(self.perms, unicorn_const.UC_PROT_READ) ~= 0
end

--- Determine if the memory can be written to.
--- @treturn bool  `true` if this block of memory is writable, `false` otherwise.
 function MemoryRegion:can_write()
    return uc_c.bitwise_and(self.perms, unicorn_const.UC_PROT_WRITE) ~= 0
end

--- Determine if the memory can be both read from and written to.
--- @treturn bool  `true` if this block of memory is both readable and writable,
--- `false` otherwise.
 function MemoryRegion:can_readwrite()
    local mask = unicorn_const.UC_PROT_READ + unicorn_const.UC_PROT_WRITE
    return uc_c.bitwise_and(self.perms, mask) == mask
end

--- Determine if the memory can be read from.
--- @treturn bool  `true` if this block of memory is executable, `false` otherwise.
function MemoryRegion:can_exec()
    return uc_c.bitwise_and(self.perms, unicorn_const.UC_PROT_EXEC) ~= 0
end

--- Determine if the memory has read, write, and execute permissions.
--- @treturn bool  `true` if this block of memory is readable, writable, and executable;
--- `false` otherwise.
function MemoryRegion:can_all()
    return uc_c.bitwise_and(self.perms, unicorn_const.UC_PROT_ALL) == unicorn_const.UC_PROT_ALL
end


--- A structure representing a QEMU translation block in memory.
---
--- QEMU contains a JIT that breaks down instruction memory into one or more blocks,
--- called "translation blocks". It translates the guest instruction set into host-native
--- instructions that are stored in these translation blocks.
---
--- Someone should check me on this. I'm guessing the meaning of the fields based on QEMU
--- documentation.
---
--- @type TranslationBlock
--- @see Engine:ctl_request_cache
--- @see https://www.qemu.org/docs/master/devel/tcg.html
local TranslationBlock = {
    --- @field pc  The simulated program counter within this block.

    --- @field icount  The number of instructions in the block.

    --- @field size  The size of the block, in bytes.
}


--- @exports
return {
    Engine = Engine,
    wrap_handle_ = wrap_handle_,
    MemoryRegion = MemoryRegion,
    TranslationBlock = TranslationBlock,
}
