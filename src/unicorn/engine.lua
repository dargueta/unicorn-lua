-- Copyright (C) 2017-2024 by Diego Argueta
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

local M = {
    Engine = Engine
}

local EngineMeta_ = {__index = Engine}


--- Create a new @{Engine}.
---
--- @param handle  A userdata handle to an open engine returned by the Unicorn C library.
--- @treturn Engine  A class instance wrapping the handle.
function M.new_engine(handle)
    local instance = {
        engine_handle_ = handle,
        -- Once a context object is unreachable, it can't be used to restore the engine to
        -- the state the context describes. Since there's no point to holding onto a
        -- context the user can no longer use, we use a weak table to store them to allow
        -- them to be garbage collected once the user can't use them anymore.
        --
        -- We still need this table because if there are active contexts laying around
        -- when the engine is closed, we need to release those as well.
        contexts_ = setmetatable({}, {__mode = "k"}),
        hooks_ = {},
    }

    return setmetatable(instance, EngineMeta_)
end

function EngineMeta_:__close()
    -- Only close the engine if it hasn't been closed already. We want to allow double-
    -- closing here because the user may want to explicitly close an engine on some
    -- control paths, but let Lua automatically close it on others.
    if self.engine_handle_ ~= nil then
        self:close()
    end
end

function EngineMeta_:__gc()
    if self.engine_handle_ ~= nil then
        self:close()
    end
end

--- Stop the emulator engine and free all resources.
---
--- This removes all hooks, frees contexts and memory, then closes the underlying Unicorn
--- engine. The object must not be used after this is called.
function Engine:close()
    if self.engine_handle_ == nil then
        error("Attempted to close an engine twice.")
    end

    self:emu_stop()

    for context in pairs(self.contexts_) do
        context:free()
    end
    self.contexts_ = {}

    for hook_handle in pairs(self.hooks_) do
        hook_handle:close()
    end
    self.hooks_ = {}

    uc_c.close(self.engine_handle_)

    -- We need to delete the handle so that when the garbage collector runs, we don't try
    -- closing an already deallocated engine.
    self.engine_handle_ = nil
end

--- Restore the engine's state to a previously-saved state.
---
--- @tparam context.Context context  The saved state to restore the engine to.
--- @see engine.Engine:context_save
function Engine:context_restore(context)
    return uc_c.context_restore(self.engine_handle_, context.context_handle_)
end

--- Save the engine's current state.
---
--- @tparam[opt] context.Context context  An existing context object to reuse. If not
--- given, a new one is created.
function Engine:context_save(context)
    local raw_context_handle
    if context ~= nil then
        raw_context_handle = context.handle_
    end
    raw_context_handle = uc_c.context_save(self.engine_handle_, raw_context_handle)

    if context == nil then
        return uc_context.Context(self.engine_handle_, raw_context_handle)
    end
    return context
end

function Engine:emu_start(start_addr, end_addr, timeout, n_instructions)
    return uc_c.emu_start(
        self.engine_handle_,
        start_addr,
        end_addr,
        timeout or 0,
        n_instructions or 0
    )
end

function Engine:emu_stop()
    uc_c.emu_stop(self.engine_handle_)
end

--- Get the status code of the last API operation on this engine.
---
--- @treturn int  One of the UC\_ERR\_ constants, like @{unicorn_const.UC_ERR_OK}.
function Engine:errno()
    return uc_c.errno(self.engine_handle_)
end

--- Add a new event hook to the engine.
---
--- The return value is a handle used to keep track of the hook. Unlike contexts, hooks
--- are not removed if the handle is garbage collected.
---
--- @tparam int kind  The type of hook to create. The constants are in @{unicorn_const}
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
function Engine:hook_add(kind, callback, start_address, end_address, udata, ...)
    error("Not implemented yet")
end

--- Remove a hook from the engine.
---
--- @param handle  A hook handle returned from @{Engine:hook_add}.
function Engine:hook_del(handle)
    error("Not implemented yet")
end

---
function Engine:mem_map()
    error("Not implemented yet")
end

function Engine:mem_protect()
    error("Not implemented yet")
end

function Engine:mem_read()
    error("Not implemented yet")
end

function Engine:mem_regions()
    error("Not implemented yet")
end

function Engine:mem_unmap()
    error("Not implemented yet")
end

function Engine:mem_write()
    error("Not implemented yet")
end


--- Get information about an initialized engine, such as its page size, mode flags, etc.
---
--- @tparam int query_flag  Any UC\_QUERY\_* constant like @{unicorn_const.UC_QUERY_MODE}.
---
--- @treturn int    The requested value.
function Engine:query(query_flag)
    return uc_c.query(self.engine_handle_, query_flag)
end

--- Read the current value of a CPU register from the engine.
---
--- @tparam int register  An architecture-specific enum value indicating the register to
--- read. These are found in the const module for the relevant architecture, and are
--- always of the form `UC_<arch>_REG_<reg name>`. For example, @{ppc_const.UC_PPC_REG_CR5}
--- would read the CR5 register from a PowerPC engine. Passing a constant from the wrong
--- architecture has undefined behavior.
---
--- @treturn int  The register's value.
function Engine:reg_read(register)
    error("Not implemented yet")
end

function Engine:reg_read_as()
    error("Not implemented yet")
end

function Engine:reg_read_batch()
    error("Not implemented yet")
end

function Engine:reg_read_batch_as()
    error("Not implemented yet")
end

--- Set the current value of a CPU register in the engine.
---
--- @tparam int register  An architecture-specific enum value indicating the register to
--- write to. The meaning is the same as in @{Engine:reg_read}.
--- @tparam int value  The value to write to the register.
function Engine:reg_write(register, value)
    error("Not implemented yet")
end

function Engine:reg_write_as()
    error("Not implemented yet")
end

function Engine:reg_write_batch()
    error("Not implemented yet")
end


-- These functions are only available in Unicorn 2.x.
local unicorn_major_version = uc_c.version()
if unicorn_major_version >= 2 then
    function Engine:ctl_exits_disable()
        return uc_c.ctl_exits_disable(self.engine_handle_)
    end

    function Engine:ctl_exits_enable()
        return uc_c.ctl_exits_enable(self.engine_handle_)
    end

    function Engine:ctl_flush_tlb()
        return uc_c.ctl_flush_tlb(self.engine_handle_)
    end

    function Engine:ctl_get_arch()
        return uc_c.ctl_get_arch(self.engine_handle_)
    end

    function Engine:ctl_get_cpu_model()
        return uc_c.ctl_get_cpu_model(self.engine_handle_)
    end

    function Engine:ctl_get_exits()
        error("Not implemented yet")
    end

    function Engine:ctl_get_exits_cnt()
        return uc_c.ctl_get_exits_cnt(self.engine_handle_)
    end

    function Engine:ctl_get_mode()
        return uc_c.ctl_get_mode(self.engine_handle_)
    end

    function Engine:ctl_get_page_size()
        error("Not implemented yet")
    end

    function Engine:ctl_get_timeout()
        return uc_c.ctl_get_timeout(self.engine_handle_)
    end

    function Engine:ctl_remove_cache()
        error("Not implemented yet")
    end

    function Engine:ctl_request_cache()
        error("Not implemented yet")
    end

    function Engine:ctl_set_cpu_model()
        error("Not implemented yet")
    end

    function Engine:ctl_set_exits()
        error("Not implemented yet")
    end

    function Engine:ctl_set_page_size()
        error("Not implemented yet")
    end
end


return M
