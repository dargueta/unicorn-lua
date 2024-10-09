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

--- @module context

local uc_c = require("unicorn_c_")

--- An engine context saves the state of an engine so that it can be restored later.
---
--- @type Context
local Context = {}

local M = {
    Context = Context
}

local ContextMeta = {__index = Context}

--- Create an object-oriented wrapper for engine contexts.
---
--- @tparam engine.Engine engine  The engine this context is bound to.
--- @tparam userdata context_handle  A context handle from the C library to wrap. This
--- must not have already been wrapped by a different @{Context} object. Doing so will
--- cause a double free and invalidate the handle while one of these is still active.
---
--- @treturn Context  An object-oriented wrapper for the engine context.
function M.wrap_handle_(engine, context_handle)
    -- We want to hold a weak reference to the engine so that this context laying around
    -- won't prevent it from being collected, but we do need to hold a strong reference to
    -- the handle returned to us by Unicorn. Thus, we need to put the engine into a weak
    -- table instead of directly in the Context object.
    local instance = {
        engine_ref_ = setmetatable({engine = engine}, {__mode = "v"}),
        handle_ = context_handle,
    }

    return setmetatable(instance, ContextMeta)
end


function ContextMeta:__close()
    if self.handle_ ~= nil then
        self:free()
    end
end


function ContextMeta:__gc()
    if self.handle_ ~= nil then
        self:free()
    end
end


--- Deallocate the engine context.
---
--- This releases all underlying resources, so the object must not be used again.
function Context:free()
    if self.handle_ == nil then
        error("Attempted to free the same context twice.")
    end

    -- The engine reference can be nil in two cases: 1) the engine was collected, or 2)
    -- this is a double free. We need to check for a double free first, as that's a user
    -- bug. This is more serious.
    if self.engine_ref_.engine == nil then
        error("BUG: Engine was garbage collected before a context.")
    end

    uc_c.context_free(self.engine_ref_.engine.handle_, self.handle_)
    self.engine_ref_.engine = nil
    self.handle_ = nil
end


return M
