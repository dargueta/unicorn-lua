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

local ContextMethods = {}
local ContextMeta = {__index = ContextMethods}

--- Create a new engine context.
---
--- @tparam engine.Engine engine  The engine this context is bound to.
--- @param[opt] context_handle  A context handle from the C library to wrap. If not given,
--- the engine state will be saved in a new context handle.
function Context(engine, context_handle)
    if context_handle == nil then
        context_handle = uc_c.context_save(engine.engine_handle_)
    end

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
function ContextMethods:free()
    if self.handle_ == nil then
        error("Attempted to free the same context twice.")
    end

    -- The engine reference can be nil in two cases: 1) the engine was collected, or 2)
    -- this is a double free. We need to check for a double free first, as that's a user
    -- bug. This is more serious.
    if self.engine_ref_.engine == nil then
        error("BUG: Engine was garbage collected before a context.")
    end

    uc_c.context_free(self.engine_ref_.engine, self.handle_)
    self.engine_ref_.engine = nil
    self.handle_ = nil
end


return {Context = Context}
