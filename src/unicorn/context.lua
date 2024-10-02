--- @module context

local uc_c = require("unicorn_c_")

local ContextMethods = {}
local ContextMeta = {__index = ContextMethods}

function Context(engine, context_handle)
    if context_handle == nil then
        context_handle = uc_c.context_save(engine)
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