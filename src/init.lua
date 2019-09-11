local _uc = require "unicorn._clib"
--local _uc_consts = require "unicorn.unicorn_const"


local _context_metatable = {
    __gc = function (self)
        _uc.ul_free(self.context_handle)
    end,
    __index = {
        update = function (self)
            _uc.ul_context_save(self.engine_handle, self.context_handle)
        end
    }
}


local function _create_context(engine_handle)
    local context_handle = _uc.ul_alloc(engine_handle)
    local object = {
        context_handle = context_handle,
        engine_handle = engine_handle
    }
    setmetatable(object, _context_metatable)

    object:update()
    return object
end


local _engine_methods = {}

-- Add in methods implemented in C to the table we're creating. Most C methods
-- don't need to be wrapped, so we define one table in the C library that contains
-- the unwrapped methods, and merge it with the one we implement here.
--for name, func in pairs(_uc.engine_c_methods) do
--    _engine_methods[name] = func
--end


function _engine_methods:context_restore(context)
    return _uc.ul_context_restore(self.engine_handle, context.context_handle)
end


function _engine_methods:context_save(context)
    if context == nil then
        context = _create_context(self.engine_handle)
    end
    context:update()
    return context
end


function _engine_methods:hook_add(hook_type, start_addr, end_addr, callback, ...)
    local extra_arguments = {...}
    local constructor

    if hook_type == _uc.UC_HOOK_INTR then
        constructor = _uc.ul_create_interrupt_hook
    elseif hook_type == _uc.UC_HOOK_BLOCK
        or hook_type == _uc.UC_HOOK_CODE
    then
        constructor = _uc.ul_create_code_hook
    elseif hook_type == _uc.UC_HOOK_INSN then
        constructor = _uc.ul_create_code_hook
    elseif hook_type == _uc.UC_HOOK_MEM_FETCH
        or hook_type == _uc.UC_HOOK_MEM_READ
        or hook_type == _uc.UC_HOOK_MEM_READ_AFTER
        or hook_type == _uc.UC_HOOK_MEM_WRITE
        or hook_type == _uc.UC_HOOK_MEM_VALID
    then
        constructor = _uc.ul_create_memory_hook
    elseif hook_type == _uc.UC_HOOK_MEM_FETCH_INVALID
        or hook_type == _uc.UC_HOOK_MEM_FETCH_PROT
        or hook_type == _uc.UC_HOOK_MEM_FETCH_UNMAPPED
        or hook_type == _uc.UC_HOOK_MEM_INVALID
        or hook_type == _uc.UC_HOOK_MEM_PROT
        or hook_type == _uc.UC_HOOK_MEM_READ_INVALID
        or hook_type == _uc.UC_HOOK_MEM_READ_PROT
        or hook_type == _uc.UC_HOOK_MEM_READ_UNMAPPED
        or hook_type == _uc.UC_HOOK_MEM_UNMAPPED
        or hook_type == _uc.UC_HOOK_MEM_WRITE_INVALID
        or hook_type == _uc.UC_HOOK_MEM_WRITE_PROT
        or hook_type == _uc.UC_HOOK_MEM_WRITE_UNMAPPED
    then
        constructor = _uc.ul_create_invalid_access_hook
    end

    local callback_wrapper = function (...)
        return callback(self, ...)
    end

    local hook_id = constructor(
        self.engine_handle, start_addr, end_addr, callback_wrapper, extra_arguments
    )
    self.hooks[hook_id] = hook_id
    return hook_id
end


function _engine_methods:hook_del(hook_id)
    if self.hooks[hook_id] == nil then
        return error("Can't remove hook not associated with this engine.")
    end

    _uc.ul_hook_del(self.engine_handle, hook_id)
    self.hooks[hook_id] = nil
end


local _engine_metatable = {
    __gc = function (self)
        for hook_id, _ in pairs(self.hooks) do
            _uc.ul_hook_del(self.engine_handle, hook_id)
        end
        _uc.ul_close(self.engine_handle)
    end,
    __index = _engine_methods
}


local _module_contents = {
    arch_supported = _uc.ul_arch_supported,
    open = function (architecture, mode)
        local engine = {
            engine_handle = _uc.ul_open(architecture, mode),
            hooks = {}
        }
        return setmetatable(engine, _engine_metatable)
    end,
    strerror = _uc.ul_strerror,
    version = _uc.ul_version,
}


-- Merge contents of Unicorn constants into the namespace we're about to return.
-- This lets us autogenerate the constants from the Unicorn header files and also
-- have this.
for name, const in pairs(_uc) do
    _module_contents[name] = const
end


return _module_contents
