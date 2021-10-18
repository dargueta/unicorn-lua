
add_rules("mode.debug", "mode.release")

local function checklua(option)
    import("core.project.project")

    local luainc = project.option("LUA_INCDIR")
    if not luainc:enabled() then
        local config = os.iorun 'luarocks config variables'
        if config then
            config = string.deserialize(config)
            luainc:enable(config.LUA_INCDIR)
            project.option("LUA_LIBPATH"):enable(path.join(config.LUA_LIBDIR, config.LUA_LIBDIR_FILE:gsub('%.dll$', ''), nil))
        end
    end
end

option 'LUA_INCDIR'
    set_showmenu(true)
    set_description 'include directory of lua'

    on_check(checklua)

option 'LUA_LIBPATH'
    set_showmenu(true)
    set_description 'lib path of lua'

    on_check(checklua)

option 'UNICORN_DIR'
    set_showmenu(true)
    set_description 'unicorn directory'

target 'unicorn54'
    -- set kind
    set_kind("shared")
    -- add files
    add_files("src/*.cpp")
    add_options('LUA_INCDIR', 'LUA_LIBPATH', 'UNICORN_DIR')

    on_load(function(target)
        local unicorn_dir = target:opt('UNICORN_DIR'):value()
        local archs = {'arm', 'arm64', 'mips', 'm68k', 'sparc', 'x86', 'unicorn'}
        for _, name in ipairs(archs) do
            local cpp_name = 'build/' .. name .. '_const.cpp'
            os.execv('python', {'tools/generate_constants.py', path.join(unicorn_dir, 'include', 'unicorn', name .. '.h'), cpp_name})
            target:add('files', cpp_name)
        end
        target:add('includedirs', path.join(unicorn_dir, 'include'))
        target:add('links', path.join(unicorn_dir, 'unicorn'))
    end)

    add_includedirs 'include'
    add_includedirs('$(LUA_INCDIR)')
    add_links('$(LUA_LIBPATH)')

    add_defines 'UNICORN_SHARED'