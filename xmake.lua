
add_rules("mode.debug", "mode.release")
add_requires("lua", {configs = {shared = true}})

if is_os 'windows' then 
    add_requires('vcpkg::unicorn')
end

target 'unicorn54'
    set_kind 'shared'

    add_files 'src/*.cpp'
    add_includedirs 'include'
    add_defines 'UNICORN_SHARED'

    add_packages('lua')

    on_load(function(target)
        local unicorn = find_packages("unicorn")[1]
        assert(unicorn, 'unicorn not found')

        target:add(unicorn)
        local incdir = unicorn.includedirs[1]
        local archs = {'arm', 'arm64', 'mips', 'm68k', 'sparc', 'x86', 'unicorn'}
        local buildir = val('buildir')
        os.mkdir(buildir)

        for _, name in ipairs(archs) do
            local cpp_name = buildir..'/'..name..'_const.cpp'
            if not os.exists(cpp_name) then
                os.execv('python', {'tools/generate_constants.py', path.join(incdir, 'unicorn', name .. '.h'), cpp_name})
            end
            target:add('files', cpp_name)
        end
    end)