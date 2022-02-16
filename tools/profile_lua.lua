--[[
This script generates some Makefile variables relating to this installation of
Lua. The idea is to run this script using the Lua executable that the library
will be built for, so we can figure out where to install the library, where the
headers are at, etc.

This obviously will not work if we're cross-compiling since the executable will
be on a different machine.
]]

local OUTPUT_FILE = arg[1]


-- The platform string passed in by Make is either:
-- * An empty string (not provided)
-- * A three-part canonical platform tuple, e.g. x86_64-linux-gnu
-- * A four-part platform tuple, e.g. x86_64-pc-linux-gnu
--
-- We want the triplet if possible.
function build_platform_triplet(platform_string)
    local fragments = {}
    for match_text in string.gmatch(platform_string, "([^-]+)") do
        fragments[#fragments + 1] = match_text
    end

    if #fragments == 4 then
        -- Skip over the "company" part
        return fragments[1] .. "-" .. fragments[3] .. "-" .. fragments[4]
    end
    return platform_string
end


local PLATFORM_TRIPLET = build_platform_triplet(arg[2] or "")

function split_string(str, separator)
    if separator == nil then
        separator = "\n"
    end

    local result = {}
    for line in str:gmatch("([^" .. separator .. "]+)") do
        result[#result + 1] = line
    end
    return result
end


--- Return a boolean indicating if the given path can be opened.
function file_exists(file)
    local handle = io.open(file)
    if handle ~= nil then
        io.close(handle)
        return true
    end
    return false
end


-- LuaJIT provides a few additional built-in libraries, "jit" being one of them.
-- We can detect if we're on LuaJIT by checking to see if the "jit" package
-- exists.
local is_luajit = type(jit) == "table"
local lua_version = _VERSION:gsub("^Lua (%d%.%d)$", "%1")

local dir_sep, path_sep, file_wildcard, dir_wildcard
local split_package_config = split_string(package.config, "\n")

if table.unpack then
    -- Lua 5.2+
    dir_sep, path_sep, file_wildcard, dir_wildcard = table.unpack(split_package_config)
else
    -- Lua 5.1
    dir_sep, path_sep, file_wildcard, dir_wildcard = unpack(split_package_config)
end


--- Locate the Lua executable used to run this script.
function find_lua_executable()
    local i = 0

    -- Find the lowest negative index in the arguments. This will give us the
    -- name of the interpreter at index i.
    while arg[i - 1] do i = i - 1 end
    local executable_name = arg[i]

    -- If executable_name exists then it's likely a file path. Whether that path
    -- is absolute or relative is unimportant for this script's purposes.
    if file_exists(executable_name) then
        return executable_name
    end

    -- If `lua` was invoked directly, that means it must be in a directory in
    -- the PATH environment variable. We'll iterate through each directory in
    -- there until we find one. (Thankfully, it's called PATH on *NIX systems as
    -- well as Windows.)
    local path_delimiter
    if is_windows then
        path_delimiter = ";"
    else
        path_delimiter = ":"
    end

    local path = os.getenv("PATH")
    for directory in path:gmatch("([^" .. path_delimiter .. "]+)") do
        local this_path = directory .. dir_sep .. executable_name
        if file_exists(this_path) then
            return this_path
        end
    end

    -- Couldn't find the path to the executable.
    return nil
end


-- The Lua docs state that the default directory separator is \ on Windows and /
-- everywhere else. This is a crude way of detecting the OS, assuming the defaults
-- weren't overridden when Lua was built.
local is_windows = dir_sep == "\\"


--- Return everything but the last component of the given path.
-- Equivalent to os.path.dirname() on Python.
function dirname(path)
    local filename = basename(path)
    if filename == path then
        return path
    end
    return path:sub(1, -(#filename + #dir_sep + 1))
end


--- Return the last component of the given path.
-- Equivalent to os.path.basename() in Python.
function basename(path)
    local last_part
    for component in path:gmatch("([^" .. dir_sep .. "]+)") do
        last_part = component
    end
    return last_part or path
end


local lua_exe = find_lua_executable() or ""
local lua_exe_dir = dirname(lua_exe)

--- Fallback directories to search through on *NIX systems for Lua's header files.
-- The `<file>` will be replaced with either the name of an expected header file
-- or the path to a subdirectory. `!` is replaced with the path to the Lua
-- executable's directory.
local POSIX_HEADER_SEARCH_DIRECTORIES = {
    "!/../include/<file>",
    "/usr/include/<file>",
    "/usr/local/include/<file>",
    "/opt/include/<file>",
    "/opt/<file>/include",
}

-- TODO (dargueta): Add more search directories, e.g. C:\Lua54 or C:\Lua5.4
local WINDOWS_HEADER_SEARCH_DIRECTORIES = {
    "!\\<file>",
    "!\\..\\<file>",
    "!\\..\\include\\<file>",
}

local LIB_DIRECTORY_NAMES = {
    "lib", "lib64", "lib32", "libx32",
}

local POSIX_LIBRARY_SEARCH_DIRECTORIES = {
    -- "exe_dir" is the directory the Lua executable is in.
    -- "<lib_dirname>" is the library directory name, e.g. "lib" or "lib64"
    -- "<file>" is the name of the file to look for
    "<exe_dir>/../<lib_dirname>/<file>",
    "/<lib_dirname>/<file>",
    "/usr/<lib_dirname>/<file>",
    "/usr/local/<lib_dirname>/<file>",
    "/usr/lib/" .. PLATFORM_TRIPLET .. "/<file>",
}

local WINDOWS_LIBRARY_SEARCH_DIRECTORIES = {
    "<exe_dir>\\<file>",
    "<exe_dir>\\..\\<file>",
    "<exe_dir>\\..\\<lib_dirname>\\<file>",
}

--- Attempt to find the directory where Lua's header files are installed.
-- @return The directory where the Lua headers are located, or nil if it can't
--         be found.
function find_headers()
    -- On *NIX systems, the most likely installation path is
    -- <lua-exe-dir>/../include/lua<version> e.g. /usr/include/lua5.4 for a
    -- system-wide installation of Lua 5.4, assuming the executable is located
    -- in /usr/bin.
    --
    -- We do this first instead of looking in the usual POSIX directories because
    -- Lua may be installed in a nonstandard location (e.g. if we're using a
    -- virtual environment).
    --
    -- As for Windows, we'll give it a shot but there's no guarantee this will
    -- be where the headers were installed.
    local include_base_dir = dirname(lua_exe_dir) .. dir_sep .. "include"
    local lua_include_dir = include_base_dir .. dir_sep .. "lua" .. lua_version

    -- A list of all the directories we're going to search. ORDER IS IMPORTANT.
    local to_search = {
        include_base_dir .. dir_sep .. "lauxlib.h",
        lua_include_dir .. dir_sep .. "lauxlib.h",
    }

    if is_luajit then
        -- The LuaJIT headers are in a subdirectory based on the name of the
        -- version of LuaJIT, not the version of Lua it implements.
        -- FIXME (dargueta): Detect the version of LuaJIT we're using
        -- This is hard-coded to 2.0 but will stop working correctly if/when
        -- LuaJIT 2.1 is released.
        to_search[#to_search + 1] =
            include_base_dir .. dir_sep .. "luajit-2.0" .. dir_sep .. "lauxlib.h"
        to_search[#to_search + 1] =
            lua_include_dir .. dir_sep .. "luajit-2.0" .. dir_sep .. "lauxlib.h"
    end

    local dir_templates
    if is_windows then
        dir_templates = WINDOWS_HEADER_SEARCH_DIRECTORIES
    else
        dir_templates = POSIX_HEADER_SEARCH_DIRECTORIES
    end

    for _, directory in ipairs(dir_templates) do
        -- Try to find lauxlib.h in this directory
        local expected_header = directory:gsub("<file>", "lauxlib.h")
        to_search[#to_search + 1] = expected_header

        if is_luajit then
            -- Same notes here as earlier
            expected_header = directory:gsub(
                "<file>", "luajit-2.0" .. dir_sep .. "lauxlib.h"
            )
            to_search[#to_search + 1] = expected_header
        else
            expected_header = directory:gsub(
                "<file>", "lua" ..  lua_version .. dir_sep .. "lauxlib.h"
            )
            to_search[#to_search + 1] = expected_header
        end
    end

    -- Now actually do the searching.
    for _, path in ipairs(to_search) do
        -- Substitute the path to the directory containing the Lua executable
        -- into the placeholder. Note that we enclose the wildcard in [] to
        -- prevent Lua from interpreting it as a regex character.
        path = path:gsub("[" .. dir_wildcard .. "]", lua_exe_dir)

        print("# DEBUG: Checking for header: ", path)
        if file_exists(path) then
            return dirname(path)
        end
    end

    -- Can't find it at all.
    print("# ERROR: Can't find the Lua headers anywhere.")
    return nil
end


function find_package_directory(path_list_string, extension)
    local search_paths = split_string(path_list_string, path_sep)
    local target_path
    for _, path in ipairs(search_paths) do
        -- Ignore ".\?.dll" on Windows, "./?.so" everywhere else.
        if path ~= "." .. dir_sep .. file_wildcard .. extension then
            -- Found our installation path. Strip off the wildcard and extension
            -- to get the directory.
            target_path = dirname(path)
            break
        end
    end

    -- If we're on Windows, the library path may contain a reference to the
    -- directory the Lua executable is located in. We need to replace this with
    -- the actual path.
    if is_windows and target_path:find(dir_wildcard, 1, true) then
        -- Substitute the path to the Lua executable into the placeholder. Note
        -- that we enclose the wildcard in [] to prevent Lua from interpreting
        -- it as a regex character.
        return target_path:gsub("[" .. dir_wildcard .. "]", lua_exe_dir)
    end
    return target_path
end


function find_lua_library()
    local potential_file_prefixes = {"lib", ""}
    local potential_file_extensions = {".a", ".lib", ".so", ".dll"}
    local potential_file_stems

    if is_luajit then
        potential_file_stems = {"luajit-5.1"}
    else
        potential_file_stems = {"lua" .. lua_version}
    end

    local to_search = {}
    local search_templates
    if is_windows then
        search_templates = WINDOWS_LIBRARY_SEARCH_DIRECTORIES
    else
        search_templates = POSIX_LIBRARY_SEARCH_DIRECTORIES
    end

    for _, directory in ipairs(search_templates) do
        for _, lib_dir_name in ipairs(LIB_DIRECTORY_NAMES) do
            for _, prefix in ipairs(potential_file_prefixes) do
                for _, ext in ipairs(potential_file_extensions) do
                    for _, stem in ipairs(potential_file_stems) do
                        local filename = prefix .. stem .. ext
                        local path = directory:gsub("<file>", filename)
                        path = path:gsub("<lib_dirname>", lib_dir_name)
                        path = path:gsub("<exe_dir>", lua_exe_dir)
                        to_search[#to_search + 1] = {
                            path = path,
                            stem = stem,
                        }
                    end
                end
            end
        end
    end

    -- Now actually do the searching.
    for _, path_info in ipairs(to_search) do
        print("# DEBUG: Checking for file: ", path_info.path)
        if file_exists(path_info.path) then
            return path_info
        end
    end

    -- Can't find it at all.
    print("# ERROR: Can't find the Lua library anywhere.")
    return {}
end


local c_library_extension
if is_windows then
    c_library_extension = ".dll"
else
    c_library_extension = ".so"
end


local c_library_dir = find_package_directory(package.cpath, c_library_extension)
local lua_library_dir = find_package_directory(package.path, ".lua")
local lua_library_file_info = find_lua_library()

local link_flag = ""
if lua_library_file_info then
    -- FIXME (dargueta): This only works for GCC and GCC-compatible compilers
    link_flag = "-l" .. lua_library_file_info.stem
end


-- Output the same variables that LuaRocks does, using ?= for assignment so that
-- we don't override any variables that have already been provided elsewhere,
-- e.g. from the command line or environment variables.
io.output(OUTPUT_FILE)
io.write("# The directory where the Lua static library is installed.\n")
io.write("LUA_LIBDIR ?= " .. dirname(lua_library_file_info.path or "") .. "\n")
io.write("# The directory where the Lua executable is located.\n")
io.write("LUA_BINDIR ?= " .. lua_exe_dir .. "\n")
io.write("# The directory where the Lua headers are.\n")
io.write("LUA_INCDIR ?= " .. (find_headers() or "") .. "\n")
io.write("# The filename of the Lua library, not always provided.\n")
io.write("LUALIB ?= " .. basename(lua_library_file_info.path or "") .. "\n")
io.write("# The Lua executable.\n")
io.write("LUA ?= " .. (lua_exe or "lua") .. "\n")
io.write("# The installation prefix.\n")
-- TODO (dargueta): Figure out this installation prefix thing
io.write("INST_PREFIX ?= \n")
io.write("# The directory where executable Lua scripts go.\n")
io.write("INST_BINDIR ?= $(LUA_BINDIR)\n")
io.write("# The directory where Lua C libraries go.\n")
io.write("INST_LIBDIR ?= " .. c_library_dir .. "\n")
io.write("# The directory where Lua script libraries go.\n")
io.write("INST_LUADIR ?= " .. lua_library_dir .. "\n")
io.write("# The directory where configuration files go.\n")
io.write("INST_CONFDIR ?= \n")
io.write("# The flag to pass to the linker for linking to Lua\n")
io.write("BUILD_LIBFLAG ?= " .. link_flag .. "\n")

-- Other stuff
io.write("LUA_SHORT_VERSION := " .. lua_version .. "\n")
io.write("LIBRARY_FILE_EXTENSION := " .. c_library_extension .. "\n")
if is_luajit then
    io.write("IS_LUAJIT := 1\n")
else
    io.write("IS_LUAJIT := 0\n")
end
if is_windows then
    io.write("IS_WINDOWS := 1\n")
else
    io.write("IS_WINDOWS := 0\n")
end

io.close()
