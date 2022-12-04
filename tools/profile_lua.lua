--[=[
This script generates some Makefile variables relating to this installation of
Lua. The idea is to run this script using the Lua executable that the library
will be built for, so we can figure out where to install the library, where the
headers are at, etc.

This obviously will not work if we're cross-compiling since the executable will
be on a different machine.
________________________________________________________________________________
Invocation:

    profile_lua.lua [-f "make" | "cmake"] [-p platform-string] [-r luarocks-path]
                    [-l lua_exe ] output_file
]=]

local getopt = require "tools.getopt"

local OPTIONS, POSARGS = getopt.getopt("f:o:p:r:l:", arg)

local OUTPUT_FILE = OPTIONS["-o"] or POSARGS[1]
local OUTPUT_FORMAT = OPTIONS["-f"] or "make"
local RAW_PLATFORM_STRING = OPTIONS["-p"] or ""
local LUAROCKS_PATH = OPTIONS["-r"]
local LUA_EXE = OPTIONS["-l"]


--- Given a platform identifier string from Make, return the three-part representation.
--
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
        platform_string = fragments[1] .. "-" .. fragments[3] .. "-" .. fragments[4]
    end
    return platform_string
end


--- Split a string along occurrences of a separator.
-- Multiple consecutive separators are treated as one.
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

-- Lua 5.2 moved `unpack()` into the `table` library.
local unpack_table = table.unpack or _G.unpack

-- LuaJIT provides a few additional built-in libraries, "jit" being one of them.
-- We can detect if we're on LuaJIT by checking to see if the "jit" package
-- exists.
local is_luajit = type(_G.jit) == "table"
local lua_version = _VERSION:gsub("^Lua (%d+%.%d+)$", "%1")

local dir_sep, path_sep, file_wildcard, dir_wildcard
local split_package_config = split_string(package.config, "\n")

dir_sep, path_sep, file_wildcard, dir_wildcard = unpack_table(split_package_config)

-- The Lua docs state that the default directory separator is \ on Windows and /
-- everywhere else. This is a crude way of detecting the OS, assuming the defaults
-- weren't overridden when Lua was built.
local is_windows = dir_sep == "\\"

-- A three-part string indicating the CPU architecture, operating system, and
-- ABI, with parts separated by a single dash: e.g. "x86_64-linux-gnu".
local PLATFORM_TRIPLET = build_platform_triplet(RAW_PLATFORM_STRING)


--- Determine if the given path is absolute or not.
function is_abspath(path)
    if is_windows then
        return path:match("^%w:\\.*$") or path:match("^\\\\%w+\\$")
    end
    return path:match("^/.*$")
end


--- Locate the Lua executable used to run this script.
function find_lua_executable()
    local i = 0

    -- Find the lowest negative index in the arguments. This will give us the
    -- name of the interpreter at index i.
    while arg[i - 1] do i = i - 1 end
    local lua = arg[i]

    if is_abspath(lua) then
        print("Lua executable: " .. lua)
        return lua
    end

    local path_delimiter
    local current_directory

    if is_windows then
        path_delimiter = ";"
        current_directory = os.getenv("CD")
    else
        path_delimiter = ":"
        current_directory = io.popen("pwd"):read("*l")
    end

    -- Seach the current directory first.
    local full_path = current_directory .. dir_sep .. lua
    if file_exists(full_path) then
        print("Lua executable: " .. full_path)
        return full_path
    end

    -- Item not found, try searching in directories in the PATH environment
    -- variable.
    local path = os.getenv("PATH")
    for directory in path:gmatch("([^" .. path_delimiter .. "]+)") do
        local full_path = directory .. dir_sep .. lua
        if file_exists(full_path) then
            print("Lua executable: " .. full_path)
            return full_path
        end
    end

    print(
        string.format(
            "WARNING: Can't determine absolute path to Lua from arg[%d]: %q",
            i,
            lua
        )
    )
    return nil
end


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


local lua_exe = LUA_EXE or find_lua_executable() or ""
local lua_exe_dir = dirname(lua_exe)

if lua_exe_dir == "" then
    error(
        "Couldn't infer directory containing Lua executable: `" .. lua_exe
        .. "`. This is needed for determining the rest of the system paths."
    )
end

-- Substitute the path to the directory containing the Lua executable
-- into the placeholder. Note that we enclose the wildcard in [] to
-- prevent Lua from interpreting it as a regex character.
function fill_wildcard(s)
    return s:gsub("[" .. dir_wildcard .. "]", lua_exe_dir)
end

--- Fallback directories to search through on *NIX systems for Lua's header files.
-- The `<file>` will be replaced with either the name of an expected header file
-- or the path to a subdirectory. `!` is replaced with the path to the Lua
-- executable's directory.
local POSIX_HEADER_SEARCH_DIRECTORIES = {
    dir_wildcard .. "/../include/<file>",
    dir_wildcard .. "/include/<file>",
    "/usr/include/<file>",
    "/usr/local/include/<file>",
    "/opt/include/<file>",
    "/opt/<file>/include",
}

-- TODO (dargueta): Add more search directories, e.g. C:\Lua54 or C:\Lua5.4
local WINDOWS_HEADER_SEARCH_DIRECTORIES = {
    dir_wildcard .. "\\<file>",
    dir_wildcard .. "\\..\\<file>",
    dir_wildcard .. "\\..\\include\\<file>",
}

local LIB_DIRECTORY_NAMES = {
    "lib", "lib64", "lib32", "libx32",
}

local POSIX_LIBRARY_SEARCH_DIRECTORIES = {
    -- "!" is the directory the Lua executable is in.
    -- "<lib_dirname>" is the library directory name, e.g. "lib" or "lib64"
    -- "<file>" is the name of the file to look for
    dir_wildcard .. "/../<lib_dirname>/<file>",
    "/<lib_dirname>/<file>",
    "/usr/<lib_dirname>/<file>",
    "/usr/local/<lib_dirname>/<file>",
    "/usr/<lib_dirname>/" .. PLATFORM_TRIPLET .. "/<file>",
}

local WINDOWS_LIBRARY_SEARCH_DIRECTORIES = {
    dir_wildcard .. "\\<file>",
    dir_wildcard .. "\\..\\<file>",
    dir_wildcard .. "\\..\\<lib_dirname>\\<file>",
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
        to_search[#to_search + 1] = fill_wildcard(expected_header)

        if is_luajit then
            -- Same notes here as earlier about the LuaJIT path difference
            expected_header = directory:gsub(
                "<file>", "luajit-2.0" .. dir_sep .. "lauxlib.h"
            )
            to_search[#to_search + 1] = fill_wildcard(expected_header)
        else
            expected_header = directory:gsub(
                "<file>", "lua" ..  lua_version .. dir_sep .. "lauxlib.h"
            )
            to_search[#to_search + 1] = fill_wildcard(expected_header)
        end
    end

    -- Now actually do the searching.
    for _, path in ipairs(to_search) do
        if file_exists(path) then
            print("Header directory: " .. dirname(path))
            return dirname(path)
        end
    end

    -- Can't find it at all.
    local search_path = ""
    for _, path in ipairs(to_search) do
        search_path = search_path .. "\n* " .. dirname(path)
    end
    error("Can't find the Lua headers; searched in" .. search_path)
    -- return nil
end


function find_package_directory(path_list_string, extension)
    local search_paths = split_string(path_list_string, path_sep)
    local target_path
    for _, path in ipairs(search_paths) do
        -- Ignore ".\?.dll" on Windows, "./?.so" everywhere else.
        if path ~= "." .. dir_sep .. file_wildcard .. extension then
            -- Found our installation path. Strip off the wildcard and extension
            -- to get the directory.
            path = dirname(fill_wildcard(path))
            print("Package directory: " .. path)
            return path
        end
    end
    return nil
end


function find_lua_library()
    local potential_file_prefixes = {"lib", ""}
    local potential_file_extensions = {".a", ".lib", ".so", ".dll"}
    local potential_file_stems

    if is_luajit then
        potential_file_stems = {"luajit-5.1"}
    else
        -- On some installations we will only have liblua.a with no version number.
        -- We put this second so it's a last resort.
        potential_file_stems = {"lua" .. lua_version, "lua"}
    end

    local to_search = {}
    local search_templates
    if is_windows then
        search_templates = WINDOWS_LIBRARY_SEARCH_DIRECTORIES
    else
        search_templates = POSIX_LIBRARY_SEARCH_DIRECTORIES
    end

    for _, stem in ipairs(potential_file_stems) do
        for _, directory in ipairs(search_templates) do
            for _, lib_dir_name in ipairs(LIB_DIRECTORY_NAMES) do
                for _, prefix in ipairs(potential_file_prefixes) do
                    for _, ext in ipairs(potential_file_extensions) do
                        local filename = prefix .. stem .. ext
                        local path = directory:gsub("<file>", filename)
                        path = path:gsub("<lib_dirname>", lib_dir_name)
                        path = fill_wildcard(path)
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
        if file_exists(path_info.path) then
            print("Lua library: " .. path_info.path)
            return path_info
        end
    end

    -- Can't find it at all.
    local search_path = ""
    for _, path_info in ipairs(to_search) do
        search_path = search_path .. "\n* " .. path_info.path
    end
    error("Can't find the Lua library; searched in" .. search_path)
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
if lua_library_file_info.stem ~= nil then
    -- FIXME (dargueta): This only works for GCC and GCC-compatible compilers
    link_flag = "-l" .. lua_library_file_info.stem
end

local VARIABLES = {
    { "LUA_LIBDIR", dirname(lua_library_file_info.path or "") },
    -- The directory where the Lua executable is located.
    { "LUA_BINDIR", lua_exe_dir },
    -- The directory where the Lua headers are.
    { "LUA_INCDIR", find_headers() or "" },
    -- The filename of the Lua library, not always provided.
    { "LUALIB", basename(lua_library_file_info.path or "") },
    -- The Lua executable.
    { "LUA", lua_exe or "lua" },
    -- The installation prefix.
    -- TODO (dargueta): Figure out this installation prefix thing
    { "INST_PREFIX", "" },
    -- The directory where executable Lua scripts go.
    { "INST_BINDIR", lua_exe_dir },
    -- The directory where Lua C libraries go.
    { "INST_LIBDIR", c_library_dir },
    -- The directory where Lua script libraries go.
    { "INST_LUADIR", lua_library_dir },
    -- The directory where configuration files go.\n")
    { "INST_CONFDIR", "" },
    -- The flag to pass to the linker for linking to Lua\n")
    -- { "BUILD_LIBFLAG", link_flag },

    -- Other stuff
    { "LUA_SHORT_VERSION", lua_version },
    { "LIBRARY_FILE_EXTENSION", c_library_extension },
    { "IS_LUAJIT", is_luajit },
    { "IS_WINDOWS", is_windows },
    { "LUAROCKS", LUAROCKS_PATH or ""},
}

-- Output the same variables that LuaRocks does, using ?= for assignment so that
-- we don't override any variables that have already been provided elsewhere,
-- e.g. from the command line or environment variables.
io.output(OUTPUT_FILE)

if OUTPUT_FORMAT == "make" then
    for _, variable_pair in ipairs(VARIABLES) do
        local key, value = unpack_table(variable_pair)
        if value == true then
            value = "1"
        elseif value == false then
            value = "0"
        end
        io.write(key .. " ?= " .. tostring(value) .. "\n")
    end
elseif OUTPUT_FORMAT == "cmake" then
    for _, variable_pair in ipairs(VARIABLES) do
        local key, value = unpack_table(variable_pair)
        if value == true then
            value = "1"
        elseif value == false then
            value = "0"
        end
        io.write("set(" .. key .. ' "' .. tostring(value) .. '")\n')
    end
elseif OUTPUT_FORMAT == "json" then
    io.write("{\n")
    for i, variable_pair in ipairs(VARIABLES) do
        local key, value = unpack_table(variable_pair)
        if value == true then
            value = "1"
        elseif value == false then
            value = "0"
        end
        io.write(string.format("  %q: %q", key, value))
        if i < #VARIABLES then
            io.write(",\n")
        end
    end
    io.write("\n}\n")
else
    error("Unrecognized output file format: " .. OUTPUT_FORMAT)
end

io.close()
