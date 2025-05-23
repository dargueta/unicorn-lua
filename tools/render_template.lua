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

local lapp = require "pl.lapp"
local stringx = require "pl.stringx"
local tablex = require "pl.tablex"
local template = require "pl.template"
local utils = require "pl.utils"


local COPYRIGHT_NOTICE = [[Copyright (C) 2017-2025 by Diego Argueta

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.]]


USAGE = [[
Render a template.

Things to note:
    o The Lua line escape character is `!', not the default `#'. This prevents
      the template engine from mistaking a C/C++ preprocessor directive for a
      line comment. This can be overridden.
    o The inline escape is the default $(...) but can be overridden.
    o The template and values files are executed in a mostly-empty environment,
      except for the following functions and tables:

      - `ipairs()'
      - `pairs()'
      - `string'
      - `stringx' (Penlight package)
      - `tablex' (Penlight package)

Arguments:
    -D... (optional string)
        A string variable to define, either "X" (empty string) or "X=YZ"
        (variable X assigned to "YZ"). Variables defined on the command line
        override values given by the values file.
    -e,--escape (default "!")
        Override the character that escapes a line into Lua.
    -i,--inline-escape (default "$()")
        Override the inline escape form. This must be three characters,
        corresponding to the escape character, the opening bracket, and the
        closing bracket. The brackets should be different characters.
    -o (default stdout)
        The file to write the rendered template to.
    <template>  (string)
        The path to the template file to render.
    <value_files...>  (optional string)
        The paths of one or more Lua files providing variables used to fill the
        template. All globals are passed to the template; any return value is
        discarded. If two files provide values for the same variable, the last
        one passed on the command line prevails.
]]


function main()
    stringx.import()

    local args = lapp(USAGE)
    local environment = {
        ipairs = ipairs,
        pairs = pairs,
        string = string,
        stringx = stringx,
        tablex = tablex,
        copyright_notice = COPYRIGHT_NOTICE,
    }

    for _, file_path in ipairs(args.value_files) do
        load_file(file_path, environment)
    end

    -- Add in variables defined on the command line, overriding anything from
    -- the loaded values file.
    if args.D then
        for _, definition in ipairs(args.D) do
            local name, _sep, contents = stringx.partition(definition, "=")
            environment[name] = contents
        end
    end

    local template_text, err = utils.readfile(args.template, false)
    if err then
        utils.quit(1, "Error opening template file %q: %s", args.template, err)
    end

    environment._escape = args.escape
    environment._inline_escape = string.sub(args.inline_escape, 1, 1)
    environment._brackets = string.sub(args.inline_escape, 2, 3)
    environment._parent = {ipairs = ipairs, pairs = pairs}
    environment._chunk_name = args.template

    local rendered_text, err, _compiled = template.substitute(template_text, environment)
    if err then
        utils.quit(1, "Error rendering template: %s", err)
    end

    args.o:write(rendered_text)
    args.o:close()
end


function load_file(filename, environment)
    local chunk, err, ran, file_contents

    file_contents, err = utils.readfile(filename, false)
    if err then
       utils.quit(1, "Error reading %q: %s", filename, err)
    end

    if _VERSION == "Lua 5.1" then
        chunk, err = loadstring(file_contents, filename)
        if chunk then
            setfenv(chunk, environment)
        end
    else  -- Lua 5.2+
        chunk, err = load(
            file_contents,
            filename,
            "t",
            environment
        )
    end

    if err then
        utils.quit(1, "Error parsing %q: %s", filename, err)
    end

    ran, err = pcall(chunk)
    if err then
        utils.quit(1, "Error executing %q: %s", filename, err)
    end
end

main()
