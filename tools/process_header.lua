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

lapp = require "pl.lapp"
pl_file = require "pl.file"
pl_lexer = require "pl.lexer"
pl_path = require "pl.path"
pl_pretty = require "pl.pretty"
pl_stringx = require "pl.stringx"
pl_utils = require "pl.utils"

pl_stringx.import()


USAGE = [[
Parse a C header file and extract all defined constants.

The output of the script is valid Lua file, with the following key-value pairs:

    * constants:
        A sequence table with the names of all enum values and non-function
        macros extracted from the header file. Only those beginning with "UC_"
        (case-insensitive) are selected.
    * source_header:
        The path to the file that was processed, as it was passed in on the
        command line.
    * source_basename:
        The basename of the file that was processed. For "/usr/include/blah.h",
        this would be "blah.h".
    * source_stem:
        The stem of the name of the file that was processed. For
        "/usr/include/blah.h", this would be "blah".

--missing-ok
    If `header_file` doesn't exist, don't throw an error. Instead, behave as if
    it were just an empty file.

<header_file> (string)
    The path to the header file to read.
<output_file> (default stdout)
    A file to write the extracted constants and other information to.
]]


function main()
    local args = lapp(USAGE)

    local source_basename = pl_path.basename(args.header_file)
    local output_text = string.format(
        "source_header = %q\nsource_basename = %q\nsource_stem = %q\nconstants = ",
        args.header_file,
        source_basename,
        pl_path.splitext(source_basename)
    )

    local constants = {}
    if pl_path.exists(args.header_file) then
        -- Read in the entire file so we can tack on a trailing newline at the
        -- end of the text.
        -- https://github.com/lunarmodules/Penlight/issues/450
        local source_text = pl_file.read(args.header_file) .. "\n"
        constants = extract_constants(source_text)
    elseif not args.missing_ok then
        pl_utils.quit(1, "Source file not found: %s", args.header_file)
    end

    args.output_file:write(output_text)
    args.output_file:write(pl_pretty.write(constants) .. "\n")
end


function extract_constants(source)
    local tokenizer = pl_lexer.cpp(source)
    local constants = {}
    local ttype, value = tokenizer()

    while ttype ~= nil do
        local extracted

        if ttype == "prepro" then
            extracted = maybe_extract_preprocessor(value)
        elseif ttype == "keyword" and value == "enum" then
            -- Enum declaration to follow
            extracted = maybe_extract_enum(tokenizer)
        end

        if extracted ~= nil then
            for name, text in pairs(extracted) do
                -- If a definition for the macro already exists, ignore the new
                -- one. It most likely is due to a #if ... #elif ... block that
                -- we're not interpreting.
                if constants[name] == nil then
                    constants[name] = text
                end
            end
        end

        ttype, value = tokenizer()
        extracted = nil
    end

    return constants
end


function maybe_extract_preprocessor(text)
    local parts = text:split()
    -- We know the first part is "#define". After that come the identifier and
    -- whatever the expansion of the macro is, if applicable.
    local directive = parts[1]
    local macro_name = parts[2]
    local macro_text = parts[3]

    if directive == "#define"
        and macro_name:startswith("UC_")
        and not macro_name:gmatch("^%w%(")  -- Ignore function macros
        and macro_text ~= nil
        and macro_text ~= ""
    then
        -- FIXME (dargueta): Ensure that `macro_text` can be evaluated as an integer
        return {[macro_name] = macro_text}
    end
    return {}
end


function maybe_extract_enum(tokenizer)
    -- The tokenizer is positioned immediately after the `enum` keyword. The
    -- next token in the stream will either be the name of the enum, or `{`
    -- if this is of the form `typedef enum { ... } XYZ`.
    local ttype, text

    local start_lineno = pl_lexer.lineno(tokenizer)
    -- `tok` is either the name of the enum or `{`.
    repeat
        ttype, text = tokenizer()
        if ttype == nil then
            local current_line = pl_lexer.lineno(tokenizer)
            pl_utils.quit(
                1,
                "Unexpected EOF on line %d, expected `{` on or near line %d",
                current_line,
                start_lineno
            )
        end
    until ttype == "{"

    local constants = {}

    -- The general structure we're expecting is
    -- IDENTIFIER [expression] ("," | "}")
    -- For this application we can probably get away with completely ignoring
    -- `expression` entirely, i.e. consuming the identifier and then discarding
    -- tokens until we reach a comma. This'll misbehave if, for example, there's
    -- a macro call as the value, but this is unlikely.
    while ttype ~= "}" do
        local current_lineno = pl_lexer.lineno(tokenizer)

        ttype, text = tokenizer()
        if ttype == "}" then
            return constants
        elseif ttype ~= "iden" then
            pl_utils.quit(
                1,
                "Expected identifier on line %s",
                tostring(current_lineno)
            )
        end

        constants[text] = text

        -- Skip everything until we hit a comma that ends the current item
        -- definition, or "}" which indicates the end of the enum.
        while ttype ~= "," and ttype ~= "}" and ttype ~= nil do
            ttype, text = tokenizer()
        end
        if ttype == nil then
            pl_utils.quit(
                1,
                "Unexpected EOF while processing enum value starting line %d",
                current_lineno
            )
        end
    end
    return constants
end

main()
