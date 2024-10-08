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

pl_file = require "pl.file"
pl_lexer = require "pl.lexer"
pl_path = require "pl.path"
pl_stringx = require "pl.stringx"
pl_tablex = require "pl.tablex"
pl_template = require "pl.template"
pl_utils = require "pl.utils"

pl_stringx.import()


OUTPUT_CPP_TEMPLATE = [[
/** Autogenerated from installed Unicorn header files. DO NOT EDIT.
 *
 * Source: $(header_file)
 *
 * @file $(slug)_const.cpp
 */

#include <unicorn/unicorn.h>
! if slug ~= "unicorn" then
#include <unicorn/$(slug).h>
! end

#include "unicornlua/lua.hpp"
#include "unicornlua/utils.hpp"

static constexpr struct NamedIntConst kConstants[] {
! for name, text in pairs(constants) do
    {"$(name)", $(name)},
! end
    {nullptr, 0}
};

extern "C" UNICORN_EXPORT int luaopen_unicorn_$(slug)_const(lua_State *L) {
    lua_createtable(L, 0, $(pl_tablex.size(constants)));
    load_int_constants(L, kConstants);
    return 1;
}
]]


function main()
    local source_header = arg[1]
    local output_file = arg[2]

    if #arg < 1 or #arg > 2 then
        pl_utils.quit(
            1,
            "USAGE: %s header_file  [output_file]\nIf `output_file` isn't given"
            .. " or is \"-\", stdout is used.\n",
            arg[-1]
        )
    end

    -- Read in the entire file so we can tack on a trailing newline at the end
    -- of the text.
    -- https://github.com/lunarmodules/Penlight/issues/450
    local source_text = pl_file.read(source_header) .. "\n"

    local constants = extract_constants(source_text)
    local source_basename = pl_path.basename(source_header)
    local stem = pl_path.splitext(source_basename)

    local text, render_error = pl_template.substitute(
        OUTPUT_CPP_TEMPLATE,
        {
            _chunk_name = "cpp_template",
            _escape = "!",
            _parent = _G,
            constants = constants,
            header_file = source_header,
            slug = stem,
        }
    )

    if render_error ~= nil then
        pl_utils.quit(1, "%s\n", render_error)
    end

    if output_file == nil or output_file == "-" then
        print(text)
    else
        pl_file.write(output_file, text)
    end
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
            pl_lexer.quit(
                1,
                "Unexpected EOF while processing enum value starting line %d",
                current_lineno
            )
        end
    end
    return constants
end

main()
