lapp = require "pl.lapp"
stringx = require "pl.stringx"
template = require "pl.template"
utils = require "pl.utils"


USAGE = [[
Render a template.

Things to note:
    o The Lua line escape character is @, not the default #
    o The inline escape is the default $(...)
    o The template and values files are executed in a mostly-empty environment,
      except for the following functions and tables:

      - ipairs
      - pairs
      - string
      - stringx (Penlight package)

Arguments:
    -D... (optional string)
        A string variable to define, either "X" (empty string) or "X=YZ"
        (variable X assigned to "YZ"). Variables defined on the command line
        override values given by the values file.
    -o (default stdout)
        The file to write the rendered template to.
    <template>  (string)
        The path to the template file to render.
    <values>  (optional string)
        The path to a Lua file providing the variables used to fill the template.
        All globals are passed to the template; any return value is discarded.
]]


function main()
    local args = lapp(USAGE)
    local environment = {
        ipairs = ipairs,
        pairs = pairs,
        string = string,
        stringx = stringx,
    }

    if args.values then
        load_file(args.values, environment)
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

    environment._escape = "@"
    environment._parent = {ipairs = ipairs, pairs = pairs}
    environment._chunk_name = "template"

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
