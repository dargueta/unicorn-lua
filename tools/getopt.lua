--- Parse the table of arguments using the given options specification.
-- This behaves the same as the `getopt` CLI tool except that it doesn't support
-- grouping short options and there's no support for long options at all.
--
-- There are two return values. The first is a table mapping flags to `true` and
-- options with arguments to the argument's value. (Returned flags include the
-- leading dash.)
-- The second return value is a table with the collected positional arguments in
-- the order they were encountered.
--
-- Short flag options cannot be consolidated, e.g. `-a`, `-b`, and `-c` must be
-- passed separately and not as `-abc`.
function getopt(spec_string, arguments)
    local flag_definitions = parse_option_spec_(spec_string)

    local options = {}
    local positional_arguments = {}

    local i = 1
    while i <= #arguments do
        local this_arg = arguments[i]

        if this_arg == "--" then
            -- `--` signals the end of options and everything from here on must
            -- be considered a positional argument.
            break
        elseif this_arg:sub(1, 1) ~= "-" then
            -- This doesn't start with a - so it must be a positional argument.
            positional_arguments[#positional_arguments + 1] = arguments[i]
        else
            -- This starts with - and isn't -- so it must be a flag.
            local has_argument = flag_definitions[this_arg]
            if has_argument == nil then
                -- No flag definition with this name was found.
                error(
                    string.format(
                        "Unrecognized flag %q as argument #%d",
                        this_arg,
                        i
                    )
                )
            elseif has_argument then
                -- This option has an argument.
                i = i + 1
                local option_value = arguments[i]
                if option_value == nil then
                    -- We hit the end of `arguments` without getting the argument
                    -- that this option takes.
                    error(
                        string.format("Option %q needs an argument", this_arg)
                    )
                end
                options[this_arg] = option_value
            else
                -- The option doesn't have an argument. Set its value to `true`.
                options[this_arg] = true
            end
        end
        i = i + 1
    end

    -- Collect all remaining arguments as positional arguments.
    while i <= #arguments do
        positional_arguments[#positional_arguments + 1] = arguments[i]
        i = i + 1
    end

    return options, positional_arguments
end


--- Get all the defined options from the option specification.
-- An option specification takes the same form used by the short options to the
-- `getopt` command line utility.
--
-- The return value is a table mapping each option character to a boolean
-- indicating if that option requires an argument or not.
function parse_option_spec_(option_spec)
    local options = {}
    local i = 1

    while i <= #option_spec do
        local opt_char = option_spec:sub(i, i)
        local has_argument = option_spec:sub(i + 1, i + 1) == ":"
        options["-" .. opt_char] = has_argument

        if has_argument then
            i = i + 2
        else
            i = i + 1
        end
    end

    return options
end

return {
    getopt = getopt
}
