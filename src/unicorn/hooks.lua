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

--- @module hooks

local M = {}

local uc_c = require("unicorn_c_")
local uc_const = require("unicorn.unicorn_const")
local have_arm64, arm64_const = pcall(require, "unicorn.arm64_const")
local have_x86, x86_const = pcall(require, "unicorn.x86_const")

if not have_arm64 then arm64_const = {} end
if not have_x86 then x86_const = {} end


local function create_hook_creator_by_name(name)
    return function (engine, callback, start_addr, end_addr, userdata)
        if end_addr == nil then
            if start_addr == nil then
                -- If neither a starting nor ending address is given, the caller wants
                -- this to apply to all of memory. Unicorn uses start_addr > end_addr to
                -- signal this intent.
                start_addr = 1
                end_addr = 0
            else
                -- No ending address is given, assume top of memory. We use -1 because
                -- that has all bits set to 1. When interpreted as an unsigned integer,
                -- it's the highest unsigned value.
                end_addr = -1
            end
        end

        return uc_c[name](
            engine.handle_,
            callback,
            start_addr or 0,
            end_addr,
            userdata
        )
    end
end


local function create_code_hook(engine, callback, start_addr, end_addr, userdata, remaining_args)
    local instruction_id = remaining_args[1]
    if instruction_id == nil then
        error("Can't create instruction hook: no opcode was passed to hook_add().")
    end

    return uc_c.create_code_hook(
        engine,
        callback,
        start_addr or 0,
        end_addr or 0,
        userdata,
        instruction_id
    )
end

local function create_tcg_opcode_hook(engine, callback, start_addr, end_addr, userdata, remaining_args)
    local opcode, flags = table.unpack(remaining_args, 1, 2)

    if opcode == nil then
        error("Can't create TCG hook: no opcode was passed to hook_add().")
    end
    if flags == nil then
        error("Can't create TCG hook: no trap flags were passed to hook_add().")
    end

    return uc_c.create_tcg_opcode_hook(
        engine,
        callback,
        start_addr,
        end_addr,
        userdata,
        opcode,
        flags
    )
end


local create_interrupt_hook = create_hook_creator_by_name("create_interrupt_hook")
local create_memory_access_hook = create_hook_creator_by_name("create_memory_access_hook")
local create_invalid_mem_access_hook = create_hook_creator_by_name("create_invalid_mem_access_hook")
local create_port_in_hook = create_hook_creator_by_name("create_port_in_hook")
local create_port_out_hook = create_hook_creator_by_name("create_port_out_hook")
local create_arm64_sys_hook = create_hook_creator_by_name("create_arm64_sys_hook")
local create_invalid_instruction_hook = create_hook_creator_by_name("create_invalid_instruction_hook")
local create_cpuid_hook = create_hook_creator_by_name("create_cpuid_hook")
local create_generic_hook_with_no_arguments = create_hook_creator_by_name("create_generic_hook_with_no_arguments")
local create_edge_generated_hook = create_hook_creator_by_name("create_edge_generated_hook")


local DEFAULT_HOOK_WRAPPERS = {
    [uc_const.UC_HOOK_BLOCK] = create_code_hook;
    [uc_const.UC_HOOK_CODE] = create_code_hook;
    [uc_const.UC_HOOK_EDGE_GENERATED] = create_edge_generated_hook;
    [uc_const.UC_HOOK_INSN_INVALID] = create_invalid_instruction_hook;
    [uc_const.UC_HOOK_INTR] = create_interrupt_hook;
    [uc_const.UC_HOOK_MEM_FETCH] = create_memory_access_hook;
    [uc_const.UC_HOOK_MEM_FETCH_INVALID] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_FETCH_PROT] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_FETCH_UNMAPPED] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_INVALID] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_PROT] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_READ] = create_memory_access_hook;
    [uc_const.UC_HOOK_MEM_READ_AFTER] = create_memory_access_hook;
    [uc_const.UC_HOOK_MEM_READ_INVALID] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_READ_PROT] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_READ_UNMAPPED] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_UNMAPPED] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_VALID] = create_memory_access_hook;
    [uc_const.UC_HOOK_MEM_WRITE] = create_memory_access_hook;
    [uc_const.UC_HOOK_MEM_WRITE_INVALID] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_WRITE_PROT] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_MEM_WRITE_UNMAPPED] = create_invalid_mem_access_hook;
    [uc_const.UC_HOOK_TCG_OPCODE] = create_tcg_opcode_hook;
}


local INSTRUCTION_HOOK_WRAPPERS = {
    [arm64_const.UC_ARM64_INS_MRS] = create_arm64_sys_hook;
    [arm64_const.UC_ARM64_INS_MSR] = create_arm64_sys_hook;
    [arm64_const.UC_ARM64_INS_SYSL] = create_arm64_sys_hook;
    [arm64_const.UC_ARM64_INS_SYS] = create_arm64_sys_hook;
    [x86_const.UC_X86_INS_CPUID] = create_cpuid_hook;
    [x86_const.UC_X86_INS_IN] = create_port_in_hook;
    [x86_const.UC_X86_INS_OUT] = create_port_out_hook;
    [x86_const.UC_X86_INS_SYSCALL] = create_generic_hook_with_no_arguments;
    [x86_const.UC_X86_INS_SYSENTER] = create_generic_hook_with_no_arguments;
}


--- Create a new hook.
---
--- @tparam engine.Engine engine  The engine to bind the hook to.
--- @tparam int hook_type  The type of hook to create. Allowed codes are defined in
--- @{unicorn_const} and start with `UC_HOOK_`.
--- @tparam function callback  The function to invoke when the hook is triggered.
--- @tparam[opt=0] int start_addr  The lowest address in emulated memory this hook is
--- active for. For instruction hooks, this is the address of the instruction executed.
--- @tparam[opt] int end_addr  The highest address in emulated memory this hook is
--- active for. For instruction hooks, this is the address of the instruction executed. If
--- not given, defaults to the highest possible address.
--- @param[opt] user_extra  Any object to pass as the final argument of the callback.
---
--- Additional arguments may be required, depending on the hook type:
---
--- * @{unicorn_const.UC_HOOK_INSN}: One additional argument is required, an
---   architecture-specific constant indicating which instruction will trigger this hook
---   upon execution. These constants take the form `UC_<arch>_INS_`, e.g.
---   @{x86_const.UC_X86_INS_SYSENTER}.
--- * @{unicorn_const.UC_HOOK_TCG_OPCODE}: Two additional arguments are required:
---
---   * The opcode to trap. This must be a constant from @{unicorn_const} and the names
---     begin with `UC_TCG_OP_` (but not `UC_TCG_OP_FLAG_`; see below).
---   * Flags for refining behavior of instruction trapping. This can be one or more
---     constants OR'ed together. They are found in @{unicorn_const} and the names begin
-----   with `UC_TCG_OP_FLAG_`.
---
--- @treturn userdata  A hook handle.
function M.create_hook(
    engine,
    hook_type,
    callback,
    start_addr,
    end_addr,
    user_extra,
    ...
)
    local wrapper
    if hook_type == uc_const.UC_HOOK_INSN then
        wrapper = INSTRUCTION_HOOK_WRAPPERS[instruction_id] or create_code_hook
    else
        wrapper = DEFAULT_HOOK_WRAPPERS[hook_type]
           or error(string.format("Unrecognized hook type code: %q", hook_type))
    end

    return wrapper(engine, callback, start_addr, end_addr, user_extra, {...})
end

--- Information about the coprocessor, used by ARM64 instruction hooks.
--- @type ARM64Coprocessor
M.ARM64Coprocessor = {
    --- A coprocessor register number.
    --- @field crn

    --- A coprocessor register number.
    ---
    --- Unicorn's documentation for this field consists of half a sentence, so I don't
    --- know what the difference is between this and @{crn}.
    ---
    --- @field crm

    --- Opcode 0.
    --- @field op0

    --- Opcode 1.
    --- @field op1

    --- Opcode 2.
    --- @field op2

    --- Value
    ---
    --- The value of the register being read from or written to.
    ---
    --- @field val
}

--- Information about the coprocessor, used by ARM instruction hooks.
--- @type ARMCoprocessor
M.ARMCoprocessor = {
    --- The coprocessor identifier.
    --- @field cp

    --- Is it a 64 bit control register
    --- @field is64

    --- Security state
    --- @field sec

    --- Coprocessor register number
    --- @field crn

    --- Coprocessor register number
    --- @field crm

    --- Opcode 1
    --- @field opc1

    --- Opcode 2
    --- @field opc2

    --- The value to read/write
    --- @field val
}


--- A data structure containing all information needed by a hook call.
---
--- Because this is the union of all information passed to hooks, not all fields are set
--- for every hook. Indeed, some, like @{arm64_coprocessor} and @{arm_coprocessor} are
--- architecture-specific and thus mutually exclusive.
---
--- @type HookCall
M.HookCall = {
    --- Information about the trapped instruction (ARM64 instruction hooks only).
    --- @field arm64_coprocessor
    --- @see ARM64Coprocessor

    --- Information about the trapped instruction (ARM instruction hooks only).
    --- @field arm_coprocessor
    --- @see ARMCoprocessor

    --- The memory address accessed (memory hooks only).
    --- @field memory_address

    --- The size of the memory accessed during the trapped operation, in bytes.
    ---
    --- If not nil, this is guaranteed to be between 1 and 8, inclusive.
    --- @field memory_access_size

    --- The value being written, for certain operations.
    ---
    --- * Memory access hooks: the value written to memory.
    --- * Instruction hooks: For @{x86_const.UC_X86_INS_OUT}, the value written to the
    ---   port.
    --- @field value

    --- The current transaction block (edge transition hooks only).
    --- @field current_tb

    --- The previous transaction block (edge transition hooks only).
    --- @field previous_tb

    --- The user-defined object passed in when the hook was registered.
    --- @field user_extra
}

return M
