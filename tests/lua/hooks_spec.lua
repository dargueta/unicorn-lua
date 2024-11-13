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

local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'
local x86 = require 'unicorn.x86_const'
local pl_pretty = require "pl.pretty"
local pl_tablex = require "pl.tablex"
local pl_utils = require "pl.utils"


function assert_argument_count(argv, expected_count)
  if #argv == expected_count then
    return
  end

  local emsg = string.format(
    "Bad number of arguments; expected %d, got %d;\n%s",
      expected_count,
      #argv,
      pl_pretty.write(argv)
  )
  error(emsg)
end

describe('Hook tests', function ()
  it('[x86] Catch valid memory read', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
    uc:mem_map(0, 2^20)

    local callback = spy.new(
      function (...)
        local argv = {...}
        -- There are six arguments to the function, but `userdata` should be nil. Trailing
        -- nil arguments get clipped, so in this case we only receive five.
        assert_argument_count(argv, 5)

        local engine, access_type, address, size, value, userdata = pl_utils.unpack(argv)
        assert.are.equals(uc, engine)
        assert.are.equal(uc_const.UC_MEM_READ_AFTER, access_type)
        assert.are.equal(0x12345, address)
        assert.are.equal(4, size)
        assert.are.equal(0xabababab, value)
        assert.are.equals(nil, userdata)

        engine:emu_stop()
      end)

    local handle = uc:hook_add(uc_const.UC_HOOK_MEM_READ_AFTER, callback, 0, 2^20)
    assert.not_nil(handle)
    -- Ensure the hook has been recorded in the engine's internal table.
    assert.are.equal(1, pl_tablex.size(uc.hooks_))

    -- mov eax, DWORD [0x12345]
    uc:mem_write(0, '\161\069\035\001\000')
    uc:mem_write(0x12340, string.rep('\171', 64))

    uc:emu_start(0, 2^20, 0, 1)
    assert.spy(callback).was_called()

    uc:hook_del(handle)
    -- Ensure the hook has been removed from the engine's internal table.
    assert.are.equal(0, pl_tablex.size(uc.hooks_))
  end)

  it('[x86] Catch port read', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
    uc:mem_map(0, 2^20)

    local callback = spy.new(
      function (...)
        local argv = {...}
        assert_argument_count(argv, 3)

        local engine, port, size, userdata = pl_utils.unpack(argv)
        assert.are.equals(uc, engine)
        assert.are.equal(0x80, port)
        assert.are.equal(4, size)
        assert.are.equals(nil, userdata)
        return 0xdeadbeef
      end)

    local handle = uc:hook_add(uc_const.UC_HOOK_INSN, callback, 0, 2^20, nil,
                               x86.UC_X86_INS_IN)
    assert.not_nil(handle)

    -- in  eax, 0x80
    uc:mem_write(0, '\229\128')
    uc:emu_start(0, 2^20, 0, 1)
    uc:emu_stop()

    assert.are.equals(0xdeadbeef, uc:reg_read(x86.UC_X86_REG_EAX))
    assert.spy(callback).was_called()
  end)

  it('[x86] Handle interrupt call', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_16)
    uc:mem_map(0, 2^20)

    local callback = spy.new(
      function (...)
        local argv = {...}
        assert_argument_count(argv, 2)

        local engine, intno, userdata = pl_utils.unpack(argv)
        assert.are.equals(uc, engine)
        assert.are.equals(nil, userdata)
        assert.are.equals(0xff, intno)
        assert.are.equals(0x55aa, uc:reg_read(x86.UC_X86_REG_AX))
        uc:reg_write(x86.UC_X86_REG_AX, 0xaa55)
      end)

    uc:hook_add(uc_const.UC_HOOK_INTR, callback)

    -- mov ax, 0x55aa
    -- int 0xff
    uc:mem_write(0x7c000, '\184\170\085\205\255')
    uc:emu_start(0x7c000, 0x7c005)
    uc:emu_stop()

    assert.spy(callback).was_called()
    assert.are.equals(0xaa55, uc:reg_read(x86.UC_X86_REG_AX), 'AX not written to')
  end)

  it('[x86] Passing scalar user data', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_16)
    uc:mem_map(0, 2^20)

    local register_id = x86.UC_X86_REG_ES
    local callback = spy.new(
      function (...)
        local argv = {...}
        assert_argument_count(argv, 3)

        local engine, intno, userdata = pl_utils.unpack(argv)
        assert.are.equals(uc, engine)
        assert.are.equals(0xff, intno)
        assert.are.equals(register_id, userdata)
        assert.are.equals(0xdead, uc:reg_read(userdata))
        uc:reg_write(userdata, 0xf00d)
      end)

    uc:hook_add(uc_const.UC_HOOK_INTR, callback, nil, nil, register_id)

    -- int 0xff
    uc:mem_write(0x7c000, '\205\255')
    uc:reg_write(register_id, 0xdead)
    uc:emu_start(0x7c000, 0x7c002)
    uc:emu_stop()

    assert.spy(callback).was_called()
    assert.are.equals(0xf00d, uc:reg_read(register_id), 'Register not written to')
  end)

  it('[x86] Passing tables as user data', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_16)
    uc:mem_map(0, 2^20)

    local info = {x86.UC_X86_REG_ES}
    local callback = spy.new(
      function (...)
        local argv = {...}
        assert_argument_count(argv, 3)

        local engine, intno, userdata = pl_utils.unpack(argv)
        assert.are.equals(uc, engine)
        assert.are.equals(0xff, intno)
        assert.are.equals(info, userdata)
        assert.are.equals(0xdead, uc:reg_read(userdata[1]))
        uc:reg_write(userdata[1], 0xf00d)
      end)

    uc:hook_add(uc_const.UC_HOOK_INTR, callback, nil, nil, info)

    -- int 0xff
    uc:mem_write(0x7c000, '\205\255')
    uc:reg_write(info[1], 0xdead)
    uc:emu_start(0x7c000, 0x7c002)
    uc:emu_stop()

    assert.spy(callback).was_called()
    assert.are.equals(0xf00d, uc:reg_read(info[1]), 'Register not written to')
  end)
end)
