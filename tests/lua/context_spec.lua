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


describe('Context tests', function ()
    it('Basic test of set/restore context', function ()
        -- Set EAX to a value, save a context, change EAX, restore the context,
        -- and ensure it has the original value.
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)

        -- Map in a page and add one instruction, a jump that results in an infinite loop.
        -- We don't care what the VM is actually doing, just that it's running.
        uc:mem_map(0, 4096)
        uc:mem_write(0, '\235\254')
        uc:emu_start()

        uc:reg_write(x86.UC_X86_REG_EAX, 123456)
        assert.are.equals(123456, uc:reg_read(x86.UC_X86_REG_EAX))

        local context = uc:context_save()

        uc:reg_write(x86.UC_X86_REG_EAX, 98765432)
        assert.are.equals(98765432, uc:reg_read(x86.UC_X86_REG_EAX))

        uc:context_restore(context)
        assert.are.equals(123456, uc:reg_read(x86.UC_X86_REG_EAX))
        uc:close()
    end)

    it('Do *not* crash if we free a context and then deallocate it.', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
        local context = uc:context_save()
        context:free()
        uc:close()
    end)
end)
