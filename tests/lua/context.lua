local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'
local x86 = require 'unicorn.x86_const'


describe('Context tests', function ()
    it('Basic test of set/restore context', function ()
        -- Set EAX to a value, save a context, change EAX, restore the context,
        -- and ensure it has the original value.
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)

        uc:reg_write(x86.UC_X86_REG_EAX, 123456)
        assert.are.equals(123456, uc:reg_read(x86.UC_X86_REG_EAX))

        local context = uc:context_save()

        uc:reg_write(x86.UC_X86_REG_EAX, 98765432)
        assert.are.equals(98765432, uc:reg_read(x86.UC_X86_REG_EAX))

        uc:context_restore(context)
        assert.are.equals(123456, uc:reg_read(x86.UC_X86_REG_EAX))
    end)

    it('Do *not* crash if we try freeing a context twice', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
        local context = uc:context_save()
        context:free()
        context:free()
    end)
end)
