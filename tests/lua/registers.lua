local unicorn = require 'unicorn'
local x86 = require 'unicorn.x86'

describe('Register tests', function ()
  it('[x86] Read one register', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc:mem_map(0, 2^20)

    -- mov eax, 0xdeadbeef
    uc:mem_write(0, '\184\239\190\173\222')
    uc:emu_start(0, 2^20, 0, 1)
    uc:emu_stop()

    local eax = uc:reg_read(x86.UC_X86_REG_EAX)
    assert.are.equals(0xdeadbeef, eax)
  end)

  it('[x86] Read multiple registers', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc:mem_map(0, 2^20)

    -- mov ebx, 0xfedcba98
    -- mov cx, 0x0123
    -- mov dl, 0x45
    uc:mem_write(0, '\187\152\186\220\254\102\185\035\001\178\069')
    uc:emu_start(0, 2^20, 0, 3)
    uc:emu_stop()

    local ebx, cx, dl = uc:reg_read_batch(x86.UC_X86_REG_EBX,
                                          x86.UC_X86_REG_CX,
                                          x86.UC_X86_REG_DL)
    assert.are.equals(0xfedcba98, ebx)
    assert.are.equals(0x0123, cx)
    assert.are.equals(0x45, dl)
  end)
end)
