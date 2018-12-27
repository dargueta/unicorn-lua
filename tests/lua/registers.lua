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
    assert.are.equals(0xfedcba98, ebx, 'Wrong value for EBX')
    assert.are.equals(0x0123, cx, 'Wrong value for CX')
    assert.are.equals(0x45, dl, 'Wrong value for DL')
  end)

  it('[x86] Write multiple registers', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    uc:reg_write_batch {
      [x86.UC_X86_REG_AX] = 0x1a2b,
      [x86.UC_X86_REG_EDX] = 0x3c4d5e6f,
      [x86.UC_X86_REG_CL] = 0x78,
    }

    local ax, edx, cl = uc:reg_read_batch(x86.UC_X86_REG_AX,
                                          x86.UC_X86_REG_EDX,
                                          x86.UC_X86_REG_CL)
    assert.are.equals(0x1a2b, ax, 'Wrong value for AX')
    assert.are.equals(0x3c4d5e6f, edx, 'EWrong value for DX')
    assert.are.equals(cl, 0x78, 'Wrong value for CL')
  end)

  describe('[x86] Integer accuracy', function ()
    describe('8-bit value', function ()
      it('64-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 116)
        assert.are.equals(116, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('32-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_EAX, 91)
        assert.are.equals(91, uc:reg_read(x86.UC_X86_REG_EAX))
      end)

      it('16-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_AX, 78)
        assert.are.equals(78, uc:reg_read(x86.UC_X86_REG_AX))
      end)

      it('8-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_AL, 128)
        assert.are.equals(128, uc:reg_read(x86.UC_X86_REG_AL))
      end)
    end)

    describe('16-bit value', function ()
      it('64-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 57836)
        assert.are.equals(57836, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('32-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_EAX, 64501)
        assert.are.equals(64501, uc:reg_read(x86.UC_X86_REG_EAX))
      end)

      it('16-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_AX, 14698)
        assert.are.equals(14698, uc:reg_read(x86.UC_X86_REG_AX))
      end)
    end)

    describe('32-bit value', function ()
      it('64-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 0x8057f18a)
        assert.are.equals(0x8057f18a, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('32-bit register', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_EAX, 0xf8105110)
        assert.are.equals(0xf8105110, uc:reg_read(x86.UC_X86_REG_EAX))
      end)
    end)

    describe('64-bit value    #int64only', function ()
      it('64-bit register, MSB clear', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 0x17f8057f18a)
        assert.are.equals(0x17f8057f18a, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('64-bit register, MSB set', function ()
        local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 0xc0239d1f81be810a)
        assert.are.equals(0xc0239d1f81be810a, uc:reg_read(x86.UC_X86_REG_RAX))
      end)
    end)
  end)
end)
