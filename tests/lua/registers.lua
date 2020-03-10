local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'
local regs_const = require 'unicorn.registers_const'
local x86 = require 'unicorn.x86_const'


describe('Register tests', function ()
  it('[x86] Read one register', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
    uc:mem_map(0, 2^20)

    -- mov eax, 0xdeadbeef
    uc:mem_write(0, '\184\239\190\173\222')
    uc:emu_start(0, 2^20, 0, 1)
    uc:emu_stop()

    local eax = uc:reg_read(x86.UC_X86_REG_EAX)
    assert.are.equals(0xdeadbeef, eax)
  end)

  it('[x86] Read multiple registers', function ()
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
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
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)

    uc:reg_write_batch {
      [x86.UC_X86_REG_AX] = 0x1a2b,
      [x86.UC_X86_REG_EDX] = 0x3c4d5e6f,
      [x86.UC_X86_REG_CL] = 0x78,
    }

    local ax, edx, cl = uc:reg_read_batch(x86.UC_X86_REG_AX,
                                          x86.UC_X86_REG_EDX,
                                          x86.UC_X86_REG_CL)
    assert.are.equals(0x1a2b, ax, 'Wrong value for AX')
    assert.are.equals(0x3c4d5e6f, edx, 'Wrong value for DX')
    assert.are.equals(cl, 0x78, 'Wrong value for CL')
  end)

  describe('[x86] Integer accuracy', function ()
    describe('8-bit value', function ()
      it('64-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 116)
        assert.are.equals(116, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('32-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_EAX, 91)
        assert.are.equals(91, uc:reg_read(x86.UC_X86_REG_EAX))
      end)

      it('16-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_AX, 78)
        assert.are.equals(78, uc:reg_read(x86.UC_X86_REG_AX))
      end)

      it('8-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_AL, 128)
        assert.are.equals(128, uc:reg_read(x86.UC_X86_REG_AL))
      end)
    end)

    describe('16-bit value', function ()
      it('64-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 57836)
        assert.are.equals(57836, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('32-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_EAX, 64501)
        assert.are.equals(64501, uc:reg_read(x86.UC_X86_REG_EAX))
      end)

      it('16-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_AX, 14698)
        assert.are.equals(14698, uc:reg_read(x86.UC_X86_REG_AX))
      end)
    end)

    describe('32-bit value', function ()
      it('64-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 0x8057f18a)
        assert.are.equals(0x8057f18a, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('32-bit register', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_EAX, 0xf8105110)
        assert.are.equals(0xf8105110, uc:reg_read(x86.UC_X86_REG_EAX))
      end)
    end)

    describe('64-bit value    #int64only', function ()
      it('64-bit register, MSB clear', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 0x17f8057f18a)
        assert.are.equals(0x17f8057f18a, uc:reg_read(x86.UC_X86_REG_RAX))
      end)

      it('64-bit register, MSB set', function ()
        local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
        uc:reg_write(x86.UC_X86_REG_RAX, 0xc0239d1f81be810a)
        assert.are.equals(0xc0239d1f81be810a, uc:reg_read(x86.UC_X86_REG_RAX))
      end)
    end)
  end)

  describe('Read registers in alternate formats', function ()
    it('Read R9 as two 32-bit signed integers', function ()
      local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
      uc:mem_map(0, 2^20)

      -- mov    r9, 0x0000deadcafebeef
      uc:mem_write(0, '\073\185\239\190\254\202\173\222\000\000')
      uc:emu_start(0, 2^20, 0, 1)

      -- First ensure that the R9 register contains the value we expect
      assert.are.equals(0x0000deadcafebeef, uc:reg_read(x86.UC_X86_REG_R9))

      local registers = uc:reg_read_as(
        x86.UC_X86_REG_R9, regs_const.REG_TYPE_INT32_ARRAY_2
      )

      -- n.b. 0xcafebeef is a signed 32-bit number
      assert.are.same({-889274641, 0xdead}, registers)
    end)

    it('Read RCX as eight 8-bit signed integers', function ()
      local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)
      uc:mem_map(0, 2^20)

      -- mov    rcx, 0x58057695f8cf0e50
      uc:mem_write(0, '\072\185\080\014\207\248\149\118\005\088')
      uc:emu_start(0, 2^20, 0, 1)

      -- First ensure that the RCX register contains the value we expect
      assert.are.equals(0x58057695f8cf0e50, uc:reg_read(x86.UC_X86_REG_RCX))

      local registers = uc:reg_read_as(
        x86.UC_X86_REG_RCX, regs_const.REG_TYPE_INT8_ARRAY_8
      )

      assert.are.same({80, 14, -49, -8, -107, 118, 5, 88}, registers)
    end)
  end)
  describe('Write registers in alternate formats', function ()
    it('Write to RCX as two 32-bit signed integers.', function ()
      local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_64)

      uc:reg_write_as(
        x86.UC_X86_REG_RCX, {-123456, 500}, regs_const.REG_TYPE_INT32_ARRAY_2
      )
      assert.are.equals(0x000001f4fffe1dc0, uc:reg_read(x86.UC_X86_REG_RCX))
    end)
  end)
end)
