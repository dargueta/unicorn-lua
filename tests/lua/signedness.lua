local unicorn = require 'unicorn'
local x86 = require 'unicorn.x86'

describe('[x86] Signedness tests', function ()
  -- While this behavior is undesirable, we do need to test it to ensure
  -- compatibility with client code until we fix it.
  it('Returns 2^64 - 1 as -1', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, 0xffffffffffffffff)
    assert.are.equals(-1, uc:reg_read(x86.UC_X86_REG_RAX))
  end)

  it('Returns 2^63 - 1 as 0x7fffffffffffffff', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, 0x7fffffffffffffff)
    assert.are.equals(0x7fffffffffffffff, uc:reg_read(x86.UC_X86_REG_RAX))
  end)

  it('Returns 2^63 - 1 as 0x7fffffffffffffff (string)', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, '0x7fffffffffffffff')
    assert.are.equals(0x7fffffffffffffff, uc:reg_read(x86.UC_X86_REG_RAX))
  end)

  it('Accepts negative values and returns them properly', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc:reg_write(x86.UC_X86_REG_RAX, -17480)
    assert.are.equals(-17480, uc:reg_read(x86.UC_X86_REG_RAX))
  end)
end)
