describe('Memory tests', function ()
  it('Writes to memory and reads it back', function ()
    local unicorn = require 'unicorn'
    local uc_const = require 'unicorn.unicorn_const'
    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)

    uc:mem_map(0, 2 ^ 20)

    uc:mem_write(0, 'ASDFGH')
    uc:mem_write(0x100, 'qwerty')
    uc:mem_write(0x1000, '123\004\005\006')
    uc:mem_write(0x10000, '7890-=')
    uc:mem_write(0x20000, '\000\001\002\003\127\255')

    assert.are.equals('ASDFGH', uc:mem_read(0, 6))
    assert.are.equals('qwerty', uc:mem_read(0x100, 6))
    assert.are.equals('123\004\005\006', uc:mem_read(0x1000, 6))
    assert.are.equals('7890-=', uc:mem_read(0x10000, 6))
    assert.are.equals('\000\001\002\003\127\255', uc:mem_read(0x20000, 6))
  end)
end)
