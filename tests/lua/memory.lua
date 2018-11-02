describe('Memory tests', function ()
  it('Writes to memory and reads it back', function ()
    local unicorn = require 'unicorn'
    local mu = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

    mu:mem_map(0, 2 ^ 20)

    mu:mem_write(0, 'ASDFGH')
    mu:mem_write(0x100, 'qwerty')
    mu:mem_write(0x1000, '123\004\005\006')
    mu:mem_write(0x10000, '7890-=')
    mu:mem_write(0x20000, '\000\001\002\003\127\255')

    assert.are.equals('ASDFGH', mu:mem_read(0, 6))
    assert.are.equals('qwerty', mu:mem_read(0x100, 6))
    assert.are.equals('123\004\005\006', mu:mem_read(0x1000, 6))
    assert.are.equals('7890-=', mu:mem_read(0x10000, 6))
    assert.are.equals('\000\001\002\003\127\255', mu:mem_read(0x20000, 6))
  end)
end)
