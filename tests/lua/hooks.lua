local unicorn = require 'unicorn'
local x86 = require 'unicorn.x86'


describe('Hook tests', function ()
  it('[x86] Catch valid memory read', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc:mem_map(0, 2^20)

    local callback = spy.new(
      function (engine, access_type, address, size, value)
        assert.are.equals(uc, engine)
        assert.are.equals(unicorn.UC_MEM_READ_AFTER, access_type)
        assert.are.equals(0x12345, address)
        assert.are.equals(4, size)
        assert.are.equals(0, value)

        engine:emu_stop()
      end)

    local handle = uc:hook_add(unicorn.UC_HOOK_MEM_READ_AFTER, callback, 0, 2^20)
    assert.not_nil(handle)

    -- mov eax, DWORD [0x12345]
    uc:mem_write(0, '\161\069\035\001\000')
    uc:mem_write(0x12340, string.rep('\000', 64))

    uc:emu_start(0, 2^20, 0, 1)
    assert.spy(callback).was_called()
  end)
end)
