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

  it('[x86] Catch port read', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc:mem_map(0, 2^20)

    local callback = spy.new(
      function (engine, port, size)
        assert.are.equals(uc, engine)
        assert.are.equals(0x80, port)
        assert.are.equals(4, size)
        return 0xdeadbeef
      end)

    local handle = uc:hook_add(unicorn.UC_HOOK_INSN, callback, 0, 2^20, nil,
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
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    uc:mem_map(0, 2^20)

    local callback = spy.new(
      function (engine, intno)
        assert.are.equals(uc, engine)
        assert.are.equals(0xff, intno)
        assert.are.equals(0x55aa, uc:reg_read(x86.UC_X86_REG_AX))
        uc:reg_write(x86.UC_X86_REG_AX, 0xaa55)
      end)

    uc:hook_add(unicorn.UC_HOOK_INTR, callback)

    -- mov ax, 0x55aa
    -- int 0xff
    uc:mem_write(0x7c000, '\184\170\085\205\255')
    uc:emu_start(0x7c000, 0x7c005)
    uc:emu_stop()

    assert.spy(callback).was_called()
    assert.are.equals(0xaa55, uc:reg_read(x86.UC_X86_REG_AX), 'AX not written to')
  end)

  it('[x86] Passing scalar user data', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    uc:mem_map(0, 2^20)

    local register_id = x86.UC_X86_REG_ES
    local callback = spy.new(
      function (engine, intno, user_data)
        assert.are.equals(uc, engine)
        assert.are.equals(0xff, intno)
        assert.are.equals(register_id, user_data)
        assert.are.equals(0xdead, uc:reg_read(user_data))
        uc:reg_write(user_data, 0xf00d)
      end)

    uc:hook_add(unicorn.UC_HOOK_INTR, callback, nil, nil, register_id)

    -- int 0xff
    uc:mem_write(0x7c000, '\205\255')
    uc:reg_write(register_id, 0xdead)
    uc:emu_start(0x7c000, 0x7c002)
    uc:emu_stop()

    assert.spy(callback).was_called()
    assert.are.equals(0xf00d, uc:reg_read(register_id), 'Register not written to')
  end)

  it('[x86] Passing tables as user data', function ()
    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    uc:mem_map(0, 2^20)

    local info = {x86.UC_X86_REG_ES}
    local callback = spy.new(
      function (engine, intno, user_data)
        assert.are.equals(uc, engine)
        assert.are.equals(0xff, intno)
        assert.are.equals(info, user_data)
        assert.are.equals(0xdead, uc:reg_read(user_data[1]))
        uc:reg_write(user_data[1], 0xf00d)
      end)

    uc:hook_add(unicorn.UC_HOOK_INTR, callback, nil, nil, info)

    -- int 0xff
    uc:mem_write(0x7c000, '\205\255')
    uc:reg_write(info[1], 0xdead)
    uc:emu_start(0x7c000, 0x7c002)
    uc:emu_stop()

    assert.spy(callback).was_called()
    assert.are.equals(0xf00d, uc:reg_read(info[1]), 'Register not written to')
  end)
end)
