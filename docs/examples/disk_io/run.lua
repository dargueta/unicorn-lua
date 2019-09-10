local unicorn = require 'unicorn'
local x86 = require 'unicorn.x86_const'


-- The dispatcher for all interrupts.
function interrupt(engine, int_num)
  local success

  if int_num == 0x13 then
    success = handle_int13(engine)
  else
    print(string.format('[INT %02XH] Error: Not implemented.', int_num))
    success = false
  end

  -- Set the carry flag depending on if the interrupt succeeded (CF=0) or failed
  -- (CF=1). Since CF is bit 0 of EFLAGS, we can avoid using bitwise operators
  -- for compatibility with Lua 5.3, and just use odd/even checking.
  local eflags = engine:reg_read(x86.UC_X86_REG_EFLAGS)
  if success == true or success == nil then
    -- Interrupt successful (treat nil as success).
    if eflags % 2 == 1 then
      eflags = eflags - 1
    end
  else
    -- Interrupt failed or not implemented, set carry flag.
    if eflags % 2 == 0 then
      eflags = eflags + 1
    end
  end
end


function handle_int13(engine)
  local subfunc, n_sectors, sector_and_cylinder, drive, buf_segment, buf_offset
        = engine:reg_read_batch(
            x86.UC_X86_REG_AH, x86.UC_X86_REG_AL, x86.UC_X86_REG_CL, x86.UC_X86_REG_DL,
            x86.UC_X86_REG_ES, x86.UC_X86_REG_BX)

  if subfunc ~= 0x02 then
    print(string.format('[INT 13H] ERROR: Invalid subfunction: %#02X.', subfunc))
    return false
  elseif drive ~= 0 then
    print(string.format('[INT 13H] ERROR: Invalid drive number: %#02X.', drive))
    return false
  end

  local sector = sector_and_cylinder % 64
  local buf_address = (buf_segment * 16) + buf_offset

  print(string.format('[INT 13H] Reading: start=%d, count=%d, to=%04X:%04X',
                      sector, n_sectors, buf_segment, buf_offset))

  io.input():seek('set', (sector - 1) * 512)
  local data = io.input():read(512 * n_sectors)
  engine:mem_write(buf_address, data)

  return true
end


local engine = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)

engine:mem_map(0, 2^20)
engine:hook_add(unicorn.UC_HOOK_INTR, interrupt)

-- Read *only* the first sector from the disk image into memory. The code in the
-- first sector will load the second sector and execute that.
fdesc = io.open('program.x86.bin', 'rb')
io.input(fdesc)
engine:mem_write(0x7c000, io.read(512))

engine:emu_start(0x7c000, 1024)

-- After the processor exits we should have a magic value in AX if everything
-- went according to plan.
local ax = engine:reg_read(x86.UC_X86_REG_AX)
if ax ~= 0x1234 then
  error(string.format('Bad value for AX: %#04x != 0x1234', ax))
else
  print('Success!')
end
