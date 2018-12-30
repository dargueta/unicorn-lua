local unicorn = require 'unicorn'
local x86 = require 'unicorn.x86'

local CMOS_STATE = {}


function handle_in(engine, port, size)
  if port == 0x70 then
    error('Port 0x70 is not readable.')
  elseif port == 0x71 then
    return handle_71_in(engine, port, size)
  else
    return 0
  end
end


function handle_out(engine, port, size, value)
  if port == 0x70 then
    return handle_70_out(engine, port, size, value)
  elseif port == 0x71 then
    error('Writing to port 0x71 is not implemented.')
  else
    return 0
  end
end


function handle_70_out(engine, port, size, value)
  if size ~= 1 then
    error('Invalid write size for port 0x70: ' .. tostring(size))
  end

  print(string.format('Writing %#02x to register 0x70', value))
  CMOS_STATE.selected_register = value
end


function handle_71_in(engine, port, size)
  if size ~= 1 then
    error('Invalid read size for port 0x71: ' .. tostring(size))
  end

  local reg = CMOS_STATE.selected_register
  local value = CMOS_STATE.registers[CMOS_STATE.selected_register]

  print(string.format('Reading register %#02x from port 0x71, got %#02x.',
                      reg, value))

  -- The CMOS usually resets the selected register after a read or write to 13,
  -- for reasons unknown. Emulate that here.
  CMOS_STATE.selected_register = 0x0d

  return value or 0
end


_WEEKDAYS = {'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'}
_MONTHS = {'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct',
           'Nov', 'Dec'}


function main()
  local engine = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

  engine:hook_add(unicorn.UC_HOOK_INSN, handle_in, 0, 0, x86.UC_X86_INS_IN)
  engine:hook_add(unicorn.UC_HOOK_INSN, handle_out, 0, 0, x86.UC_X86_INS_OUT)

  -- This seems to be the default for some reason
  CMOS_STATE.selected_register = 0x0d

  local now = os.date('*t')
  CMOS_STATE.registers = {
    [0] = now.sec,
    [2] = now.min,
    [4] = now.hour,
    [6] = now.wday,
    [7] = now.day,
    [8] = now.month,
    [9] = now.year % 100,
    [0x32] = math.floor(now.year / 100)
  }

  engine:mem_map(0, 4096)

  -- Load the program image into memory
  local fdesc = io.open('program.x86.bin', 'rb')
  engine:mem_write(0, fdesc:read(256))
  fdesc:close()

  engine:emu_start(0, 127)
  engine:emu_stop()

  local raw_data = engine:mem_read(128, 10)
  local sec = raw_data:byte(1)
  local min = raw_data:byte(2)
  local hour = raw_data:byte(3)
  local wday = raw_data:byte(4)
  local day = raw_data:byte(5)
  local month = raw_data:byte(6)
  local year = raw_data:byte(7)
  local century = raw_data:byte(8)
  local full_year_low, full_year_high = raw_data:byte(9, 10)
  local full_year = (full_year_high * 256) + full_year_low

  engine:close()

  -- FIXME: Month and day are swapped, and those are the only wrong ones.
  print(string.format(
    '\nToday is: %s, %d %s %d %02d:%02d:%02d (C=%d)', _WEEKDAYS[wday], month,
    _MONTHS[day], full_year, hour, min, sec, century))
end

main()
