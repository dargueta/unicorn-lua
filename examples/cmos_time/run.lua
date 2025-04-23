-- Copyright (C) 2017-2025 by Diego Argueta
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'
local x86 = require 'unicorn.x86_const'


function handle_in(engine, port, size, cmos)
  if port == 0x70 then
    error('Port 0x70 is not readable.')
  elseif port == 0x71 then
    return handle_71_in(engine, port, size, cmos)
  else
    return 0
  end
end


function handle_out(engine, port, size, value, cmos)
  if port == 0x70 then
    return handle_70_out(engine, port, size, value, cmos)
  elseif port == 0x71 then
    error('Writing to port 0x71 is not implemented.')
  else
    return 0
  end
end


function handle_70_out(engine, port, size, value, cmos)
  if size ~= 1 then
    error('Invalid write size for port 0x70: ' .. tostring(size))
  end

  print(string.format('Writing %#02x to register %d', value,
                      cmos.selected_register))
  cmos.selected_register = value
end


function handle_71_in(engine, port, size, cmos)
  if size ~= 1 then
    error('Invalid read size for port 0x71: ' .. tostring(size))
  end

  local reg = cmos.selected_register
  local value = cmos.registers[cmos.selected_register]

  print(string.format('Reading register %d from port 0x71, got %#02x.', reg,
                      value))

  -- The CMOS usually resets the selected register to 13 after a read or write,
  -- for reasons unknown. Emulate that here.
  cmos.selected_register = 0x0d

  return value or 0
end


WEEKDAYS = {'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'}
MONTHS = {'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct',
          'Nov', 'Dec'}


function main()
  local engine = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
  local now = os.date('*t')
  local cmos_state = {
    -- Register 13 seems to be the default for some reason
    selected_register = 0x0d,
    registers = {
      [0] = now.sec,
      [2] = now.min,
      [4] = now.hour,
      [6] = now.wday,
      [7] = now.day,
      [8] = now.month,
      [9] = now.year % 100,
      [0x32] = math.floor(now.year / 100)
    }
  }

  engine:hook_add(uc_const.UC_HOOK_INSN, handle_in, 0, 0, cmos_state, x86.UC_X86_INS_IN)
  engine:hook_add(uc_const.UC_HOOK_INSN, handle_out, 0, 0, cmos_state, x86.UC_X86_INS_OUT)
  engine:mem_map(0, 2^20)

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
  -- Byte 7 contains the year as an unsigned offset from some epoch I haven't
  -- bothered to look up. Bytes 9-10 give the full year, so we don't need this.
  local century = raw_data:byte(8)
  local full_year_low, full_year_high = raw_data:byte(9, 10)
  local full_year = (full_year_high * 256) + full_year_low

  engine:close()

  print(string.format(
    '\nToday is: %s, %d %s %d %02d:%02d:%02d (C=%d)', WEEKDAYS[wday], day,
    MONTHS[month], full_year, hour, min, sec, century))
end

main()
