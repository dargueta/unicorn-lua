-- Copyright (C) 2017-2024 by Diego Argueta
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

-- Text-mode VGA driver

local curses = require 'curses'
local unicorn = require 'unicorn'
local uc_const = require 'unicorn.unicorn_const'

function make_color_pair(foreground, background)
  return (background * 16) + foreground
end


function color_attr(foreground, background)
  return curses.color_pair(make_color_pair(foreground, background))
end


-- Initialize the screen and return stdscr
function initialize_screen()
  local stdscr = curses.initscr()
  curses.echo(false)
  curses.nl(false)
  curses.start_color()
  curses.raw(true)
  stdscr:clear()

  -- initialize color pairs to typical defaults
  for foreground = 0, 15 do
    for background = 0, 15 do
      local pair = make_color_pair(foreground, background)
      curses.init_pair(pair, foreground, background)
    end
  end

  return stdscr
end


-- Given an address into VGA memory for mode 3, convert it to a row and column.
function addr_to_row_col(address)
  local offset = address - 0xb8000
  if offset < 0 then
    error(string.format('Bad address: %#08x', address))
  end

  -- There are 80 characters per row, two bytes per character, for a total of
  -- 160 bytes per row.
  local row = math.floor(offset / 160)

  -- Two bytes per column so we take the modulus of 160 to get the row offset
  -- in bytes, then divide by 2 to get the column.
  local col = math.floor((offset % 160) / 2)

  return row, col
end


function vga_write_trigger(engine, access_type, address, size, value, term_win)
  --[[
    * Write to an even address: changes character.
    * Write to an odd address: changes attribute.

    We're in 16-bit mode so writes can only be one or two bytes, so all we have
    to do is handle four cases, the combination of write sizes and odd/even
    addresses.
  ]]
  local row, col = addr_to_row_col(address)

  if size > 2 then
    error('Writes of more than 2 bytes not supported.')
  elseif size == 2 then
    if address % 2 == 0 then
      -- Write a character and attribute to (row, col)
      local colors = math.floor(value / 256)
      local char = string.char(value % 256)
      local fg = colors % 16
      local bg = math.floor(colors / 16) % 16
      local attr = color_attr(fg, bg)

      term_win:attrset(attr)
      term_win:mvaddch(row, col, char)
    else
      -- Because I'm lazy
      error('Refusing to do multibyte write on unaligned address.')
    end
  else
    if address % 2 == 0 then
      -- Write a character to (row, col)
      term_win:mvaddch(row, col, string.char(value))
    else
      -- Write the attribute for (row, col)
      local fg = value % 16
      local bg = math.floor(value / 16) % 256
      local attr = color_attr(fg, bg)

      local char = term_win:mvwgetch(row, col)
      term_win:attrset(attr)
      term_win:mvwaddch(row, col, char)
    end
  end

  term_win:refresh()
end


function main()
  local stdscr = initialize_screen()
  local term_win = curses.newwin(25, 80, 0, 0)

  -- Clear the screen, setting it to white text on a black background.
  term_win:wbkgdset(' ', make_color_pair(7, 0))

  local engine = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)
  engine:mem_map(0, 2^20)

  -- Add a hook for detecting writes to video memory, but only for text mode 3.
  engine:hook_add(uc_const.UC_HOOK_MEM_WRITE, vga_write_trigger, 0xb8000, 0xbffff, term_win)

  local fdesc = io.open('program.x86.bin')
  engine:mem_write(0x7c000, fdesc:read(512))
  fdesc:close()

  engine:emu_start(0x7c000, 2^20)
  engine:emu_stop()
  engine:close()

  -- Reset to white text on black background, pause, then wait for a keypress
  -- before exiting.
  term_win:attrset(color_attr(7, 0))
  term_win:mvaddstr(24, 0, 'Press any key to continue')
  term_win:getch()
  curses.endwin()
end

main()
