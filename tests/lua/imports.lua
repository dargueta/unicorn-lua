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

describe("Ensure library loads don't crash.", function ()
  it('Import base library', function () require 'unicorn' end)
  it('[unicorn] require', function () require 'unicorn.unicorn_const' end)
  it('[arm] require', function() require 'unicorn.arm_const' end)
  it('[arm64] require', function () require 'unicorn.arm64_const' end)
  it('[m68k] require', function () require 'unicorn.m68k_const' end)
  it('[mips] require', function () require 'unicorn.mips_const' end)
  it('[sparc] require', function () require 'unicorn.sparc_const' end)
  it('[x86] require', function () require 'unicorn.x86_const' end)

  -- Unicorn 2.x only
  describe("Unicorn 2.x tests only", function ()
    for _, arch in ipairs({"ppc", "riscv", "s390x", "tricore"}) do
      it("[" .. arch .. "] require", function()
        local uc = require "unicorn"
        local v_major = uc:version()

        if v_major >= 2 then
          require("unicorn." .. arch .. "_const")
        end
      end)
    end
  end)
end)


describe('Ensure binding version number looks correct.', function ()
  it('Check existence of version table', function()
    local unicorn = require 'unicorn'
    assert.is_not_nil(unicorn.LUA_LIBRARY_VERSION)
  end)

  it('Checks version table looks correct', function ()
    local unicorn = require 'unicorn'
    local major, minor, patch = table.unpack(unicorn.LUA_LIBRARY_VERSION)

    assert.is_equal("number", type(major), 'Major version is borked')
    assert.is_equal("number", type(minor), 'Minor version is borked')
    assert.is_equal("number", type(patch), 'Patch version is borked')
  end)
end)
