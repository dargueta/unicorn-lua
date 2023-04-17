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
