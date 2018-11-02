describe("Ensure library loads don't crash.", function ()
  it('Import base library', function () require 'unicorn' end)
  it('[arm] require', function() require 'unicorn.arm' end)
  it('[arm64] require', function () require 'unicorn.arm64' end)
  it('[m68k] require', function () require 'unicorn.m68k' end)
  it('[mips] require', function () require 'unicorn.mips' end)
  it('[sparc] require', function () require 'unicorn.sparc' end)
  it('[x86] require', function () require 'unicorn.x86' end)
end)