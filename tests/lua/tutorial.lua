describe('[x86] Basic register read/write', function ()
    local unicorn = require 'unicorn'
    local x86 = require 'unicorn.x86'

    local X86_CODE32 = "\x41\x4a" -- INC ecx; DEC edx
    local ADDRESS = 0x1000000

    -- Initialize emulator in X86-32bit mode
    local mu = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

    -- map 2MB memory for this emulation
    mu:mem_map(ADDRESS, 2 * 1024 * 1024)

    -- write machine code to be emulated to memory
    mu:mem_write(ADDRESS, X86_CODE32)

    -- initialize machine registers
    mu:reg_write(x86.UC_X86_REG_ECX, 0x1234)
    mu:reg_write(x86.UC_X86_REG_EDX, 0x7890)

    -- emulate code in infinite time & unlimited instructions
    mu:emu_start(ADDRESS, ADDRESS + #X86_CODE32)

    -- read some registers back
    local r_ecx = mu:reg_read(x86.UC_X86_REG_ECX)
    local r_edx = mu:reg_read(x86.UC_X86_REG_EDX)

    -- make sure we got the right values
    assert(r_ecx == 0x1235, "Wrong value for ECX")
    assert(r_edx == 0x788f, "Wrong value for EDX")
end)
