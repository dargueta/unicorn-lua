Reading the CMOS Realtime Clock
===============================

This code example shows how one can emulate the CMOS clock by hooking access to
ports 0x70 and 0x71. It is *not* a realistic implementation and is intended for
illustrative purposes *only*.

To run the program, first compile ``program.asm`` using NASM or a compatible
assembler, like so:

.. code-block:: sh

    nasm -Wall -Werror -fbin -o program.bin program.asm

You can then run it:

.. code-block:: sh

    # You might need to change the file extension in LUA_CPATH to `.dylib` if
    # you're on a Mac, or `.dll` if you're on Windows.
    LUA_CPATH="../../bin/?.so" lua cmos.lua
