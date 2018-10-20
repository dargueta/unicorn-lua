unicorn-lua
===========

An attempt at making Lua bindings for the `Unicorn CPU Emulator <http://www.unicorn-engine.org/>`_.

This is in a *highly* experimental phase right now and **should not** be used in
anything requiring reliability.

At the moment I'm only testing this on Lua 5.3 with an unmodified ``luaconf.h``.
I cannot guarantee the library will behave as expected on all platforms or older
5.x versions of Lua.

Known Limitations
-----------------

The following are some limitations that are either impossible to work around due
to the nature of Lua, or I haven't gotten around to fixing yet.

Signedness
~~~~~~~~~~

Because numbers in Lua are always signed, values above ``LUA_MAXINTEGER`` [1]_
such as addresses or register values cannot be passed to functions as normal
integers, as you'll end up with stuff like this:

.. code-block::

    Lua 5.3.5  Copyright (C) 1994-2018 Lua.org, PUC-Rio
    > i = 0x8000000000000000
    > i
    -9223372036854775808

Passing Arguments
^^^^^^^^^^^^^^^^^

Arguments with values above ``LUA_MAXINTEGER`` must be passed to functions as
*strings* to avoid loss of precision:

.. code-block:: lua

    -- Correct way to write 0x8000000000000000 to RAX.  :(
    uc:reg_write(x86.UC_REG_RAX, '0x8000000000000000')

This library accepts a decimal or hexadecimal string for any memory address or
register value. Unfortunately, these values *must* be unsigned, so the following
will trigger an exception:

.. code-block:: lua

    -- Wrong way to set all bits
    uc:reg_write(x86.UC_REG_RAX, -1)
    uc:reg_write(x86.UC_REG_RAX, '-1')

    -- Correct way to set all bits
    uc:reg_write(x86.UC_REG_RAX, '0xffffffffffffffff')

Return Values
^^^^^^^^^^^^^

Function return values are outside my control; Lua returns them to the script as
signed integers:

.. code-block:: lua

    uc:reg_write(x86.UC_REG_RAX, '0xffffffffffffffff')

    -- Returns -1 not 2^64 - 1
    uc:reg_read(x86.UC_REG_RAX)

License
-------

I'm releasing this under the terms of the
`3-Clause BSD License <https://opensource.org/licenses/BSD-3-Clause>`_. For the
full legal text, see ``LICENSE.txt``.

.. [1] Typically 2\ :sup:`63` - 1 on 64-bit machines and 2\ :sup:`31` - 1 on
       32-bit machines.
