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
such as addresses or register values will be returned from functions as negative
numbers, e.g.

.. code-block:: lua

    uc:reg_write(x86.UC_REG_RAX, 0xffffffffffffffff)

    -- Returns -1 not 2^64 - 1
    uc:reg_read(x86.UC_REG_RAX)

This doesn't affect how arguments are passed *to* the library, only return values
*from* the library.

Development
-----------

This project has the following dependencies. Ensure you have them installed
before using.

* For running: `Unicorn CPU Emulator <http://www.unicorn-engine.org/>`_
* For unit testing: `busted <http://olivinelabs.com/busted/>`_

To run unit tests, do:

.. code-block:: sh

    make test

License
-------

I'm releasing this under the terms of the
`3-Clause BSD License <https://opensource.org/licenses/BSD-3-Clause>`_. For the
full legal text, see ``LICENSE.txt``.

.. [1] Typically 2\ :sup:`63` - 1 on 64-bit machines and 2\ :sup:`31` - 1 on
       32-bit machines.
