unicorn-lua
===========

An attempt at making Lua bindings for the `Unicorn CPU Emulator <http://www.unicorn-engine.org/>`_.

This is in a *highly* experimental phase right now and **should not** be used in
anything requiring reliability.


At the moment I'm only testing this on Lua 5.3 with an unmodified ``luaconf.h``).
I cannot guarantee the library will behave as expected on all platforms or older
5.x versions of Lua.


Known Limitations
-----------------

The following notes assume Lua was compiled with 64-bit integers and double-precision
floats. They're significant limitations and I intend to fix these ASAP.

* Because numbers in Lua are always signed, addresses on Lua are limited to
  [0, 2\ :sup:`63`). In theory this should be fine since most processors can't
  handle addresses over 2\ :sup:`48`. [#]_
* You must be careful when reading from/writing to registers with 64 bits or
  more. To avoid loss of precision due to automatic conversion to floating-point
  numbers, if you want to set the most significant bit you'll need to pass a
  *negative* number.

.. code-block:: lua

    -- Correct way to write 0x8000000000000000 to RAX.  :(
    uc:reg_write(x86.UC_REG_RAX, -9223372036854775808)

This is horrific and I intend to fix it soon.

License
-------

I'm releasing this under the terms of the
`3-Clause BSD License <https://opensource.org/licenses/BSD-3-Clause>`_. For the
full legal text, see ``LICENSE.txt``.

.. [#] At the time of writing (October 2018)
