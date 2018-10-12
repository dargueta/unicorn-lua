unicorn-lua
===========

An attempt at making Lua bindings for the `Unicorn CPU Emulator <http://www.unicorn-engine.org/>`_.

This is in a *highly* experimental phase right now and **should not** be used in
anything requiring reliability.


This is only tested on Lua 5.3. I cannot guarantee the library will behave as
expected on Lua 5.2, particularly because all numbers in Lua 5.2 are floats. [#]_
Don't even try 5.1.

Known Limitations
-----------------

* Because numbers in Lua are always signed, addresses on 64-bit Lua are limited
  to [0, 2\ :sup:`63`) or [0, 2\ :sup:`31`) on 32-bit Lua.
* Reading a register may give you different numbers depending on whether you're
  running 64-bit or 32-bit Lua. For example, a 32-bit register containing the
  value 0xffffffff will be -1 on 32-bit Lua, and 2\ :sup:`32` - 1 on 64-bit Lua.
* I haven't tested this yet but I suspect running this on a system where the
  emulated CPU's endianness differs from the host machine's will behave oddly.

License
-------

I'm releasing this under the terms of the
`3-Clause BSD License <https://opensource.org/licenses/BSD-3-Clause>`_. For the
full legal text, see ``LICENSE.txt``.

.. [#] Integer support was only added in 5.3.
