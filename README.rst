unicorn-lua
===========

|build-status| |lua-versions|

.. |build-status| image:: https://travis-ci.org/dargueta/unicorn-lua.svg?branch=master
   :alt: Build status
   :target: https://travis-ci.org/dargueta/unicorn-lua

.. |lua-versions| image:: https://img.shields.io/badge/lua-5.1%2C%205.2%2C%205.3-blue.svg
   :alt: Lua versions
   :target: https://www.lua.org

An attempt at making Lua bindings for the `Unicorn CPU Emulator <http://www.unicorn-engine.org/>`_.

This is in a *highly* experimental phase right now and **should not** be used in
anything requiring reliability.

At the moment I'm only testing this on unmodified Lua 5.1 - 5.3 on Linux systems.
I cannot guarantee the library will behave as expected on all host platforms,
though I will try.

Known Limitations
-----------------

The following are some limitations that are either impossible to work around due
to the nature of Lua, or I haven't gotten around to fixing yet.

64-bit Integers
~~~~~~~~~~~~~~~

64-bit integers *do not* fully work on Lua 5.2 or 5.1. This is because Lua only
added direct support for integers in 5.3; Lua 5.1 and 5.2 use floating-point
numbers, which provide at most 17 `digits of precision <https://en.wikipedia.org/wiki/Double-precision_floating-point_format>`_.
Thus, values over 53 bits cannot be represented accurately.

We can work around this limitation by

* Using libraries such as `BigInt <https://luarocks.org/modules/jorj/bigint>`_.
  This could quickly become cumbersome, and the performance impact is unknown.
* Providing special read and write functions for 64-bit integers. This is the
  least disruptive but also makes the API irregular.

I don't intend to fix this at the moment, as I want to focus on getting the API
complete first.

Signedness
~~~~~~~~~~

Because numbers in Lua are always signed, values above ``LUA_MAXINTEGER`` [1]_
such as addresses or register values will be returned from functions as negative
numbers, e.g.

.. code-block:: lua

    uc:reg_write(x86.UC_X86_REG_RAX, 0xffffffffffffffff)

    -- Returns -1 not 2^64 - 1
    uc:reg_read(x86.UC_X86_REG_RAX)

This doesn't affect how arguments are passed *to* the library, only values returned
*from* the library.

Big-Endian Hosts
~~~~~~~~~~~~~~~~

Reading from/writing to registers on a big-endian host system won't work for
registers that aren't the same size as a Lua integer. This is because the library
currently has no concept of register sizes and thus doesn't know how to do
typecasts. Due to how byte order works this doesn't matter on a little-endian
system, but will result in things like a 16-bit register getting returned to
Lua as 0x7fff000000000000 instead of 0x7fff.

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
