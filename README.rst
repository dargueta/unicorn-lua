unicorn-lua
===========

|build-status| |lua-versions| |platforms|

.. |build-status| image:: https://travis-ci.com/dargueta/unicorn-lua.svg?branch=master
   :alt: Build status
   :target: https://travis-ci.com/dargueta/unicorn-lua

.. |lua-versions| image:: https://img.shields.io/badge/lua-5.1%20%7C%205.2%20%7C%205.3%20%7C%205.4%20%7C%20LuaJIT2.0-blue
   :alt: Lua versions
   :target: https://www.lua.org

.. |platforms| image:: https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey
   :alt: Supported platforms

Lua bindings for the `Unicorn CPU Emulator`_.

I'm currently testing this on vanilla Lua 5.1 - 5.4, and LuaJIT 2.0 on both Linux
and OSX.

License Change
--------------

As of version 2.0 the license has changed to GPL v2. This is due to the viral
nature of the GPL license family: since QEMU uses GPL, this must also be GPL
even though it only dynamically links to Unicorn. I apologize for the mistake I
made when I created this with the BSD-3 license.

Known Limitations
-----------------

The following are some limitations that are either impossible to work around due
to the nature of Lua, or I haven't gotten around to fixing yet.

32-bit Lua Behavior
~~~~~~~~~~~~~~~~~~~

Behavior for 32-bit Lua (i.e. compiled with ``LUA_32BITS`` set to a nonzero value)
won't handle 64-bit integers properly. Exactly what happens is technically
undefined until C++20, but most likely you would silently lose the upper 32 bits.
It's for this reason I strongly discourage using such builds.

64-bit Integers
~~~~~~~~~~~~~~~

64-bit integers *do not* fully work on Lua 5.2 or 5.1. This is because Lua only
added direct support for integers in 5.3; Lua 5.1 and 5.2 use floating-point
numbers, which provide at most 17 `digits of precision`_. Thus, values over 53
bits cannot be represented accurately before 5.3.

We can work around this limitation by:

* Using libraries such as `BigInt`_. This could quickly become cumbersome, and
  the performance impact is unknown.
* Providing special read and write functions for 64-bit integers. This is the
  least disruptive but also makes the API irregular.

I don't intend to fix this at the moment, as I want to focus on getting the API
complete first.

.. _BigInt: https://luarocks.org/modules/jorj/bigint
.. _digits of precision: https://en.wikipedia.org/wiki/Double-precision_floating-point_format

Signedness
~~~~~~~~~~

Because numbers in Lua are always signed, values above ``LUA_MAXINTEGER`` [1]_
such as addresses or register values will be returned from functions as negative
numbers, e.g.

.. code-block:: lua

    uc:reg_write(x86_const.UC_X86_REG_RAX, 0xffffffffffffffff)

    -- Returns -1 not 2^64 - 1
    uc:reg_read(x86_const.UC_X86_REG_RAX)

This doesn't affect how arguments are passed *to* the library, only values returned
*from* the library.

Floating-point Registers
~~~~~~~~~~~~~~~~~~~~~~~~

The 80-bit ST(x) registers on x86 architectures can't be read from or written to
properly; a bug in the current encoding/decoding code gives garbage values so I've
disabled it for the time being. Even if it did work, because Lua's floating-point
numbers are by default at most 64 bits, you're still going to lose precision when
reading the registers.


Emergency Collection and Memory Leaks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If Lua doesn't have enough available memory to do a proper garbage collection
cycle, the collector will run in "emergency mode." [2]_ In this mode, finalizers
are *not* run, so you could end up in a situation where hooks, contexts, and
other resources held by a disused engine aren't released and never can be.

This rarely happens and most user code will probably be able to let the library
do its own memory management. If you like to be safe, call the ``close()`` method
on an engine after you're done using it to reduce the risk of an emergency
collection leaking resources.

General Usage
-------------

``unicorn`` tries to mirror the organization and naming conventions of the
`Python binding`_ as much as possible. For example, architecture-specific
constants are defined in submodules like ``unicorn.x86_const``; a few global
functions are defined in ``unicorn``, and the rest are instance methods of the
engine.

.. _Python binding: http://www.unicorn-engine.org/docs/tutorial.html

Quick Example
~~~~~~~~~~~~~

This is a short example to show how a some of the features can be used to emulate
the BIOS setting up a system when booting.

.. code-block:: lua

    local unicorn = require 'unicorn'
    local uc_const = require 'unicorn.unicorn_const'

    local uc = unicorn.open(uc_const.UC_ARCH_X86, uc_const.UC_MODE_32)

    -- Map in 1 MiB of RAM for the processor with full read/write/execute
    -- permissions. We could pass permissions as a third argument if we want.
    uc:mem_map(0, 0x100000)

    -- Revoke write access to the VGA and BIOS ROM shadow areas.
    uc:mem_protect(0xC0000, 32 * 1024, uc_const.UC_PROT_READ|uc_const.UC_PROT_EXEC)
    uc:mem_protect(0xF0000, 64 * 1024, uc_const.UC_PROT_READ|uc_const.UC_PROT_EXEC)

    -- Create a hook for the VGA driver that's called whenever VGA memory is
    -- written to by client code.
    uc:hook_add(uc_const.UC_MEM_WRITE, vga_write_callback, 0xA0000, 0xBFFFF)

    -- Install interrupt hooks so the CPU can perform I/O and other operations.
    -- We'll handle all of that in Lua. Only one interrupt hook can be set at a
    -- time.
    uc:hook_add(uc_const.UC_HOOK_INTR, interrupt_dispatch_hook)

    -- Load the boot sector of the hard drive into 0x7C000
    local fdesc = io.open('hard-drive.img')
    local boot_sector = fdesc:read(512)
    uc:mem_write(0x7C000, boot_sector)
    fdesc:close()

    -- Start emulation at the boot sector we just loaded, stopping if execution
    -- hits the address 0x100000. Since this is beyond the range we have mapped
    -- in, the CPU will run forever until the code shuts it down, just like a
    -- real system.
    uc:emu_start(0x7C000, 0x100000)


Detailed Examples
~~~~~~~~~~~~~~~~~

More real-world examples can be found in the ``docs/examples`` directory. To run
them, make sure you do ``make examples`` to generate the required resources.


Deviations from the Python Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because ``end`` is a Lua keyword, ``mem_regions()`` returns tables whose record
names are ``begins``, ``ends``, and ``perms`` rather than ``begin``, ``end``,
``perms``.

Requirements
------------

This project has the following dependencies. Ensure you have them installed
before using.

* Lua 5.1 or higher, as well as the static library and headers. Lua 5.3 and above
  must *not* have been compiled with the ``LUA_32BITS`` option set.
* A C++ compiler supporting the C++11 standard or later. Supported compilers include
  GCC 4.1+ and GCC-compatible compilers like Clang.
* The `Unicorn CPU Emulator`_ library must be installed in your system's standard
  library location. Currently only Unicorn 1.x is supported.
* You must also have the Unicorn headers installed.
* Some examples have additional dependencies; see their READMEs for details.

Just Installing?
----------------

If you just want to install this library, open a terminal, navigate to the root
directory of this repository, and run

.. code-block:: sh

    luarocks build


Development
-----------

Using a virtual environment for Lua is strongly recommended. You'll want to avoid
using your OS's real Lua, and using virtual environments allows you to test with
multiple versions of Lua. You can use `lenv <https://github.com/mah0x211/lenv>`_
for this.

If you're running MacOS and encounter a linker error with LuaJIT, check out
`this ticket <https://github.com/LuaJIT/LuaJIT/issues/449>`_.


Building and Testing
~~~~~~~~~~~~~~~~~~~~

.. code-block:: sh

    # Build and install the library into your tree
    luarocks build

    # Build and run the tests
    luarocks test

Examples
--------

See the ``examples`` directory for examples of how you can use this library.

License
-------

See NOTICE.txt and LICENSE.txt for details. I'm legally required to release this
under GPL 2+ due to QEMU's license, so please don't ask me to change this to MIT
or 3-clause BSD. Sorry.


**Footnotes**

.. [1] Typically 2\ :sup:`63` - 1 on 64-bit machines and 2\ :sup:`31` - 1 on
       32-bit machines.
.. [2] *Programming in Lua*, 4th Edition, page 233.

.. _Unicorn CPU Emulator: http://www.unicorn-engine.org
