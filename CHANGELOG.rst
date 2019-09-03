Changes
=======

1.0b3 (unreleased)
------------------

* Changed MIPS file extension from ``*.S`` to ``*.s``.
* Documented floating-point limitation in repo's README.
* Overhauled ``configure`` script to allow using the operating system's Lua installation. Using a
  virtual environment is no longer forced.

Significant refactor
~~~~~~~~~~~~~~~~~~~~

All files from ``src/constants`` were moved into ``src``, and the submodule
initialization functions were moved from ``unicornlua.c`` into their respective
submodules.

The corresponding headers under ``unicornlua/constants`` were all deleted except
``globals.h``, which was moved up to ``unicornlua``. All constant declaration
arrays were made static.

This refactor allows us to easily put architecture-specific functions inside the
submodules instead of only having constants in there.

1.0b2 (2019-08-21)
------------------

* Better documentation
* Add support for MIPS examples, describe cross-compilation toolchain
* Error handling for when memory allocation fails


1.0b1 (2019-06-27)
------------------

Minor change -- all X86 binaries for the examples are included, so you only need
``nasm`` if you're going to modify them.


1.0b0 (2019-04-13)
------------------

Initial release
