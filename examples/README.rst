Example Programs
================

There are some example programs you can use to see how this library (and Unicorn
in general) works. Due to file path issues they must be run from inside the
directory they're in, or via the Makefile in the root directory of the repo:

.. code-block:: sh

     make run_example EXAMPLE=name

``name`` is the name of the directory the example is in, e.g. ``disk_io`` or
``cmos_time``.


**Note:** Some of these examples may not work with LuaJIT.


Compiling X86 Examples
----------------------

You need an x86 assembler. All examples are written for `NASM <https://nasm.us>`_
but will most likely work with `YASM <https://yasm.tortall.net>`_ as well. Zero
guarantees are made for other assemblers.

Cross-Compiling MIPS Examples
-----------------------------

For building the examples written in MIPS assembly language, you're going to need
a cross-compiling toolchain. You can install it with one of the following options:

Linux (Debian & derivatives like Ubuntu)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Open a terminal and run the following:

.. code-block:: sh

    apt-get update
    sudo apt-get install gcc-multilib-mips-linux-gnu    \
                         linux-libc-dev-mips-cross      \
                         gcc-mipsel-linux-gnu

Linux (any distribution)
~~~~~~~~~~~~~~~~~~~~~~~~

I think `Crosstool-NG <http://crosstool-ng.github.io>`_ will get the job done,
however we don't support it yet.


Windows (Cygwin)
~~~~~~~~~~~~~~~~

Cygwin is an easy way to run Linux programs on your Windows machine. To get it,
go to their website `here <https://www.cygwin.com>`_.

Open the Cygwin installer and install the following packages:

* ``gcc-multilib-mips-linux-gnu`` (or ``gcc-mips-linux-gnu`` if you can't find it)
* ``linux-libc-dev-mips-cross``
* ``gcc-mipsel-linux-gnu``
