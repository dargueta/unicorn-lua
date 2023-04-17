Lua API
=======

This is a description of the Lua-facing UnicornLua API.

The Engine
----------

The Unicorn engine supports the following instance methods:

``close()``
~~~~~~~~~~~

Removes all hooks, frees contexts and memory, then closes the underlying Unicorn
engine. The object must not be used after this is called.


``context_restore(context)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Restore the given context object.


``context_save(context=nil)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Save the engine's current state into a new context object, or overwrites the
existing state in *context* if it's passed in. Passing in a state reuses the
existing memory.

*NOTE*: Engines do not hold references to context objects they create. A context
object is automatically garbage-collected if no references to it remain, so it's
up to you to ensure that you store the return value somewhere.

Arguments
^^^^^^^^^

``context``: Optional. Must be a context object previously returned by
``context_save()``. If given, the state in the context object will be overwritten
with the engine's current state. This saves on memory usage -- potentially a lot.

Returns
^^^^^^^

The newly-created context, or ``context`` if one was passed in.


``emu_start(start_address=0, end_address=nil, timeout=nil, max_instructions=nil)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Start emulation and return immediately.

Arguments
^^^^^^^^^

* ``start_address``: The address in memory to begin executing instructions at. If
  not given, defaults to 0.
* ``end_address``: The highest address in memory to allow instructions executing
  at. If not given, defaults to the end of memory.
* ``timeout``: The maximum number of seconds to execute.
* ``max_instructions``: The maximum number of instructions to execute.


``emu_stop()``
~~~~~~~~~~~~~~

Stop emulation. No resources (hooks, contexts, etc.) are freed and they continue
to be valid.


``errno()``
~~~~~~~~~~~

Return the numeric code of the last error that occurred inside the engine. The
constants for these error codes are in the ``unicorn`` namespace and begin with
``UC_ERR_``.


``ctl_exits_disable()``
~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_exits_enable()``
~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_flush_tlb()``
~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_arch()``
~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_cpu_model()``
~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_exits()``
~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_exits_cnt()``
~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_mode()``
~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_page_size()``
~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_get_timeout()``
~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_remove_cache(start_addr, end_addr)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_request_cache(address)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_set_cpu_model(model)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_set_exits(exits)``
~~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*

``ctl_set_page_size(page_size)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*New in 2.2.0 (requires Unicorn 2)*


``hook_add(kind, callback, start_address=nil, end_address=nil, udata=nil, ...)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add a new hook to this engine.

Arguments
^^^^^^^^^

* ``kind``: The type of hook to create. The constants are in the ``unicorn``
  namespace and begin with ``UC_HOOK_``.
* ``callback``: The Lua function to call when the hook fires. The arguments the
  hook is expected to accept depend on the type of the hook.
* ``start_address``: The lowest memory address this hook will be active for. If
  not given or ``nil``, defaults to 0.
* ``end_address``: The highest memory address this hook will be active for. If
  not given or ``nil``, defaults to the highest possible memory address.
* ``udata``: An additional argument to pass to the hook for its use, such as a
  file handle or a table. Unicorn keeps a hard reference to it in the registry
  until the hook is deleted, but otherwise doesn't care what it is.

Returns
^^^^^^^

A handle to the hook that was just created. Save this somewhere; without it, you
won't be able to remove the hook later. If you know you won't ever need to remove
the hook before closing the engine, you can ignore the return value.


``hook_del(handle)``
~~~~~~~~~~~~~~~~~~~~

Delete the given hook.


``mem_map(start, size, perms=UC_PROT_ALL)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Map in new (virtual) memory for use by the emulated processor.

Arguments
^^^^^^^^^

* ``start``: The starting address of the region of memory to map in.
* ``size``: The size of this region, in bytes.
* ``perms``: The permissions to attach to this memory region. If not given,
  all permissions (read/write/execute) are granted to the engine for this region.


``mem_protect(start, size, new_perms)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Change access permissions for the given region in memory.

Arguments
^^^^^^^^^

* ``start``: The starting address of the region of memory to modify.
* ``size``: The size of this region, in bytes.
* ``perms``: The new permissions to attach to this memory region.


``mem_read(start, size)``
~~~~~~~~~~~~~~~~~~~~~~~~~

Read ``size`` bytes from mapped memory starting at ``start``, and return it as a
string.

*NOTE*: All memory in the range ``[start, start + size)`` must already be mapped.
If any memory in that range is unmapped, it'll trigger an exception.

Arguments
^^^^^^^^^

* ``start``: The address in virtual memory to start reading from.
* ``size``: The number of bytes to read.

Returns
^^^^^^^

A string containing the bytes at the given memory location.


``mem_regions()``
~~~~~~~~~~~~~~~~~

Get a list of currently mapped memory regions, along with their assigned
permission flags. Example:

.. code-block:: lua

    local uc = unicorn.open(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)

    -- Map in 1 MiB total
    uc:mem_map(0, 2 ^ 20)

    -- Revoke write access to the VGA and BIOS ROM shadow areas.
    uc:mem_protect(0xC0000, 32 * 1024, unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    uc:mem_protect(0xF0000, 64 * 1024, unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)

    -- Get all the defined memory regions.
    local regions = uc:mem_regions()

The return value is a table containing one entry per memory region, in no
guaranteed order. Each entry is a table with three keys:

* ``starts``: The starting address of this memory region.
* ``ends``: The last valid address in this memory region, i.e. the *inclusive*
  upper bound.
* ``perms``: The permission flags for this region.

Thus, for the above example, the returned table would have the following entries
(sorted here for ease of reading):

* ``starts``: 0, ``ends``: 786431, ``perms``: UC_PROT_ALL
* ``starts``: 786432, ``ends``: 819199, ``perms``: UC_PROT_READ|UC_PROT_EXEC
* ``starts``: 819200, ``ends``: 983039, ``perms``: UC_PROT_ALL
* ``starts``: 983040, ``ends``: 1048575, ``perms``: UC_PROT_READ|UC_PROT_EXEC


``mem_unmap(start, size)``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Unmap a region of virtual memory from the engine. Hooks spanning this region are
*not* removed.

Arguments
^^^^^^^^^

* ``start``: The start of the memory region to release.
* ``size``: The number of bytes starting from ``start`` to free.


``mem_write(address, string)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Write bytes to an address in virtual memory.

Arguments
^^^^^^^^^

* ``address``: The address to begin writing data to.
* ``string``: The data to write into virtual memory.

*Note*: The region ``[address, address + #string)`` must be mapped in already.
If any part of that span is unmapped, it'll trigger an error.


``query(setting_id)``
~~~~~~~~~~~~~~~~~~~~~

Query a setting of the engine.

Arguments
^^^^^^^^^

``setting_id``: The ID of the setting to query. These can be found in the ``unicorn``
namespace and begin with ``UC_QUERY_``.

Returns
^^^^^^^

The value of the setting. This is usually an integer.

``reg_read(reg_id)``
~~~~~~~~~~~~~~~~~~~~

Read the value of a register as a 32- or 64-bit signed integer. [*]_

Arguments
^^^^^^^^^

``reg_id`` is the ID of the register to read. The constants can be found in the
corresponding constants module for the architecture the engine is running. For
example, for an x86 engine:

.. code-block:: lua

    local x86 = require "unicorn.x86_const"

    -- Create your engine, run some code...
    local eax = engine:reg_read(x86.UC_X86_REG_EAX)
    print(eax)

Returns
^^^^^^^

The value of the register as a signed integer.


``reg_read_as(reg_id, type)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*Nonstandard function*

Read a register according to the given type. You can use this for reading the
large XMM, YMM, ZMM, AVX, and AVX-512 registers that are more than 64 bits. It's
also a (somewhat hacky) way to read a 64-bit integer register on Lua 5.2 and
earlier without loss of precision.

.. code-block:: lua

    -- Read XMM0 as an array of four 32-bit floating-point numbers.
    local values = {
      uc:reg_read_as(x86.UC_X86_REG_XMM0, unicorn.UL_REG_TYPE_FLOAT32_ARRAY_4)
    }

Arguments
^^^^^^^^^

* ``reg_id``: The ID of the register to read.
* ``type``: An enum value indicating how to interpret the register. The constants
  are in the ``unicorn`` namespace and begin with ``UL_REG_TYPE_``.

Returns
^^^^^^^

What's returned is dictated by ``type``. This can be an integer, float, array of
integers, or array of floats.


``reg_read_batch(registers)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read multiple integer registers in one function call.

.. code-block:: lua

    local eax, ecx = engine:reg_read_batch({x86.UC_X86_REG_EAX, x86.UC_X86_REG_ECX})


Arguments
^^^^^^^^^

``registers``: A table with a list of all the IDs of the registers to read.

Returns
^^^^^^^

A table of all the registers read, in the order given in the function call.


``reg_read_batch_as(registers_and_types)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*Nonstandard function*

This is essentially ``reg_read_as()`` but allows you to read multiple registers
at once.

It reads multiple registers in one function call, reinterpreting them as
dictated by the values of the table argument.

.. code-block:: lua

    local values = engine:reg_read_batch_as {
        x86.UC_X86_REG_XMM0 = unicorn.UL_REG_TYPE_FLOAT32_ARRAY_4,
        x86.UC_X86_REG_RAX = unicorn.UL_REG_TYPE_INT8_ARRAY_8
    }

    -- Example of a possible return value
    --[[
        {
            x86.UC_X86_REG_XMM0 = {0.0, 3.1416, 2.71828, 1.0};
            x86.UC_X86_REG_RAX = {127, -3, 0, 5, 23, 96, -19, -100}
        }
    ]]

Arguments
^^^^^^^^^

``registers_and_types``: A table mapping the IDs of registers to read to a
constant indicating how that register should be interpreted.

Returns
^^^^^^^

A table mapping the register ID to the value(s) the register was interpreted as.


``reg_write(reg_id, value)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Write a numeric value to a register.

Arguments
^^^^^^^^^

* ``reg_id``: The ID of the register to write to.
* ``value``: The value to write to the register. Must be a signed integer. If
  this is a floating-point value, it'll be truncated to an integer. Any other
  kind of value will trigger an error.


``reg_write_as(reg_id, value, type)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*Nonstandard function*

Write a value to a register according to the given type. This is most useful for
writing to the large XMM, YMM, ZMM, AVX, and AVX-512 registers that are more than
64 bits. It's also a (somewhat hacky) way to write to a 64-bit integer register
on Lua 5.2 and earlier without loss of precision.

.. code-block:: lua

    -- Write to a 64-bit register as an array of two 32-bit integers.
    uc:reg_write_as(
      x86.UC_X86_REG_RCX, {-123456, 500}, unicorn.UL_REG_TYPE_INT32_ARRAY_2
    )


Arguments
^^^^^^^^^

* ``reg_id``: The ID of the register to write to. See ``reg_write()``.
* ``value``: The value to write to the register. This will be an integer, float,
  table of integers, or table of floats. The exact type is dictated by the ``type``
  argument.
* ``type``: An enum value dictating how to interpret ``value`` when writing to
  the register. The constants are in the ``unicorn`` namespace and begin with
  ``UL_REG_TYPE_``.


``reg_write_batch(values)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Write to multiple registers with a single function call.

Arguments
^^^^^^^^^

``values``: A table mapping register IDs to the values to write to those registers.


Contexts
--------

``free()``
~~~~~~~~~~

Release the resources of this context object. It can no longer be used.
Note: (This still works correctly if the library is compiled against Unicorn
1.0.1 and older, before Unicorn added ``uc_context_free()``.)

*New in 1.1.0*


Globals
-------

These live in the ``unicorn`` namespace.

``LUA_LIBRARY_VERSION``
~~~~~~~~~~~~~~~~~~~~~~~

This is a three-element table giving the major, minor, and patch versions of the
Lua binding.

``arch_supported(architecture)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Query if the build of the Unicorn library was compiled for support for the given
architecture.

Arguments
^^^^^^^^^

``architecture``: An enum value for the architecture to ask about. Constants are
in the ``unicorn`` namespace and begin with ``UC_ARCH_``.

*Changed in 2.2.0:*

``unicorn.arch_supported`` now returns false if the architecture is nil instead
of crashing. This allows code to easily determine if an architecture is supported
without needing to check the Unicorn version AND assume that the Unicorn library
was compiled with all available architectures. For example:

Old way:

.. code-block:: lua

    local have_ppc
    if uc:version()[1] < 2 then
        have_ppc = false
    else
        have_ppc = uc.arch_supported(uc_const.UC_ARCH_PPC)
    end

New way:

.. code-block:: lua

    local have_ppc = uc.arch_supported(uc_const.UC_ARCH_PPC)


Returns
^^^^^^^

A boolean indicating if the architecture is supported. An unrecognized value for
``architecture`` will always return ``false``.


``open(architecture, mode)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a new engine with the given architecture and execution mode.

Arguments
^^^^^^^^^

* ``architecture``: An enum value indicating the architecture for the new engine.
Constants are in the ``unicorn`` namespace and begin with ``UC_ARCH_``. An
unsupported architecture will trigger an error, so you may want to check to see
if the architecture is supported first using ``arch_supported()``.

* ``mode``: Mode flags specific to the architecture. For example, to start an
  ARM64 machine in big-endian mode, pass ``UC_MODE_BIG_ENDIAN``. Multiple flags
  must be OR'ed together. Not all architectures support all options; see the
  Unicorn documentation for details.

Returns
^^^^^^^

The engine object.


``strerror(errno)``
~~~~~~~~~~~~~~~~~~~

Get the error message for the given error code.

Arguments
^^^^^^^^^

``errno``: A valid error code. The constants are in the ``unicorn`` namespace and
begin with ``UC_ERR_``.

Returns
^^^^^^^

The error message the library associates with the error code, as a string.


``version()``
~~~~~~~~~~~~~

Get the version of the Unicorn library this library was compiled against.

Returns
^^^^^^^

Two integers -- the major and minor version of the library, respectively.


.. [*] Depends on if your Lua build is 32 or 64 bits. Lua 5.2 and older don't
       have integer support so only numbers requiring 53 bits or less will be
       accurately represented (on 64-bit builds).
