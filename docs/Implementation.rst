Implementation Details
======================

aka "Wait why did I do it this way? Huh?"

Engines
-------

An engine is a full userdata object with instance methods attached to it via the
``__index`` metatable. Its metatable also defines ``__gc`` so it'll close itself
once it goes out of scope.

The *data* part of the full userdata is a ``UCLuaEngine`` object that contains
the Unicorn C engine and a set of its active hooks.

Hooks
-----

The table of active hooks for an given engine is stored in the ``UCLuaEngine``
object. The engine's destructor will delete this table when the engine is closed
or garbage collected.

Contexts
--------

Contexts are implemented similar to hooks, except they're structs allocated by
Lua, not classes allocated on the heap.

They are directly managed by engines because of the required cleanup order. To
signal a context has been cleaned up, its fields are nulled out by the engine if
Lua cleans up the engine before it cleans up the context. This way, when the
context gets garbage collected, it will detect that its resources have already
been freed and it does nothing.

Bookkeeping Tables
------------------

The library relies on some tables in the C registry for keeping track of active
engines, hooks, and using pointers to get engine objects.

Engine Pointers
~~~~~~~~~~~~~~~

A table in the C registry is used to store a pointer from a ``uc_engine`` (the
Unicorn engine object) to the corresponding Lua object wrapping it. This way, in
a callback we can always have the Lua engine object and call methods on it.

Callbacks
~~~~~~~~~

Callbacks for hooks are stored with hard references in the C registry to prevent
them from being garbage-collected when the hook it's registered to is still
active. Once a hook is deleted, the corresponding callback is removed from the C
registry.
