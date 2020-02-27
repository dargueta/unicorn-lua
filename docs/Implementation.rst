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
