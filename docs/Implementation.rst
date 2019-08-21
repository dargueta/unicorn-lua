Implementation Details
======================

aka "Wait why did I do it this way? Huh?"

Engines
-------

An engine is a full userdata object with instance methods attached to it via the
``__index`` metatable. Its metatable also defines ``__gc`` so it'll close itself
once it goes out of scope.

The *data* part of the full userdata is a ``UCLuaEngine`` struct that contains
the Unicorn C engine and a hard reference to the table containing its active
hooks (see below).

Hooks
-----

The table of active hooks for an given engine is (unfortunately) stored in the
registry. The engine's destructor will delete this table when the engine is closed
or garbage collected.

In an ideal world we'd store the hooks in an ephemeron table, where an engine
object is the key and the value is a table of hooks for that specific engine.
The hooks would be automatically released when the engine is garbage-collected.
Unfortunately, LuaJIT apparently has a tendency to attempt to release the hooks
table *after* the engine has already been collected, causing an error.

Bookkeeping Tables
------------------

The library relies on some tables in the C registry for keeping track of active
engines, hooks, and using pointers to get engine objects.

Engine Pointers
~~~~~~~~~~~~~~~

A table in the C registry is used to store a pointer from a ``uc_engine`` (the
Unicorn engine object) to the corresponding Lua object wrapping it. This way, in
a callback we can always have the Lua engine object and call methods on it.

Hook Tables
~~~~~~~~~~~

Each engine keeps its hook table in the registry. The engine has a hard reference
to it so the hook table will get orphaned if the engine fails to delete it, e.g.
in an "emergency collection" cycle.

Callbacks
~~~~~~~~~

Callbacks for hooks are also stored with hard references in the registry.
