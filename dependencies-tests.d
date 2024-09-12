tests/c/compat.o: tests/c/compat.cpp tests/c/doctest.h tests/c/fixtures.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp
tests/c/context.o: tests/c/context.cpp include/unicornlua/context.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp tests/c/doctest.h tests/c/fixtures.hpp \
 include/unicornlua/errors.hpp
tests/c/engine.o: tests/c/engine.cpp tests/c/doctest.h tests/c/fixtures.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp include/unicornlua/context.hpp \
 include/unicornlua/errors.hpp
tests/c/fixtures.o: tests/c/fixtures.cpp tests/c/doctest.h tests/c/fixtures.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp
tests/c/hooks.o: tests/c/hooks.cpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 tests/c/doctest.h tests/c/fixtures.hpp include/unicornlua/engine.hpp \
 include/unicornlua/utils.hpp
tests/c/main.o: tests/c/main.cpp tests/c/doctest.h
tests/c/registers.o: tests/c/registers.cpp tests/c/doctest.h \
 include/unicornlua/registers.hpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/register_types.hpp
tests/c/utils.o: tests/c/utils.cpp tests/c/doctest.h tests/c/fixtures.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp
