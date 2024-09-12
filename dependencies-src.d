src/basic_control_functions.o: src/basic_control_functions.cpp \
 include/unicornlua/control_functions.hpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/engine.hpp \
 include/unicornlua/hooks.hpp include/unicornlua/lua.hpp \
 include/unicornlua/utils.hpp include/unicornlua/errors.hpp \
 include/unicornlua/integer_conversions.hpp \
 include/unicornlua/unicornlua.hpp
src/compat.o: src/compat.cpp include/unicornlua/compat.hpp \
 include/unicornlua/lua.hpp
src/context.o: src/context.cpp include/unicornlua/context.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp include/unicornlua/errors.hpp
src/control_functions.o: src/control_functions.cpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/control_functions.hpp \
 include/unicornlua/lua.hpp include/unicornlua/engine.hpp \
 include/unicornlua/hooks.hpp include/unicornlua/utils.hpp \
 include/unicornlua/transaction.hpp
src/engine.o: src/engine.cpp include/unicornlua/context.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp include/unicornlua/control_functions.hpp \
 include/unicornlua/lua.hpp include/unicornlua/errors.hpp \
 include/unicornlua/memory.hpp include/unicornlua/registers.hpp \
 include/unicornlua/register_types.hpp include/unicornlua/unicornlua.hpp
src/errors.o: src/errors.cpp include/unicornlua/errors.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp
src/hooks.o: src/hooks.cpp include/unicornlua/engine.hpp \
 include/unicornlua/hooks.hpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/utils.hpp \
 include/unicornlua/errors.hpp include/unicornlua/transaction.hpp
src/memory.o: src/memory.cpp include/unicornlua/compat.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/utils.hpp
src/registers_const.o: src/registers_const.cpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/registers.hpp \
 include/unicornlua/register_types.hpp include/unicornlua/utils.hpp
src/registers.o: src/registers.cpp include/unicornlua/errors.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/registers.hpp include/unicornlua/register_types.hpp \
 include/unicornlua/register_template_functions.hpp
src/registers_misc.o: src/registers_misc.cpp include/unicornlua/compat.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/utils.hpp \
 include/unicornlua/errors.hpp include/unicornlua/registers.hpp \
 include/unicornlua/register_types.hpp
src/transaction.o: src/transaction.cpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/transaction.hpp
src/unicorn.o: src/unicorn.cpp include/unicornlua/context.hpp \
 include/unicornlua/engine.hpp include/unicornlua/hooks.hpp \
 include/unicornlua/lua.hpp include/unicornlua/compat.hpp \
 include/unicornlua/utils.hpp include/unicornlua/unicornlua.hpp
src/utils.o: src/utils.cpp include/unicornlua/lua.hpp \
 include/unicornlua/compat.hpp include/unicornlua/utils.hpp
