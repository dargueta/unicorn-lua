/**
 * Miscellaneous utilities used by the Unicorn Lua binding.
 *
 * @file utils.h
 */

#ifndef INCLUDE_UNICORNLUA_UTILS_H_
#define INCLUDE_UNICORNLUA_UTILS_H_

#include <stdexcept>

#include <unicorn/unicorn.h>

#include "unicornlua/lua.h"


/**
 * Throw a Lua error with a message derived from the given Unicorn error code.
 *
 * @param L         A pointer to the current Lua state.
 * @param error     A unicorn error code.
 *
 * @note Like lua_error, this function never returns, and should be treated in
 * exactly the same way.
 */
int ul_crash_on_error(lua_State *L, uc_err error);


/**
 * Create a new weak table with the given key mode, and push it onto the stack.
 *
 * @param L         A pointer to the current Lua state.
 * @param mode      The table mode to use. See the Lua documentation for a full
 *                  description of valid modes and how they work.
 */
void ul_create_weak_table(lua_State *L, const char *mode);

struct NamedIntConst {
    const char *name;
    lua_Integer value;
};

void load_int_constants(lua_State *L, const struct NamedIntConst *constants);


/**
 * Count the number of items in the table.
 *
 * `luaL_len()` only returns the number of entries in the array part of a table,
 * so this function iterates through the entirety of the table and returns the
 * result. */
int count_table_elements(lua_State *L, int table_index);

/**
 * Something like a heap, but managed by Lua.
 *
 * @tparam T    The datatype of the item being allocated.
 */
template <class T>
class LuaResourceTable {
public:
    explicit LuaResourceTable(
        lua_State *L, bool weak_references = false, lua_CFunction destructor = nullptr
    ) : L_(L), destructor_(destructor) {
        if (weak_references)
            ul_create_weak_table(L_, "v");
        else
            lua_newtable(L_);
        table_ref_ = luaL_ref(L_, LUA_REGISTRYINDEX);
    }

    ~LuaResourceTable() {
        free_all();
        luaL_unref(L_, LUA_REGISTRYINDEX, table_ref_);
    }

    T * allocate(bool leave_object_on_stack) {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int table_index = lua_gettop(L_);

        T *item = reinterpret_cast<T *>(lua_newuserdata(L_, sizeof(T)));

        // If the user wants the Lua object left on the stack, we need to make a
        // copy, because luaL_ref removes the original one from the stack.
        if (leave_object_on_stack)
            lua_pushvalue(L_, -1);

        luaL_ref(L_, table_index);

        // Remove the table from the stack. We can't use lua_pop() because there
        // may be a copy of the userdata there that the caller wanted.
        lua_remove(L_, table_index);
        return item;
    }

    void free(T *item) {
        int value_reference = get_value_reference(item);

        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        if (destructor_ != nullptr) {
            lua_geti(L_, -1, value_reference);
            destructor_(L_);
            lua_pop(L_, 1);
        }
        luaL_unref(L_, -1, value_reference);
        lua_pop(L_, 1);
    }

    void free_all() {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int table_index = lua_gettop(L_);

        lua_pushnil(L_);
        while (lua_next(L_, table_index) != 0) {
            // Lua value TOS, integer key below it. If we were given a dtor,
            // invoke it on the Lua value.
            // FIXME (dargueta): Don't check for NULL on every iteration.
            if (destructor_ != nullptr)
                destructor_(L_);

            // Remove the value from TOS; the key is now at the top.
            lua_pop(L_, 1);

            // Remove this entry from the table.
            int element_ref = lua_tointeger(L_, -2);
            luaL_unref(L_, table_index, element_ref);
        }

        // Remove the table from the stack.
        lua_pop(L_, 1);
    }

private:
    lua_State *L_;
    lua_CFunction destructor_;
    int table_ref_;

    int get_value_reference(const T *item) const {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int table_index = lua_gettop(L_);

        lua_pushnil(L_);
        while (lua_next(L_, table_index) != 0) {
            // Lua value TOS, integer reference below it.
            if (lua_touserdata(L_, -1) != item) {
                lua_pop(L_, 1);
                continue;
            }

            int value_reference = lua_tointeger(L_, -2);
            // Pop the value, key, and table off the stack
            lua_pop(L_, 3);
            return value_reference;
        }

        // Pop the table off the stack to leave it as it was before the function
        // call.
        lua_pop(L_, 1);
        throw std::invalid_argument(
            "Could not find the specified item in the managed table."
        );
    }
};

#endif  /* INCLUDE_UNICORNLUA_UTILS_H_ */
