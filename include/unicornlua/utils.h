/**
 * Miscellaneous utilities used by the Unicorn Lua binding.
 *
 * @file utils.h
 */

#ifndef INCLUDE_UNICORNLUA_UTILS_H_
#define INCLUDE_UNICORNLUA_UTILS_H_

#include <new>
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
class WeakLuaAllocator {
public:
    explicit WeakLuaAllocator(
        lua_State *L, lua_CFunction destructor = nullptr
    ) : L_(L), destructor_(destructor) {
        ul_create_weak_table(L_, "v");
        table_ref_ = luaL_ref(L_, LUA_REGISTRYINDEX);
    }

    ~WeakLuaAllocator() {
        free_all();
        luaL_unref(L_, LUA_REGISTRYINDEX, table_ref_);
    }

    T *allocate() {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int table_index = lua_gettop(L_);

        T *item = reinterpret_cast<T *>(lua_newuserdata(L_, sizeof(T)));
        if (item == nullptr) {
            // Remove the allocation table from the stack and blow up.
            lua_pop(L_, 1);
            throw std::bad_alloc();
        }

        // Because we need to return the userdata at the top of the stack, we
        // need to make a copy of it and use that as the value to store in the
        // table.
        lua_pushvalue(L_, -1);
        lua_rawsetp(L_, table_index, item);

        // Remove the table from the stack. We can't use lua_pop() because the
        // top of the stack contains the copy of the userdata the caller wanted.
        lua_remove(L_, table_index);
        return item;
    }

    void free(T *item) {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int table_index = lua_gettop(L_);

        // Check to see if the pointer exists in our allocation table. If it
        // doesn't exist, we either already freed it or it never existed here
        // in the first place.
        lua_rawgetp(L_, table_index, item);
        if (lua_isnil(L_, -1)) {
            // Get rid of nil and our allocation table, then crash.
            lua_pop(L_, 2);
            throw std::invalid_argument("Pointer not found in allocator table.");
        }

        // The top of the stack is the userdata, allocation table is underneath
        // it.
        if (destructor_ != nullptr)
            destructor_(L_);

        // Get rid of the userdata value on the stack. It's still present in the
        // allocation table.
        lua_pop(L_, 1);

        // Deallocate the userdata by setting its entry in the allocation table
        // to nil.
        lua_pushnil(L_);
        lua_rawsetp(L_, table_index, item);

        // Remove the allocation table from the stack.
        lua_pop(L_, 1);
    }

    void free_all() {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int table_index = lua_gettop(L_);

        lua_pushnil(L_);
        while (lua_next(L_, table_index) != 0) {
            // Lua value TOS, pointer key below it.
            // FIXME (dargueta): Don't check for NULL on every iteration.
            if (destructor_ != nullptr)
                destructor_(L_);

            // Remove the value from TOS; the key is now at the top.
            lua_pop(L_, 1);

            // Remove this entry from the allocation table by assigning its
            // value to nil.
            auto item = reinterpret_cast<const T *>(lua_touserdata(L_, -1));
            lua_pushnil(L_);
            lua_rawsetp(L_, table_index, item);
        }

        // Remove the allocation table from the stack.
        lua_pop(L_, 1);
    }

    int size() const noexcept {
        lua_geti(L_, LUA_REGISTRYINDEX, table_ref_);
        int count = luaL_len(L_, -1);
        lua_pop(L_, 1);
        return count;
    }

private:
    lua_State *L_;
    lua_CFunction destructor_;
    int table_ref_;
};

#endif  /* INCLUDE_UNICORNLUA_UTILS_H_ */
