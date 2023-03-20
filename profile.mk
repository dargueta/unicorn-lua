LUA ?= $(or $(shell which lua), lua)

BUILD_TYPE ?= release
BUILD_DIR ?= cmake-build-$(BUILD_TYPE)


ifdef LUAROCKS
	F_LUAROCKS := -r "$(LUAROCKS)"
else
	F_LUAROCKS :=
endif


# Only pass `LUA` to the profiling script if it's an absolute path.
ifeq ($(abspath $(LUA)), $(LUA))
	F_LUA := -l "$(LUA)"
else
	F_LUA :=
endif


PROFILE = $(LUA) tools/profile_lua.lua $(F_LUA) $(F_LUAROCKS) -p "$(MAKE_HOST)"


.PHONY: all
all: lua-profile.mk lua-profile.cmake


lua-profile.mk: tools/profile_lua.lua
	$(PROFILE) -f make $@
	echo "\nBUILD_TYPE=$(BUILD_TYPE)" >> $@

lua-profile.cmake: tools/profile_lua.lua
	$(PROFILE) -f cmake $@
