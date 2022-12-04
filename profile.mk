LUA ?= $(or $(shell which lua), lua)

ifdef LUAROCKS
	F_LUAROCKS := -r "$(LUAROCKS)"
else
	F_LUAROCKS :=
endif

ifeq ($(abspath $(LUA)), $(LUA))
	F_LUA := -l "$(LUA)"
else
	F_LUA :=
endif


PROFILE = $(LUA) tools/profile_lua.lua $(F_LUA) $(F_LUAROCKS) -p "$(MAKE_HOST)"


.PHONY: all
all: lua-profile.cmake lua-profile.mk


lua-profile.mk: tools/profile_lua.lua
	$(PROFILE) -f make $@


lua-profile.cmake: tools/profile_lua.lua
	$(PROFILE) -f cmake $@


$(BUILD_DIR): lua-profile.cmake
	cmake -S . -B build\
		-DCMAKE_INSTALL_PREFIX=$(INST_LIBDIR)  \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE)       \
		-DCMAKE_VERBOSE_MAKEFILE=YES           \
		-DLUAROCKS=$(LUAROCKS)
