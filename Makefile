LUAROCKS ?= luarocks
BUILD_DIR := build.luarocks


.PHONY: install
install:
	$(LUAROCKS) build


.PHONY: test
test:
	$(LUAROCKS) make
	$(LUAROCKS) test


.PHONY: clean
clean:
	git clean -Xf
	$(RM) -r $(BUILD_DIR)
