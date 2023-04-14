UNICORN_DIRECTORY=__unicorn_repo
UNICORN_MAJOR_VERSION := $(firstword $(subst ., ,$(UNICORN_VERSION)))


OS ?= $(shell uname -s)
ifeq ($(OS),Windows_NT)
    CI_UNICORN_INSTALL_RULE=install_unicorn__windows
else
    ifeq ($(UNICORN_MAJOR_VERSION),1)
        CI_UNICORN_INSTALL_RULE=install_unicorn__unix__1
    else
        CI_UNICORN_INSTALL_RULE=install_unicorn__unix__2
    endif
endif


$(UNICORN_DIRECTORY):
	git clone -q --depth 1 https://github.com/unicorn-engine/unicorn.git $@
	git -C $@ fetch -q --all --tags --prune
	git -C $@ checkout $(UNICORN_VERSION)


.PHONY: install_unicorn
install_unicorn: $(CI_UNICORN_INSTALL_RULE)


# Installation for Unicorn 1.x
.PHONY: install_unicorn__unix__1
install_unicorn__unix__1: $(UNICORN_DIRECTORY)
	@echo "Installing Unicorn $(UNICORN_MAJOR_VERSION)"
	$(MAKE) -C $<
	cd $< && sudo ./make.sh install


# Installation for Unicorn 2.x
.PHONY: install_unicorn__unix__2
install_unicorn__unix__2: $(UNICORN_DIRECTORY)
	@echo "Installing Unicorn $(UNICORN_MAJOR_VERSION)"
	cmake -S $(UNICORN_DIRECTORY) -B $(UNICORN_DIRECTORY)/build -DCMAKE_BUILD_TYPE=Release
	$(MAKE) -C $(UNICORN_DIRECTORY)/build
	sudo $(MAKE) -C $(UNICORN_DIRECTORY)/build install


.PHONY: install_unicorn__windows
install_unicorn__windows:
	python3 install-unicorn-windows.py $(UNICORN_VERSION)
