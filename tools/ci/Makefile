UNICORN_DIRECTORY=__unicorn_repo

ifeq ($(OS),Windows_NT)
	CI_UNICORN_INSTALL_RULE=install_unicorn__windows
else
	CI_UNICORN_INSTALL_RULE=install_unicorn__unix
endif


$(UNICORN_DIRECTORY):
	git clone -q --depth 1 https://github.com/unicorn-engine/unicorn.git $@
	git -C $@ fetch -q --all --tags --prune
	git -C $@ checkout $(UNICORN_VERSION)


.PHONY: install_unicorn
install_unicorn: $(CI_UNICORN_INSTALL_RULE)


.PHONY: install_unicorn__unix
install_unicorn__unix: $(UNICORN_DIRECTORY)
	$(MAKE) -C $<
	cd $< && sudo ./make.sh install


.PHONY: install_unicorn__windows
install_unicorn__windows:
	python3 install-unicorn-windows.py $(UNICORN_VERSION)
