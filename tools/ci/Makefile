ifeq ($(OS),Windows_NT)
	CI_UNICORN_INSTALL_RULE=install_unicorn__windows
else
	CI_UNICORN_INSTALL_RULE=install_unicorn__unix
endif


.PHONY: install_unicorn
install_unicorn: $(CI_UNICORN_INSTALL_RULE)


.PHONY: install_unicorn__unix
install_unicorn__unix:
	git clone --depth 1 https://github.com/unicorn-engine/unicorn.git unicorn-$(UNICORN_VERSION)
	git -C unicorn-$(UNICORN_VERSION) fetch --all --tags --prune
	git -C unicorn-$(UNICORN_VERSION) checkout $(UNICORN_VERSION)
	unicorn-$(UNICORN_VERSION)/make.sh
	sudo unicorn-$(UNICORN_VERSION)/make.sh install


.PHONY: install_unicorn__windows
install_unicorn__windows:
	python3 install-unicorn.py $(UNICORN_VERSION)
