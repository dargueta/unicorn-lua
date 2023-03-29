# common-variables.mk must be included before this

.PHONY: build
build: $(LIB_BUILD_TARGET) $(TEST_EXECUTABLE)

.PHONY: clean
clean:
	$(RM) $(LIB_OBJECT_FILES) $(CONSTANT_FILES) $(LIB_BUILD_TARGET)
	$(RM) $(TEST_EXECUTABLE) $(TEST_CPP_OBJECT_FILES)
	$(RM) -r $(BUILD_DIR) $(CONSTS_DIR)


$(CONSTS_DIR)/%_const.cpp: $(UNICORN_INCDIR)/unicorn/%.h | $(CONSTS_DIR)
	python3 tools/generate_constants.py $< $@


$(CONSTS_DIR):
	mkdir -p $@


# Provided for completeness; we should never need this as LuaRocks creates it
# for us.
$(BUILD_DIR):
	mkdir -p $@
