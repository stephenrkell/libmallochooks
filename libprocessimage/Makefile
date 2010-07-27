default: lib

.PHONY: src
src:
	$(MAKE) -C src

.PHONY: clean
clean:
	$(MAKE) -C src clean

.PHONY: lib
lib: src
	cd lib && ln -sf ../src/libprocessimage.so .
