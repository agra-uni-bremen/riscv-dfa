all: vp/build/Makefile
	make install -C vp/build -l4

vp/build/Makefile:
	mkdir vp/build || true
	cd vp/build && cmake ..

clean:
	rm -rf vp/build

clean-all: clean
