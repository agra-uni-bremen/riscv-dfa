vps: vp/build/Makefile vp/dependencies/systemc-dist
	make install -C vp/build -j6

vp/dependencies/systemc-dist:
	cd vp/dependencies/ && ./build_systemc_232.sh

all: vps vp-display

vp/build/Makefile:
	mkdir vp/build || true
	cd vp/build && cmake ..

env/basic/vp-display/build/Makefile:
	mkdir env/basic/vp-display/build || true
	cd env/basic/vp-display/build && cmake ..

vp-display: env/basic/vp-display/build/Makefile
	make -C  env/basic/vp-display/build -j4

vp-clean:
	rm -rf vp/build

qt-clean:
	rm -rf env/basic/vp-display/build

sysc-clean:
	rm -rf vp/dependencies/systemc*

clean-all: vp-clean qt-clean sysc-clean

clean: vp-clean

