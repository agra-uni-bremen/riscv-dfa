NPROCS:=$(shell grep -c ^processor /proc/cpuinfo)

vps: vp/build/Makefile vp/dependencies/systemc-dist
	make install -C vp/build -j$(NPROCS)

vp/dependencies/systemc-dist:
	cd vp/dependencies/ && ./build_systemc_232.sh

all: vps vp-display

vp/build/Makefile:
	mkdir vp/build || true
	cd vp/build && cmake -DCMAKE_BUILD_TYPE=Debug ..

vp-clean:
	rm -rf vp/build

sysc-clean:
	rm -rf vp/dependencies/systemc*

clean-all: vp-clean qt-clean sysc-clean

clean: vp-clean

codestyle:
	find . -name "*.h*" -o -name "*.cpp" | xargs clang-format -i -style=file      #file is .clang-format
