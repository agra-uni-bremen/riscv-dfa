.PHONY: tainttest
tainttest: tainttest.cpp
	g++ -g tainttest.cpp -o tainttest

test: tainttest
	./tainttest

debug: tainttest
	gdb ./tainttest
