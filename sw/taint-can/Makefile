all : main.cpp irq.c irq.h bootstrap.S
	riscv32-unknown-elf-gcc main.cpp irq.c bootstrap.S -o main -nostartfiles -Wl,--no-relax

clean:
	rm -f main

sim: all
	riscv-dfa main
