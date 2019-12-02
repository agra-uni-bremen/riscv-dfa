all : main.c irq.c irq.h bootstrap.S
	riscv32-unknown-elf-gcc main.c irq.c bootstrap.S -o main -nostartfiles -Wl,--no-relax

clean:
	rm -f main

sim: all
	riscv-vp main
