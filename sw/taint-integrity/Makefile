all: main atts

main : main.c
	riscv32-unknown-elf-gcc -g main.c -o main -march=rv32ima

atts: wilander_kamkar.c
	riscv32-unknown-elf-gcc -g wilander_kamkar.c -o atts -march=rv32ima

clean:
	rm -f main atts

sim: all
	riscv-vp main

test: atts
	riscv-vp --parameter 13 atts
