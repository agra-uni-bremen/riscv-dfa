all : main.cpp
	riscv32-unknown-elf-g++ -ggdb -std=c++14 main.cpp -o main -march=rv32g -mabi=ilp32d
	
dump-elf: all
	riscv32-unknown-elf-readelf -a main
	
dump-code: all
	riscv32-unknown-elf-objdump -D main
	
clean:
	rm -f main
