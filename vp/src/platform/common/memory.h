#ifndef RISCV_ISA_MEMORY_H
#define RISCV_ISA_MEMORY_H

#include <stdint.h>
#include <boost/iostreams/device/mapped_file.hpp>
#include <iostream>

#include "bus.h"

#include "systemc"
#include "taint.hpp"
#include "tlm_utils/simple_target_socket.h"

struct TaintedMemory : public sc_core::sc_module {
	tlm_utils::simple_target_socket<TaintedMemory> tsock;

	uint32_t size;
	Taint<uint8_t> *data;
	Taintlevel taint;

	TaintedMemory(sc_core::sc_module_name, uint32_t size) :
		          size(size), data(new Taint<uint8_t>[size]()), taint(0){
		tsock.register_b_transport(this, &TaintedMemory::transport);
	}

	TaintedMemory(sc_core::sc_module_name, uint32_t size, Taintlevel taint) :
		          size(size), data(new Taint<uint8_t>[size]()), taint(taint){
		for(unsigned i = 0; i < size; i++)
		{
			data[i] = Taint<uint8_t>(0, taint);
		}
		tsock.register_b_transport(this, &TaintedMemory::transport);
	}


	~TaintedMemory() { delete[] data; }

	void load_binary_file(const std::string &filename, unsigned addr) {
		boost::iostreams::mapped_file_source f(filename);
		assert(f.is_open());
		for (unsigned i = 0; i < f.size(); i++) {
			data[addr + i] = f.data()[i];
		}
	}

	void write_data(unsigned addr, const Taint<uint8_t> *src, unsigned num_bytes) {
		assert(addr + num_bytes <= size);
		memcpy((void*)(data + addr), src, num_bytes * sizeof(Taint<uint8_t>));
	}

	void read_data(unsigned addr, Taint<uint8_t> *dst, unsigned num_bytes) {
		assert(addr + num_bytes <= size);
		memcpy((void*)dst, data + addr, num_bytes * sizeof(Taint<uint8_t>));
	}

	void transport(tlm::tlm_generic_payload &trans, sc_core::sc_time &delay) {
		tlm::tlm_command cmd = trans.get_command();
		unsigned addr = trans.get_address();
		Taint<uint8_t> *ptr = reinterpret_cast<Taint<uint8_t> *>(trans.get_data_ptr());
		auto len = trans.get_data_length();

		assert(addr < size);

		if (cmd == tlm::TLM_WRITE_COMMAND) {
			write_data(addr, ptr, len);
		} else if (cmd == tlm::TLM_READ_COMMAND) {
			read_data(addr, ptr, len);
		} else {
			sc_assert(false && "unsupported tlm command");
		}

		delay += sc_core::sc_time(10, sc_core::SC_NS);
	}
};

#endif  // RISCV_ISA_MEMORY_H
