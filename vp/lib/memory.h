#ifndef RISCV_ISA_MEMORY_H
#define RISCV_ISA_MEMORY_H

#include <stdint.h>
#include <iostream>
#include <boost/iostreams/device/mapped_file.hpp>

#include "bus.h"

#include "systemc"
#include "tlm_utils/simple_target_socket.h"
#include "taint.hpp"

struct TaintedMemory : public sc_core::sc_module {
    tlm_utils::simple_target_socket<TaintedMemory> tsock;

    Taint<uint8_t> *data;
    uint32_t size;

    TaintedMemory(sc_core::sc_module_name, uint32_t size)
        : data(new Taint<uint8_t>[size]()), size(size) {
        tsock.register_b_transport(this, &TaintedMemory::transport);
    }

    ~TaintedMemory()
    {
    	delete[] data;
    }

    void load_binary_file(const std::string &filename, unsigned addr) {
        boost::iostreams::mapped_file_source f(filename);
        assert (f.is_open());
        for(unsigned i = 0; i < f.size(); i++)
        {
        	 data[addr + i] = f.data()[i];
        }
    }

    void write_data(unsigned addr, const Taint<uint8_t> *src, unsigned num_bytes) {
        assert (addr + num_bytes <= size);
        if(src[0].getTaintId() != 0)
        	printf("writing tainted data\n");
        memcpy(data + addr, src, num_bytes * sizeof(Taint<uint8_t>));
    }

    void read_data(unsigned addr, Taint<uint8_t> *dst, unsigned num_bytes) {
        assert (addr + num_bytes <= size);

        memcpy(dst, data + addr, num_bytes * sizeof(Taint<uint8_t>));
        for(uint8_t i = 0; i < num_bytes; i++)
        {
        	if(dst[i].getTaintId())
        	{
        		printf("reading tainted data\n");
        	}
        }
    }

    void transport(tlm::tlm_generic_payload &trans, sc_core::sc_time &delay) {
        tlm::tlm_command cmd = trans.get_command();
        unsigned addr = trans.get_address();
        Taint<uint8_t> *ptr = reinterpret_cast<Taint<uint8_t>*>(trans.get_data_ptr());
        auto len = trans.get_data_length();

        assert ((addr >= 0) && (addr < size));

        if(cmd == tlm::TLM_WRITE_COMMAND) {
            write_data(addr, ptr, len);
        } else if (cmd == tlm::TLM_READ_COMMAND) {
            read_data(addr, ptr, len);
        } else {
            sc_assert (false && "unsupported tlm command");
        }

        delay += sc_core::sc_time(10, sc_core::SC_NS);
    }
};


#endif //RISCV_ISA_MEMORY_H
