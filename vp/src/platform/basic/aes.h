#pragma once

#include <cstdlib>
#include <cstring>

#include <systemc>

#include <tlm_utils/simple_target_socket.h>

#include "core/common/irq_if.h"

struct AES : public sc_core::sc_module {
	tlm_utils::simple_target_socket<AES> tsock;


	static const uint8_t blocksize = 64;
	// memory mapped data frame
	std::array<Taint<uint8_t>, blocksize> key_frame;
	std::array<Taint<uint8_t>, blocksize> data_frame;

	// memory mapped configuration registers

	std::unordered_map<uint64_t, uint32_t *> addr_to_reg;

	static const uint8_t ACTION_REG_ADDR = 0x0;
	static const uint8_t KEY_REG_ADDR    = ACTION_REG_ADDR + 0x4;
	static const uint8_t MEM_REG_ADDR    = KEY_REG_ADDR + blocksize;

	SC_HAS_PROCESS(SimpleSensor);

	AES(sc_core::sc_module_name){
		tsock.register_b_transport(this, &AES::transport);
	}

	void transport(tlm::tlm_generic_payload &trans, sc_core::sc_time&) {
		auto addr = trans.get_address();
		auto cmd = trans.get_command();
		auto len = trans.get_data_length();
		auto ptr = reinterpret_cast<Taint<uint8_t> *>(trans.get_data_ptr());



		if (addr >= MEM_REG_ADDR) {
			auto reg_offset = addr - MEM_REG_ADDR;
			// access data frame
			assert((reg_offset + len) <= data_frame.size());
			if (cmd == tlm::TLM_READ_COMMAND) {
				memcpy((void*)ptr, &data_frame[reg_offset], len * sizeof(Taint<uint8_t>));
			}else if(cmd == tlm::TLM_WRITE_COMMAND) {
				memcpy((void*)(&data_frame[reg_offset]), ptr, len * sizeof(Taint<uint8_t>));
			}
		}
		else if(addr >= KEY_REG_ADDR) {
			auto reg_offset = addr - KEY_REG_ADDR;
			// access data frame
			assert((reg_offset + len) <= key_frame.size());
			//Key is write only
			assert(cmd == tlm::TLM_WRITE_COMMAND);

			for(unsigned i = 0; i < len; i++)
			{

				key_frame[reg_offset + i] = ptr[i];
			}

		} else {
			assert(len < 5);
			if(cmd == tlm::TLM_WRITE_COMMAND)
			{
				uint8_t action = *ptr;
				switch(action)
				{
				case 01: //encrypt mockup
					for(uint8_t i = 0; i < blocksize; i++)
					{
						//This downgrades the confidential data
						//Here, you would need to show the quality of encryption
						data_frame[i] = (data_frame[i] ^ key_frame[i]).require(MergeStrategy::highest);
					}
					break;
				case 02: //decrypt mockup
					for(uint8_t i = 0; i < blocksize; i++)
					{
						data_frame[i] = data_frame[i] ^ key_frame[i];
					}
					break;
				default:
					assert(false && "invalid command");
				}
			}
			else
			{
				memset((void*)ptr, 0, len * sizeof(Taint<uint8_t>));
			}
		}
	}
};
