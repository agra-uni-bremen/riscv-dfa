#pragma once

#include <systemc>

#include <tlm_utils/simple_target_socket.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>


struct FileLoader : public sc_core::sc_module {
	tlm_utils::simple_target_socket<FileLoader> tsock;
	std::fstream file;
	bool readonly;

	uint32_t file_offs = 0x1000;	//Where actual file contents are
	uint32_t filesize = 0;


	FileLoader(sc_core::sc_module_name, std::string path, bool readonly = true)
		 : readonly(readonly){
		tsock.register_b_transport(this, &FileLoader::transport);
		file.open(path, readonly ? std::ios::in : (std::ios::in | std::ios::out));
		if(file.is_open())
		{
			file.seekg(0, file.end);
			filesize = file.tellg();
			//no need to rewind
		}
	}

	void transport(tlm::tlm_generic_payload &trans, sc_core::sc_time&) {

		assert(file.is_open() && "Inputfile not opened");

		auto addr = trans.get_address();
		auto cmd = trans.get_command();
		auto len = trans.get_data_length();
		auto ptr = reinterpret_cast<Taint<uint8_t> *>(trans.get_data_ptr());

		if(addr < file_offs)		//metadata
		{
			assert(cmd == tlm::TLM_READ_COMMAND && "Write to read-only register");
			assert(len == 4 && "only allow to read whole register");
			switch(addr)
			{
			case 0:
				for(unsigned i = 0; i < len; i++)
				{
					ptr[i] = reinterpret_cast<uint8_t*>(&file_offs)[i];
				}
				break;
			case sizeof(uint32_t):
				for(unsigned i = 0; i < len; i++)
				{
					ptr[i] = reinterpret_cast<uint8_t*>(&filesize)[i];
				}
				break;
			default:
				assert(0 && "accessed invalid register");
			}
		}
		else	//data section
		{
			assert(len < 16);
			char buf[len];
			file.seekg(addr-file_offs, file.beg);
			if (cmd == tlm::TLM_WRITE_COMMAND) {
				assert(readonly == false && "Tried writing to readonly file");
				for(unsigned i = 0; i < len; i++)
				{
					buf[i] = ptr[i];		//if some sort of security class, require here
				}
				file.write(buf, len);
			} else {		//READ
				file.read(buf, len);
				for(unsigned i = 0; i < len; i++)
				{
					ptr[i] = buf[i];
				}
			}
		}
	}
};
