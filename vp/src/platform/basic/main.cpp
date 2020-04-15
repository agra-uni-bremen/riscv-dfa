#include <cstdlib>
#include <ctime>

#include "core/common/clint.h"
#include "platform/common/elf_loader.h"
#include "core/rv32/gdb_stub.h"
#include "core/rv32/iss.h"
#include "platform/common/memory.h"
#include "platform/common/plic.h"
#include "dma.h"
#include "flash.h"
#include "sensor.h"
#include "aes.h"
#include "sensor2.h"
#include "terminal.h"
#include "basic_timer.h"
#include "file_loader.h"

#include <boost/io/ios_state.hpp>
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>

struct Options {
	typedef unsigned int addr_t;

	Options &check_and_post_process() {
		mem_end_addr = mem_start_addr + mem_size - 1;
		return *this;
	}

	std::string input_program;
	std::string test_signature;
	std::string parameter_file;
	int32_t parameter = 0;

	addr_t mem_size = 1024 * 1024 * 32;  // 32 MB ram, to place it before the CLINT and run the base examples (assume
	                                     // memory start at zero) without modifications
	addr_t mem_start_addr = 0x00000000;
	addr_t mem_end_addr = mem_start_addr + mem_size - 1;
	addr_t clint_start_addr = 0x02000000;
	addr_t clint_end_addr = 0x0200ffff;
	addr_t term_start_addr = 0x20000000;
	addr_t term_end_addr = term_start_addr + 16;
	addr_t secterm_start_addr = 0x21000000;
	addr_t secterm_end_addr = secterm_start_addr + 16;
	addr_t secmem_start_addr = 0x22000000;
	addr_t secmem_size       = 1024;
	addr_t secmem_end_addr   = secmem_start_addr + secmem_size;
	uint8_t secmem_taint     = MergeStrategy::highest + 1;				//strategy 'highest' level 1
	addr_t file_loader_sa	= 0x30000000;
	addr_t file_loader_ea	= 0x3F000000;
	addr_t plic_start_addr = 0x40000000;
	addr_t plic_end_addr = 0x41000000;
	addr_t sensor_start_addr = 0x50000000;
	addr_t sensor_end_addr = 0x50001000;
	addr_t sensor2_start_addr = 0x50002000;
	addr_t sensor2_end_addr = 0x50004000;
	addr_t aes_start_addr = 0x51000000;
	addr_t aes_end_addr   = 0x51001000;
	addr_t dma_start_addr = 0x70000000;
	addr_t dma_end_addr = 0x70001000;

	bool use_debug_runner = false;
	bool use_instr_dmi = false;
	bool use_data_dmi = false;

	unsigned int tlm_global_quantum = 10;

	void show() {
		std::cout << "options {" << std::endl;
		std::cout << "  use instr dmi = " << use_instr_dmi << std::endl;
		std::cout << "  use data dmi = " << use_data_dmi << std::endl;
		std::cout << "  tlm global quantum = " << tlm_global_quantum << std::endl;
		std::cout << "}" << std::endl;
	}
};

Options parse_command_line_arguments(int argc, char **argv) {
	// Note: first check for *help* argument then run *notify*, see:
	// https://stackoverflow.com/questions/5395503/required-and-optional-arguments-using-boost-library-program-options
	try {
		Options opt;

		namespace po = boost::program_options;

		po::options_description desc("Options");

		desc.add_options()("help", "produce help message")("memory-start", po::value<unsigned int>(&opt.mem_start_addr),
		                                                   "set memory start address")(
		    "debug-mode", po::bool_switch(&opt.use_debug_runner),
		    "start execution in debugger (using gdb rsp interface)")(
		    "tlm-global-quantum", po::value<unsigned int>(&opt.tlm_global_quantum), "set global tlm quantum (in NS)")(
		    "use-instr-dmi", po::bool_switch(&opt.use_instr_dmi), "use dmi to fetch instructions")(
		    "use-data-dmi", po::bool_switch(&opt.use_data_dmi), "use dmi to execute load/store operations")(
		    "use-dmi", po::bool_switch(), "use instr and data dmi")(
			"input-file", po::value<std::string>(&opt.input_program)->required(), "input file to use for execution")(
			"parameter-file", po::value<std::string>(&opt.parameter_file), "input file for parameter")(
		    "signature", po::value<std::string>(&opt.test_signature)->default_value(""), "output filename for the test execution signature")(
		    "parameter", po::value<int32_t>(&opt.parameter)->default_value(0), "parameter appearing at 0x1FFFFFC"
		    );

		po::positional_options_description pos;
		pos.add("input-file", 1);

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(desc).positional(pos).run(), vm);

		if (vm.count("help")) {
			std::cout << desc << std::endl;
			exit(0);
		}

		po::notify(vm);

		if (vm["use-dmi"].as<bool>()) {
			opt.use_data_dmi = true;
			opt.use_instr_dmi = true;
		}

		return opt.check_and_post_process();
	} catch (boost::program_options::error &e) {
		std::cerr << "Error parsing command line options: " << e.what() << std::endl;
		exit(-1);
	}
}

int sc_main(int argc, char **argv) {
	Options opt = parse_command_line_arguments(argc, argv);

	std::srand(std::time(nullptr));  // use current time as seed for random generator

	tlm::tlm_global_quantum::instance().set(sc_core::sc_time(opt.tlm_global_quantum, sc_core::SC_NS));

	ISS core;
	TaintedMemory mem("TAINTEDMemory", opt.mem_size);
	SimpleTerminal term("SimpleTerminal");
	SecureTerminal secterm("SecureTerminal", opt.secmem_taint);
	TaintedMemory secmem("secureMemory", opt.secmem_size, opt.secmem_taint);
	for(unsigned i = 0; i < opt.secmem_size; i++)
	{
		secmem.data[i] = Taint<uint8_t>(i & 0xFF, opt.secmem_taint);
	}
	ELFLoader loader(opt.input_program.c_str());
	SimpleBus<2, 11> bus("SimpleBus");
	CombinedMemoryInterface iss_mem_if("MemoryInterface", core.quantum_keeper);
	SyscallHandler sys;
	PLIC plic("PLIC");
	CLINT clint("CLINT");
	SimpleSensor sensor("SimpleSensor", 2);
	SimpleSensor2 sensor2("SimpleSensor2", 5);
	AES aes("SimpleAes");
	BasicTimer timer("BasicTimer", 3);
	SimpleDMA dma("SimpleDMA", 4);
	FileLoader fileParameter("ParameterFile", opt.parameter_file);

	direct_memory_interface dmi({mem.data, opt.mem_start_addr, mem.size});
	InstrMemoryProxy instr_mem(dmi, core.quantum_keeper);
	DataMemoryProxy data_mem(dmi, &iss_mem_if, core.quantum_keeper);

	instr_memory_interface *instr_mem_if = &iss_mem_if;
	data_memory_interface *data_mem_if = &iss_mem_if;
	if (opt.use_instr_dmi) instr_mem_if = &instr_mem;
	if (opt.use_data_dmi) data_mem_if = &data_mem;


	{
		unsigned i = 0;
		bus.ports[i++] = new PortMapping(opt.mem_start_addr, opt.mem_end_addr);
		bus.ports[i++] = new PortMapping(opt.term_start_addr, opt.term_end_addr);
		bus.ports[i++] = new PortMapping(opt.secterm_start_addr, opt.secterm_end_addr);
		bus.ports[i++] = new PortMapping(opt.plic_start_addr, opt.plic_end_addr);
		bus.ports[i++] = new PortMapping(opt.sensor_start_addr, opt.sensor_end_addr);
		bus.ports[i++] = new PortMapping(opt.clint_start_addr, opt.clint_end_addr);
		bus.ports[i++] = new PortMapping(opt.dma_start_addr, opt.dma_end_addr);
		bus.ports[i++] = new PortMapping(opt.sensor2_start_addr, opt.sensor2_end_addr);
		bus.ports[i++] = new PortMapping(opt.secmem_start_addr, opt.secmem_end_addr);
		bus.ports[i++] = new PortMapping(opt.aes_start_addr, opt.aes_end_addr);
		bus.ports[i++] = new PortMapping(opt.aes_start_addr, opt.aes_end_addr);
	}

	loader.load_executable_image(mem.data, mem.size, opt.mem_start_addr);
	core.init(instr_mem_if, data_mem_if, &clint, &sys, loader.get_entrypoint(),
	          opt.mem_end_addr - 4);  // -4 to not overlap with the next region
	sys.init(mem.data, opt.mem_start_addr, loader.get_heap_addr());

	// connect TLM sockets
	iss_mem_if.isock.bind(bus.tsocks[0]);
	dma.isock.bind(bus.tsocks[1]);
	{
		unsigned i = 0;
		bus.isocks[i++].bind(mem.tsock);
		bus.isocks[i++].bind(term.tsock);
		bus.isocks[i++].bind(secterm.tsock);
		bus.isocks[i++].bind(plic.tsock);
		bus.isocks[i++].bind(sensor.tsock);
		bus.isocks[i++].bind(clint.tsock);
		bus.isocks[i++].bind(dma.tsock);
		bus.isocks[i++].bind(sensor2.tsock);
		bus.isocks[i++].bind(secmem.tsock);
		bus.isocks[i++].bind(aes.tsock);
		bus.isocks[i++].bind(fileParameter.tsock);
	}
	// connect interrupt signals/communication
	plic.target_hart = &core;
	clint.target_hart = &core;
	sensor.plic = &plic;
	dma.plic = &plic;
	timer.plic = &plic;
	sensor2.plic = &plic;

	//Special uint32_t parameter
	for(unsigned i = 0; i < sizeof(int32_t); i++){
		mem.data[0x1FFFFFC + i] = reinterpret_cast<uint8_t*>(&opt.parameter)[i];
	}

	if (opt.use_debug_runner) {
		debug_memory_mapping dmm({mem.data, opt.mem_start_addr, mem.size});
		new DebugCoreRunner(core, dmm);
	} else {
		new DirectCoreRunner(core);
	}

	sc_core::sc_start();

	core.show();

	if (opt.test_signature != "") {
		auto begin_sig = loader.get_begin_signature_address();
		auto end_sig = loader.get_end_signature_address();

		{
			boost::io::ios_flags_saver ifs(cout);
			std::cout << std::hex;
			std::cout << "begin_signature: " << begin_sig << std::endl;
			std::cout << "end_signature: " << end_sig << std::endl;
			std::cout << "signature output file: " << opt.test_signature << std::endl;
		}

		assert(end_sig >= begin_sig);
		assert(begin_sig >= opt.mem_start_addr);

		auto begin = begin_sig - opt.mem_start_addr;
		auto end = end_sig - opt.mem_start_addr;

		ofstream sigfile(opt.test_signature, ios::out);

		auto n = begin;
		while (n < end) {
			sigfile << std::hex << std::setw(2) << std::setfill('0') << (unsigned)mem.data[n];
			++n;
		}
	}

	return 0;
}
