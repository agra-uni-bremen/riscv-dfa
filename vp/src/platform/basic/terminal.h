#pragma once

#include "systemc"

#include "tlm_utils/simple_target_socket.h"

struct SimpleTerminal : public sc_core::sc_module {
	tlm_utils::simple_target_socket<SimpleTerminal> tsock;

	SimpleTerminal(sc_core::sc_module_name) { tsock.register_b_transport(this, &SimpleTerminal::transport); }

	void transport(tlm::tlm_generic_payload& trans, sc_core::sc_time&) {
		sc_assert(trans.get_command() == tlm::TLM_WRITE_COMMAND);
		sc_assert(trans.get_data_length() == 1);

		// this may throw if tainted
		char c = *reinterpret_cast<Taint<uint8_t>*>(trans.get_data_ptr());

		std::cout << c;
	}
};

struct SecureTerminal : public sc_core::sc_module {
	tlm_utils::simple_target_socket<SecureTerminal> tsock;
	Taintlevel level;

	SecureTerminal(sc_core::sc_module_name) : level(0) { tsock.register_b_transport(this, &SecureTerminal::transport); }

	SecureTerminal(sc_core::sc_module_name, Taintlevel level) : level(level) {
		tsock.register_b_transport(this, &SecureTerminal::transport);
	}

	void transport(tlm::tlm_generic_payload& trans, sc_core::sc_time&) {
		sc_assert(trans.get_command() == tlm::TLM_WRITE_COMMAND);
		sc_assert(trans.get_data_length() == 1);

		// this may throw if tainted differently
		char c = reinterpret_cast<Taint<uint8_t>*>(trans.get_data_ptr())->require(level);

		std::cout << c;
	}
};
