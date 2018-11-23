#ifndef RISCV_ISA_TERMINAL_H
#define RISCV_ISA_TERMINAL_H

#include "systemc"

#include "tlm_utils/simple_target_socket.h"


struct SimpleTerminal : public sc_core::sc_module {

    tlm_utils::simple_target_socket<SimpleTerminal> tsock;

    SimpleTerminal(sc_core::sc_module_name) {
        tsock.register_b_transport(this, &SimpleTerminal::transport);
    }

    void transport(tlm::tlm_generic_payload &trans, sc_core::sc_time &delay) {
        sc_assert (trans.get_command() == tlm::TLM_WRITE_COMMAND);
        sc_assert (trans.get_data_length() == sizeof(Taint<uint8_t>));

        //this may throw if tainted
        char c = *reinterpret_cast<Taint<uint8_t>*>(trans.get_data_ptr());

        std::cout << c;
    }
};


#endif //RISCV_ISA_TERMINAL_H
