#ifndef RISCV_ISA_SENSOR_H
#define RISCV_ISA_SENSOR_H

#include <cstdlib>
#include <cstring>

#include <systemc>

#include <tlm_utils/simple_target_socket.h>

#include "core/common/irq_if.h"

struct SimpleSensor : public sc_core::sc_module {
	tlm_utils::simple_target_socket<SimpleSensor> tsock;

	interrupt_gateway *plic = 0;
	uint32_t irq_number = 0;
	sc_core::sc_event run_event;

	// memory mapped data frame
	std::array<Taint<uint8_t>, 64> data_frame;

	// memory mapped configuration registers
	uint32_t scaler = 25;
	uint32_t filter = 0;
	uint32_t taint = 2;

	std::unordered_map<uint64_t, uint32_t *> addr_to_reg;

	enum {
		SCALER_REG_ADDR = 0x80,
		FILTER_REG_ADDR = 0x84,
		TAINT_REG_ADDR = 0x88,
	};

	SC_HAS_PROCESS(SimpleSensor);

	SimpleSensor(sc_core::sc_module_name, uint32_t irq_number) : irq_number(irq_number) {
		tsock.register_b_transport(this, &SimpleSensor::transport);
		SC_THREAD(run);

		addr_to_reg = {
		    {SCALER_REG_ADDR, &scaler},
		    {FILTER_REG_ADDR, &filter},
		    {TAINT_REG_ADDR, &taint},
		};
	}

	void transport(tlm::tlm_generic_payload &trans, sc_core::sc_time&) {
		auto addr = trans.get_address();
		auto cmd = trans.get_command();
		auto len = trans.get_data_length();
		auto ptr = reinterpret_cast<Taint<uint8_t> *>(trans.get_data_ptr());

		if (addr <= 63) {
			// access data frame
			assert(cmd == tlm::TLM_READ_COMMAND);
			assert((addr + len) <= data_frame.size());

			// return last generated random data at requested address
			memcpy((void *)ptr, &data_frame[addr], sizeof(Taint<uint8_t>) * len);
		} else {
			assert(len == 4);  // NOTE: only allow to read/write whole register

			auto it = addr_to_reg.find(addr);
			assert(it != addr_to_reg.end());  // access to non-mapped address

			// trigger pre read/write actions
			if ((cmd == tlm::TLM_WRITE_COMMAND) && (addr == SCALER_REG_ADDR)) {
				uint32_t value = Taint<uint32_t>(ptr);
				if (value < 1 || value > 100) return;  // ignore invalid values
			}

			// actual read/write
			if (cmd == tlm::TLM_READ_COMMAND) {
				Taint<uint8_t> buf[4];
				Taint<uint32_t>::expand(buf, *it->second);
				memcpy((void *)ptr, buf, sizeof(Taint<uint8_t>) * 4);
			} else if (cmd == tlm::TLM_WRITE_COMMAND) {
				*it->second = Taint<uint32_t>(ptr);
			} else {
				assert(false && "unsupported tlm command for sensor access");
			}

			// trigger post read/write actions
			if ((cmd == tlm::TLM_WRITE_COMMAND) && (addr == SCALER_REG_ADDR)) {
				run_event.cancel();
				run_event.notify(sc_core::sc_time(scaler, sc_core::SC_MS));
			}
		}
	}

	void run() {
		while (true) {
			run_event.notify(sc_core::sc_time(scaler, sc_core::SC_MS));
			sc_core::wait(run_event);  // 40 times per second by default

			// fill with random data
			for (auto &n : data_frame) {
				if (filter == 1) {
					n = Taint<uint8_t>(rand() % 10 + 48, taint);
				} else if (filter == 2) {
					n = Taint<uint8_t>(rand() % 26 + 65, taint);
				} else {
					// fallback for all other filter values
					n = Taint<uint8_t>(rand() % 92 + 32, taint);  // random printable char
				}
			}

			plic->gateway_incoming_interrupt(irq_number);
		}
	}
};

#endif  // RISCV_ISA_SENSOR_H
