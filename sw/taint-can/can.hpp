/*
 * can.hpp
 *
 *  Created on: Mar 30, 2020
 *      Author: dwd
 */

#pragma once
#include <stdint.h>

namespace can
{

typedef uint16_t ID;

//rough abstraction of can frame
struct Frame
{
	ID      id:11;
	uint8_t len:4;
	uint8_t data[8];
};

}

namespace obd
{

struct DTC
{
	uint16_t data;

	uint8_t getFirstChar()
	{
		return (data & 0b11000000) >> 6;
	}
	uint8_t getSecondChar()
	{
		return (data & 0b00110000) >> 4;
	}
	//and so on
};

enum Service : uint8_t
{
	show_current_data = 1,
	show_freeze_frame_data,
	show_stored_dtcs,	//diagnostic trouble codes
	clear_stored_dtcs,
	test_results_oxy,
	test_results_other,
	show_pending_dtcs,
	request_vehicle_info,
	show_permanent_dtcs
};

enum PID : uint8_t
{
	supported_pids_01_20 = 0,
	monitor_status,
	freeze_dtc,
	fuel_system_status,
	calculated_engine_load,
	engine_coolant_temp,
	stft_bank_1,	//short term fuel trim
	ltft_bank_1,	//long  term fuel trim
	stft_bank_2,
	ltft_bank_2,
	fuel_pressure,
	// TODO: Whole list
	obd_standard_conformity = 28,
	supported_pids_21_40 = 32,
	supported_pids_41_60 = 64,
	not_recognized = 0x7F

};

enum ExtendedPID : uint16_t
{
	login = 1,

	//FIXME: No vehicle specifics in open standards
	dump_mem,	//whoops?
};

static constexpr can::ID sae_standard_query=0x7DF;

struct Query
{
	uint8_t  additionalBytes;	//2 (standard) or 3 (vehicle specific)
	Service service;
	union
	{
		PID pid;
		ExtendedPID epid;
	};
};


struct Response
{
	uint8_t  additionalBytes;	//3 to 7
	Service service;			//Same as query, except that 40h is added to the service value.
	union
	{
		struct
		{
			PID pid;
			uint8_t val[4];
		} normal;
		struct
		{
			ExtendedPID epid;
			uint8_t val[4];
		} extended;
	};
};


}
