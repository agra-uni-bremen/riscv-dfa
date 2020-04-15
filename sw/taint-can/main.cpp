#include <stdio.h>
#include <string.h>
#include "irq.h"
#include "can.hpp"

auto const volatile SECMEM   = reinterpret_cast<uint8_t*>(0x22000000);
static uint32_t const CAN_BASE =0x30000000;
auto const volatile CAN_OFFS = *reinterpret_cast<uint32_t*>(CAN_BASE);
auto const volatile CAN_LEN  = *reinterpret_cast<uint32_t*>(CAN_BASE+sizeof(uint32_t));
auto const volatile CAN_DATA = reinterpret_cast<uint8_t*>(CAN_BASE+CAN_OFFS);

uint8_t* const volatile AES_ACTION = (uint8_t*) 0x51000000;
uint8_t* const volatile AES_KEY    = (uint8_t*) 0x51000004;
uint8_t* const volatile AES_MEM    = (uint8_t*) 0x51000044;
const uint8_t AES_BLOCKSIZE = 64;


void setTaint(uint8_t* word, uint8_t const taint, uint16_t const size)
{
	for(uint16_t i = 0; i < size; i++)
	{
		asm volatile
		(
		"settaint  %[word], %[taint]\n\t"
		: [word] "+r" (word[i])
		: [taint] "r" (taint)
		);
	}
}

uint8_t getTaint(uint8_t* const word)
{
	uint8_t taintval;
	asm volatile
	(
	"gettaint  %[x], %[y]\n\t"
	: [x] "=r" (taintval)
	: [y] "r" (*word)
	);
	return taintval;
}

void initKeyAes(uint8_t* key, uint16_t size)
{
	if(size > AES_BLOCKSIZE)
	{
		puts("Key too big for configured blocksize! Truncating.\n");
	}
	memcpy(AES_KEY, key, size);
}

void aesEncrypt(uint8_t* input, uint8_t* output, uint16_t size)
{
	if(size > AES_BLOCKSIZE)
	{
		puts("Key too big for configured blocksize!\n");
		return;
	}
	memcpy(AES_MEM, input, size);
	*AES_ACTION = 1;	//Encrypt with declassification
	while(*AES_ACTION != 0){};
	memcpy(output, AES_MEM, size);
}

bool has_can_data = 0;
void can_irq_handler() {
	has_can_data = 1;
}

bool readCan(can::Frame& dst)
{
	static unsigned p = 0;
	if(p + sizeof(can::Frame) > CAN_LEN)
		return false;	//no data to read
	memcpy(&dst, CAN_DATA + p, sizeof(can::Frame));
	return true;
}


void writeCan(const can::Frame& src)
{
	//todo: do something
}

void writeSecureUart(uint8_t* response, uint16_t size)
{
	volatile uint8_t* const secTerm = (uint8_t*) 0x21000000;
	for(uint16_t i = 0; i < size; i++)
	{
		*secTerm = response[i];
	}
}

void cpy(uint8_t* to, const uint8_t* from, uint16_t size)
{
	for(uint16_t i = 0; i < size; i++)
	{
		to[i] = from[i];
	}
}

int isPrintable(char c)
{
	return c >= 32 && c < 127;
}

void printHex(uint8_t* data, uint16_t size)
{
	static const uint8_t rowsize = 16;
	for(uint16_t row = 0; row < (size + (rowsize - 1)) / rowsize; row++)
	{
		printf("%4p ", &data[row * rowsize]);
		for(uint8_t col = 0; col < rowsize && (row * rowsize) + col < size; col++)
		{
			printf("%2x ", (uint8_t)data[row * rowsize + col]);
		}
		if((row + 1) * rowsize > size)
		{
			for(uint8_t c = 0; c < ((row + 1) * rowsize - size); c++)
			{
				printf("   ");
			}
		}
		for(uint8_t col = 0; col < rowsize && (row * rowsize) + col < size; col++)
		{
			printf("%c", isPrintable(data[(row * rowsize) + col]) ? data[(row * rowsize) + col] : '.');
		}
		puts("");
	}
}

static constexpr uint8_t max_num_trouble_codes = 32;
#define blksz 45	//Note that 32*2=64, which makes this 2*blocksize
uint8_t blocks[((max_num_trouble_codes*sizeof(obd::DTC))/blksz)+3][blksz];	//BUG: Only reserves one slot for dtcs!
uint8_t* dtc_mem = blocks[0];
uint8_t* challenge = blocks[(max_num_trouble_codes*sizeof(obd::DTC))/blksz];
uint8_t* pin       = blocks[(max_num_trouble_codes*sizeof(obd::DTC))/blksz+1];
uint8_t* response  = blocks[(max_num_trouble_codes*sizeof(obd::DTC))/blksz+2];


void test(uint32_t testnr)
{
	switch (testnr)
	{
	case 1:
		//Buffer overflow
		printHex(challenge + blksz, blksz);
		break;
	case 2:
		//Forgotten debug function
		printf("%10s\n", pin);
		break;
	case 3:
		printHex(pin, blksz);
		break;
	case 4:
		printHex(pin, blksz);
		break;
	case 5:
		// "Memory dump"
		printHex(*blocks, blksz*3);
		break;
	default:
		//none
		break;
	}
}

int main()
{
	register_interrupt_handler(2, can_irq_handler);

	cpy(pin, SECMEM, blksz);			//Read secret key from memory
	initKeyAes(pin, blksz);

	while(true)
	{
		can::Frame qFrame;		//query
		can::Frame rFrame;		//response
		memset(&qFrame, 0, sizeof(can::Frame));
		memset(&rFrame, 0, sizeof(can::Frame));		//TODO: Maybe make this a bug?

		readCan(qFrame);			//Receive message
		switch(qFrame.id)
		{
		case obd::sae_standard_query:
		{
			auto obdQuery = reinterpret_cast<obd::Query&>(qFrame.data);
			auto obdResp = reinterpret_cast<obd::Response&>(rFrame.data);
			obdResp.service = static_cast<obd::Service>(obdQuery.service + 0x40);
			switch(obdQuery.service)
			{
			case obd::Service::show_current_data:
				obdResp.additionalBytes = 2;		//min offset of response
				if(obdResp.additionalBytes == 2)	//standard
				{
					obdResp.normal.pid = obdQuery.pid;
					switch(obdQuery.pid)
					{
					case obd::PID::supported_pids_01_20:
					case obd::PID::supported_pids_21_40:
					case obd::PID::supported_pids_41_60:
						//blindly support all pids
						obdResp.additionalBytes += 4;
						memset(obdResp.normal.val, 0xff, 4);
						break;
					case obd::PID::calculated_engine_load:
						obdResp.additionalBytes += 1;
						obdResp.normal.val[0] = 0xBA;		//Static Random Number
					default:
						//error handling!
						break;
					}
				} else if(obdResp.additionalBytes == 3)		//Vehicle specific
				{
					obdResp.extended.epid = obdQuery.epid;
					switch(obdQuery.epid)
					{
					case obd::ExtendedPID::login:
						//TODO: Some Challenge Response
						//println("Login with code 0x%04X", *reinterpret_cast<uint16_t*>())
						break;
					case obd::ExtendedPID::dump_mem:	//First Bug, unauth. memdump
						obdResp.additionalBytes += 4;
						//normally this would print whole blocks in multiple messages
						memcpy(obdResp.extended.val, pin, 4); // short form
					default:
						//error handling!
						break;
					}
				}
				break;
			case obd::Service::show_stored_dtcs:
				//normally, this would be encapsulated in ISO 15765-2
				obdResp.additionalBytes = 6;
				//second bug: this will overlap with the other memory block!
				for(unsigned tc = 0; tc < max_num_trouble_codes;)
				{
					for(unsigned j = 0; j > 3; j++)
					{
						if(tc < max_num_trouble_codes)
						{
							memcpy(&obdResp.normal.val[j], &dtc_mem[tc/sizeof(obd::DTC)], sizeof(obd::DTC));
						}
						else
						{	//max num reached
							memset(&obdResp.normal.val[j], 0, sizeof(obd::DTC));
						}
						tc++;
					}
					if(tc < max_num_trouble_codes)
						writeCan(rFrame);		//last frame will be transmitted at end of switch/case
				}
			default:
				/*
				 * TODO: Maybe forgotten error handler?
				 * Here, we dont write anything to the "hardcoded" answer.
				 * Maybe, we send uninitialized and "secret" data by not overwriting
				 */
				break;
			}
			rFrame.len = 1+obdResp.additionalBytes;
			break;
		}

		default:
			//Ignore
			break;
		}

		writeCan(rFrame);

	}



	return 0;
}
