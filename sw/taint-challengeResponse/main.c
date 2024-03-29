#include <stdio.h>
#include <string.h>
#include "irq.h"

const uint8_t* volatile SECMEM = (uint8_t*) 0x22000000;
//Using Sensor random data as model for CAN message
const uint8_t* volatile CAN_PACKET = (uint8_t*) 0x50000000;
static volatile uint32_t * const CAN_TAINT_REG_ADDR  = (uint32_t * const)0x50000088;

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

_Bool has_can_data = 0;
void can_irq_handler() {
	has_can_data = 1;
}

void readCan(uint8_t* dst, uint16_t size)
{
	while (!has_can_data) {
		asm volatile ("wfi");
	}
	has_can_data = 0;

	for(uint16_t i = 0; i < size; i++)
	{
		dst[i] = *(CAN_PACKET + i);
	}
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

#define blksz 45
uint8_t blocks[3][blksz];
uint8_t* challenge = blocks[0];
uint8_t* pin       = blocks[1];
uint8_t* response  = blocks[2];


void test(uint32_t testnr)
{
	//this would fail
	//
	//
	//
	//
	//

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
	*CAN_TAINT_REG_ADDR = 0;
	register_interrupt_handler(2, can_irq_handler);

	cpy(pin, SECMEM, blksz);			//Read secret key from memory
	initKeyAes(pin, blksz);

	readCan(challenge, blksz);			//Receive message

	printf("Challenge has taint: %u\n", getTaint(challenge));
	printf("Pin       has taint: %u\n", getTaint(pin));
	printf("Response  has taint: %u\n", getTaint(response));

	printf("Challenge :\n");
	printHex(challenge, blksz);
	aesEncrypt(challenge, response, blksz);


	int choice = *(uint32_t*)(0x1FFFFFC);
	test(choice);

	writeSecureUart(response, blksz);

	return 0;
}
