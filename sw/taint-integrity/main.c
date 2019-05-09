#include <stdio.h>
#include <string.h>

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

void hashFunction(uint8_t* challenge, uint8_t* key, uint8_t* response, uint16_t size)
{
	for(uint16_t i = 0; i < size; i++)
	{
		response[i] = challenge[i] ^ key[i];
	}
}

void readUart(uint8_t* dst, uint16_t size)
{
	static char uartInput[] = "?/5~=K9fNGJ'vE{NsbGtW+7+&*gN}5[>";
	for(uint16_t i = 0; i < size; i++)
	{
		dst[i] = uartInput[i % 32];
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
uint8_t a [blksz];
uint8_t b [blksz];
uint8_t c [blksz];

const uint8_t* volatile SECMEM = (uint8_t*) 0x22000000;

int main()
{
	readUart(a, blksz);
	cpy(b, SECMEM, blksz);

	memset(c, 0, blksz);
	printf("After memset taint: %u\n", getTaint(c));
	asm volatile
	(
	"jal %[addr], 0\n\t"
	:
	: [addr] "r" (c)
	:
	);

	writeSecureUart(a, blksz);

	return 0;
}
