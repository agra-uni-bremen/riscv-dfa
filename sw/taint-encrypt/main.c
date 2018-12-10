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

void ultraSecureCrypt(uint8_t* plain, uint8_t* key, uint8_t* cipher, uint16_t size)
{
	for(uint16_t i = 0; i < size; i++)
	{
		cipher[i] = plain[i] ^ key[i];
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
uint8_t ciphertext[blksz];
uint8_t plaintext[blksz];
uint8_t key[blksz];

int main()
{
	printf("Plaintext at %4p\n", plaintext);
	printf("Key       at %4p\n", key);
	printf("Cipher    at %4p\n", ciphertext);

	strcpy(plaintext, "Dies ist ein sehr geheimer Text.");
	strcpy(key,       "MeineOmaFaehrtImHuenerstallMotor");

	setTaint(plaintext, 1, blksz);
	//this would fail
	//setTaint(key, 2, blksz);
	setTaint(key, 1, blksz);

	ultraSecureCrypt(plaintext, key, ciphertext, blksz);

	//this should fail
	//printf("%10s\n", plaintext);
	//printf("%10s\n", key);

	printf("Plaintext has taint: %u\n", getTaint(plaintext));
	printf("Key       has taint: %u\n", getTaint(key));
	printf("Cipher    has taint: %u\n", getTaint(ciphertext));

	setTaint(ciphertext, 0, blksz);

	//this would fail
	//printHex(ciphertext, strlen(plaintext))

	//This is ok
	printHex(ciphertext, blksz);

	//this would fail (buffer overflow from an imaginary buffer before plaintext
	//printHex(plaintext - blksz, 2 * blksz);

	return 1;
}
