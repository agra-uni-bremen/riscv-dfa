#include <stdio.h>
#include <string.h>

void setTaint(uint8_t* word, uint8_t const taint, uint16_t const size)
{
	for(uint16_t i = 0; i < size; i++)
	{
		asm volatile
		(
		"lbu a0, 0(%[ptr])\n\t"
		"settaint  a0, %[taint]\n\t"
		"sb a0, 0(%[ptr])\n\t"
		:
		: [taint] "r" (taint), [ptr] "r" (&word[i])
		: "a0"
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

int main()
{
	const uint16_t blksz = 100;
	uint8_t plaintext[blksz];
	uint8_t key[blksz];
	uint8_t ciphertext[blksz];

	setTaint(plaintext, 1, blksz);
	setTaint(key, 1, blksz);

	strcpy(plaintext, "Dies ist ein sehr geheimer Text.");
	strcpy(key, "Dies ist ein sehr geheimer Schluessel.");

	ultraSecureCrypt(plaintext, key, ciphertext, blksz);

	//this should fail
	printf("%10s\n", plaintext);
	printf("%10s\n", key);

	printf("Plaintext has taint: %u\n", getTaint(plaintext));
	printf("Key       has taint: %u\n", getTaint(key));
	printf("Cipher    has taint: %u\n", getTaint(ciphertext));

	return 1;
}
