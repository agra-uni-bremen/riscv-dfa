#include "stdio.h"

void setTaint(uint32_t* word, uint8_t taint)
{
	asm volatile
	(
	"settaint  %[word], %[taint]\n\t"
	: [word] "=r" (*word)
	: [taint] "r" (taint)
	);
}

uint8_t getTaint(uint32_t* const word)
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

int main()
{
	uint32_t word = 0;
	printf("Word: %zu\n", word);

	setTaint(&word, 1);

	puts("tainted word\n");
	word ++;
	puts("incremented word\n");

	uint32_t taintval = getTaint(&word);

	printf("word has taint %zu\n", taintval);

	//this would fail
	printf("word has value %u\n", word);

	return 1;
}
