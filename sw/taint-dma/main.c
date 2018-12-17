#include <stdint.h>
#include <stdio.h>

#include "irq.h"

static volatile char * const TERMINAL_ADDR = (char * const)0x20000000;

static volatile uint32_t * const DMA_SRC_ADDR  = (uint32_t * const)0x70000000;
static volatile uint32_t * const DMA_DST_ADDR  = (uint32_t * const)0x70000004;
static volatile uint32_t * const DMA_LEN_ADDR  = (uint32_t * const)0x70000008;
static volatile uint32_t * const DMA_OP_ADDR   = (uint32_t * const)0x7000000C;
static volatile uint32_t * const DMA_STAT_ADDR = (uint32_t * const)0x70000010;

static const uint32_t DMA_OP_NOP = 0;
static const uint32_t DMA_OP_MEMCPY = 1;


_Bool dma_completed = 0;

void dma_irq_handler() {
	dma_completed = 1;
}

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

int main() {
	register_interrupt_handler(4, dma_irq_handler);
	
	uint8_t src[] = "Meine Ohmer faehrt im Huehnerstall mortorrard";
	uint8_t dst[sizeof(src)] = { 0 };
	
	setTaint(src, 1, sizeof(src));

	dma_completed = 0;
	*DMA_SRC_ADDR = (uint32_t)(&src[0]);
	*DMA_DST_ADDR = (uint32_t)(&dst[0]);
	*DMA_LEN_ADDR = 32;
	*DMA_OP_ADDR  = DMA_OP_MEMCPY;
	
	while (!dma_completed) {
		asm volatile ("wfi");
	}
	
	printf("src taint ID: %u\n", getTaint(dst));
	printf("dst taint ID: %u\n", getTaint(dst));

	//this would fail
	/*
	for (int i=0; i<sizeof(src); ++i)
	{
		*TERMINAL_ADDR = dst[i];
	}
	*TERMINAL_ADDR = '\n';
	*/

	return 0;
}
