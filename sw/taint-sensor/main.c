#include "irq.h"

#include <stdint.h>
#include <stdio.h>


static volatile char * const TERMINAL_ADDR = (char * const)0x20000000;
static volatile char * const SECTERMINAL_ADDR = (char * const)0x21000000;
static volatile char * const SENSOR_INPUT_ADDR = (char * const)0x50000000;
static volatile uint32_t * const SENSOR_SCALER_REG_ADDR = (uint32_t * const)0x50000080;
static volatile uint32_t * const SENSOR_FILTER_REG_ADDR = (uint32_t * const)0x50000084;
static volatile uint32_t * const SENSOR_TAINT_REG_ADDR  = (uint32_t * const)0x50000088;

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

_Bool has_sensor_data = 0;

void sensor_irq_handler() {
	has_sensor_data = 1;
}

void dump_sensor_data(volatile char * const sink) {
	printf("Dumping sensor data\n");
	while (!has_sensor_data) {
		asm volatile ("wfi");
	}
	has_sensor_data = 0;
	
	uint8_t buf[64];

	for (int i=0; i<64; ++i) {
		buf[i] = *(SENSOR_INPUT_ADDR + i);
	}

	printf("Sensor has taint: %u\n", getTaint(buf));

	for (int i=0; i<64; ++i)
	{
		*sink = buf[i];
	}

	*sink = '\n';
}

int main() {
	register_interrupt_handler(2, sensor_irq_handler);
	
	*SENSOR_SCALER_REG_ADDR = 5;
	*SENSOR_FILTER_REG_ADDR = 2;
	*SENSOR_TAINT_REG_ADDR = 1;

	//this would fail
	for (int i=0; i<2; ++i)
		dump_sensor_data(TERMINAL_ADDR);

	for (int i=0; i<2; ++i)
		dump_sensor_data(SECTERMINAL_ADDR);

	printf("Setting sensor taint to 0\n");

	*SENSOR_TAINT_REG_ADDR = 0;

	for (int i=0; i<2; ++i)
		dump_sensor_data(TERMINAL_ADDR);

	return 0;
}
