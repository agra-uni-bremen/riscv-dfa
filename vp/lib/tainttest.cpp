/*
 * tainttest.cpp
 *
 *  Created on: 22 Nov 2018
 *      Author: dwd
 */


#include "taint.hpp"
#include <iostream>
#include <stdint.h>
#include <assert.h>

using namespace std;

int main()
{
	uint8_t b = 10;
	Taint<uint8_t> t = b;

	uint8_t c = t;
	assert(c == t);

	t = 10;

	t.setTaintId(1);
	Taint<uint32_t> t2 = t;

	bool threw = false;
	try
	{
		c = t2;	//should throw
	}
	catch(TaintingException& ex)
	{
		cerr << "Correct error: " << ex.what() << endl;
		threw = true;
	}
	assert(threw);


	cout << "Sizeof Taint<uint8_t>  : " << sizeof(Taint<uint8_t>)  << endl;
	cout << "Sizeof Taint<uint16_t> : " << sizeof(Taint<uint16_t>) << endl;
	cout << "Sizeof Taint<uint32_t> : " << sizeof(Taint<uint32_t>) << endl;

	exit(EXIT_SUCCESS);
}
