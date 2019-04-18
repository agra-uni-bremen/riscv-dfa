/*
 * tainttest.cpp
 *
 *  Created on: 22 Nov 2018
 *      Author: dwd
 */

#include <assert.h>
#include <stdint.h>
#include <iostream>
#include "../core/rv32/taint.hpp"

using namespace std;

int main() {
	cout << "Sizeof Taint<uint8_t>  : " << sizeof(Taint<uint8_t>) << endl;
	cout << "Sizeof Taint<uint16_t> : " << sizeof(Taint<uint16_t>) << endl;
	cout << "Sizeof Taint<uint32_t> : " << sizeof(Taint<uint32_t>) << endl;

	uint8_t b = 10;
	Taint<uint8_t> t = b;

	uint8_t c = t;
	assert(c == t);

	t = 10;

	t.setTaintId(MergeStrategy::highest + 2);
	Taint<uint32_t> t2 = t;

	bool threw = false;
	try {
		c = t2;  // flow to zero
	} catch (TaintingException& ex) {
		cerr << "Correct throw: " << ex.what() << endl;
		threw = true;
	}
	assert(threw);

	threw = false;
	try {
		c = t2.require(MergeStrategy::highest + 1);  // flow to low
	} catch (TaintingException& ex) {
		cerr << "Correct throw: " << ex.what() << endl;
		threw = true;
	}
	assert(threw);

	c = t2.require(MergeStrategy::highest + 3);		//flow from 2 to 3 is allowed


	Taint<uint8_t> i(MergeStrategy::lowest + 2);
	c = i;		//demotion to 0

	{
	Taint<uint8_t> ic = i;	//implicit demotion to 0
	assert(ic.getTaintId() == 0);	//test of merge function
	}

	threw = false;
	try {
		c = i.require(MergeStrategy::lowest + 3);  // flow to high
	} catch (TaintingException& ex) {
		cerr << "Correct throw: " << ex.what() << endl;
		threw = true;
	}
	assert(threw);

	exit(EXIT_SUCCESS);
}
