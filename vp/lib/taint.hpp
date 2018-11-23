/*
 * taint.hpp
 *
 *  Created on: 22 Nov 2018
 *      Author: dwd
 */

#pragma once

#include <stdint.h>
#include <iostream>
#include <exception>
#include <cstring>

#include "tlm_core/tlm_2/tlm_generic_payload/tlm_gp.h"

//#define DEBUG(...) ...
#define DEBUG(...)

struct TaintingException : public std::exception
{
	std::string msg;
	TaintingException() : msg("Invalid tainting operation"){}
	TaintingException(std::string msg) : msg("Invalid tainting operation: " + msg){}
	const char * what () const throw () override
	{
		return msg.c_str();
	}
};

template<typename T> class Taint
{
	T value;
	uint8_t id[sizeof(T)];

	static_assert(sizeof(T) <= 4);

public:
	Taint()
	{
		DEBUG(std::cout << "Construct empty" << std::endl;)
		//intentionally left value undefined
		id[0] = 0;
		if(sizeof(T) > 1)	//Most instances will be uint8_t -> Size 1
		{
			memset(id, 0, sizeof(T));
		}
	}

	Taint(const Taint<T>& other)
	{
		DEBUG(std::cout << "Construct from Taint " << int(other.value) << " id (" << int(other.getTaintId()) << ")" << std::endl;)
		value = other.value;
		memcpy(id, other.id, sizeof(T));
	}

	Taint(const T other)
	{
		DEBUG(std::cout << "Construct from basetype " << int(other) << std::endl;)
		value = other;
		memset(id, 0, sizeof(T));
	}


	friend void swap(Taint<T>& lhs, Taint<T>& rhs)
	{
		std::swap(lhs.value, rhs.value);
		std::swap(lhs.id, rhs.id);
	}

	Taint<T>& operator =(const Taint<T>& other)
	{
		DEBUG(std::cout << "Move operator = " << int(other.value) << " id (" << int(other.getTaintId()) << ")" << std::endl;)
		if(id[0] != 0 && other.id[0] != id[0])
		{
			std::cout << "Overwriting tainted value " << int(id[0]) << " with " << int(other.id[0]) << std::endl;
		}
		Taint<T> temp(other);
		swap(*this, temp);

		return *this;
	}

	operator T() const
	{
		DEBUG(std::cout << "Demotion of " << int(value) << " id (" << int(getTaintId()) << ")" << std::endl;)
		for(uint8_t i = 0; i < sizeof(T); i++)
		{
			if(id[i] != 0)
			{
				throw TaintingException("Invalid demotion of ID " + std::to_string(id[i]));
			}
		}
		return value;
	}

	//Explicit Type conversions for Register width
	//Note: This only works with big-endian host processors
	template<typename B>
	operator Taint<B>() const
	{
		DEBUG(std::cout << "Conversion of " << int(value) << " id (" << int(getTaintId()) << ")" << std::endl;)
		Taint<B> temp = value;
		temp.setTaintId(getTaintId());
		return temp;
	}

	void expand(Taint<uint8_t> ar[sizeof(T)])
	{
		for(uint8_t i = 0; i < sizeof(T); i ++)
		{
			ar[i] = reinterpret_cast<uint8_t*>(&value)[i];
			ar[i].setTaintId(getTaintId());
		}
	}

	void confine(Taint<uint8_t> ar[sizeof(T)])
	{
		for(uint8_t i = 0; i < sizeof(T); i ++)
		{
			id[i] = ar[i].getTaintId();
			if(id[0] != id[i])
			{
				throw(TaintingException("Unaligned confine on Taint Objects"));
			}
			ar[i].setTaintId(0);	//expensive
			reinterpret_cast<uint8_t*>(&value)[i] = ar[i];
		}
	}

	void setTaintId(uint8_t taintID)
	{
		memset(id, taintID, sizeof(T));
	}

	uint8_t getTaintId() const
	{
		uint8_t taintID = id[0];
		for(uint8_t i = 1; i < sizeof(T); i++)
		{
			if(taintID != id[i])
			{
				throw(TaintingException("Unaligned read on Taint Object"));
			}
		}
		return taintID;
	}
};


