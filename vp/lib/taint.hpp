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

//#define DEBUG(x) x;
#define DEBUG(x) ;

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

public:
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

	Taint()
	{
		//DEBUG(std::cout << "Construct empty" << std::endl);
		//intentionally left value undefined
		id[0] = 0;
		if(sizeof(T) > 1)	//Most instances will be uint8_t -> Size 1
		{
			memset(id, 0, sizeof(T));
		}
	}

	Taint(const Taint<T>& other)
	{
		//DEBUG(std::cout << "Construct from Taint " << int(other.value) << " id (" << int(other.getTaintId()) << ")" << std::endl);
		value = other.value;
		memcpy(id, other.id, sizeof(T));
	}

	Taint(const T other)
	{
		//DEBUG(std::cout << "Construct from basetype " << int(other) << std::endl);
		value = other;
		memset(id, 0, sizeof(T));
	}

	Taint(Taint<uint8_t> ar[sizeof(T)])
	{
		uint8_t taint = ar[0].getTaintId();
		for(uint8_t i = 0; i < sizeof(T); i ++)
		{
			if(taint != ar[i].getTaintId())
			{
				if(taint == 0)
				{
					std::cerr << "unaligned confine on Taint Objects?" << std::endl;
					taint = ar[i].getTaintId();
				}
				else
				{
					throw(TaintingException("Unaligned confine on different tainted Objects"));
				}
			}
			//magic that relies that value is first byte in ar[i]
			reinterpret_cast<uint8_t*>(&value)[i] = *reinterpret_cast<uint8_t*>(&ar[i]);
		}
		setTaintId(taint);
	}

	friend void swap(Taint<T>& lhs, Taint<T>& rhs)
	{
		std::swap(lhs.value, rhs.value);
		std::swap(lhs.id, rhs.id);
	}

	uint8_t mergeTaintingValues(const uint8_t a, const uint8_t b)
	{
		if(a != b)
		{
			if(a > 0 && b == 0)
			{
				return a;
			}
			else if(b > 0 && a == 0)
			{
				return b;
			}
			else
			{
				std::cerr << "Combination of two tainting values, I dont know how to merge!" << std::endl;
				throw(TaintingException("unknown combination of taint values"));
				return a;
			}
		}
		else
		{
			return a;
		}
	}

	Taint<T>& operator =(const Taint<T>& other)
	{
		//DEBUG(std::cout << "Move operator = " << int(other.value) << " id (" << int(other.getTaintId()) << ")" << std::endl);
		if(id[0] != 0 && other.id[0] != id[0])
		{
			DEBUG(std::cout << "Overwriting tainted value " << int(id[0]) << " with " << int(other.id[0]) << std::endl);
		}
		Taint<T> temp(other);
		swap(*this, temp);

		return *this;
	}

	Taint<T> operator+(const Taint<T>& other)
	{
		Taint<T> ret(value + other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<T> operator+(const T& other)
	{
		Taint<T> ret(*this);
		ret.value += other;
		return ret;
	}

	Taint<bool> operator<(const Taint<T>& other)
	{
		Taint<bool> ret(value < other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<bool> operator<(const T& other)
	{
		Taint<bool> ret(value < other);
		ret.setTaintId(getTaintId());
		return ret;
	}

	Taint<bool> operator==(const Taint<T>& other)
	{
		Taint<bool> ret(value == other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<bool> operator==(const T& other)
	{
		Taint<bool> ret(value == other);
		ret.setTaintId(getTaintId());
		return ret;
	}

	Taint<T> operator^(const Taint<T>& other)
	{
		Taint<T> ret(value ^ other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator^(const N& other)
	{
		Taint<T> ret(*this);
		ret.value ^= other;
		return ret;
	}

	Taint<T> operator|(const Taint<T>& other)
	{
		Taint<T> ret(value | other);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator|(const N& other)
	{
		Taint<T> ret(*this);
		ret.value |= other;
		return ret;
	}

	Taint<T> operator&(const Taint<T>& other)
	{
		Taint<T> ret(value & other);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator&(const N& other)
	{
		Taint<T> ret(*this);
		ret.value &= other;
		return ret;
	}

	Taint<T> operator<<(const Taint<T>& other)
	{
		Taint<T> ret(value << other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator<<(const N& other)
	{
		Taint<T> ret(*this);
		ret.value <<= other;
		return ret;
	}

	Taint<T> operator>>(const Taint<T>& other)
	{
		Taint<T> ret(value >> other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator>>(const N& other)
	{
		Taint<T> ret(*this);
		ret.value >>= other;
		return ret;
	}

	operator T() const
	{
		//DEBUG(std::cout << "Demotion of " << int(value) << " id (" << int(getTaintId()) << ")" << std::endl);
		for(uint8_t i = 0; i < sizeof(T); i++)
		{
			if(id[i] != 0)
			{
				throw TaintingException("Invalid demotion of ID " + std::to_string(id[i]));
			}
		}
		return value;
	}

	T peek()
	{
		if(id[0] != 0)
		{
			std::cout << "Warning: Peeking into Object with taint ID " << int(id[0]) << std::endl;
		}
		return value;
	}

	//implicit Type conversions for Register width
	//Note: This only works with big-endian host processors
	template<typename N>
	operator Taint<N>() const
	{
		//DEBUG(std::cout << "Conversion of " << int(value) << " id (" << int(getTaintId()) << ")" << std::endl);
		Taint<N> temp(value);
		temp.setTaintId(getTaintId());
		return temp;
	}

	template<typename N>
	Taint<N> as()
	{
		Taint<N> ret(static_cast<N>(value));
		ret.setTaintId(getTaintId());
		return ret;
	}

	void expand(Taint<uint8_t> ar[sizeof(T)])
	{
		for(uint8_t i = 0; i < sizeof(T); i ++)
		{
			ar[i] = reinterpret_cast<uint8_t*>(&value)[i];
			ar[i].setTaintId(getTaintId());
		}
	}

	static void expand(Taint<uint8_t> ar[sizeof(T)], T value)
	{
		for(uint8_t i = 0; i < sizeof(T); i ++)
		{
			ar[i] = reinterpret_cast<uint8_t*>(&value)[i];
		}
	}
};


