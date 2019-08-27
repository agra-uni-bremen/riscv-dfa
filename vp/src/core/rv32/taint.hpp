/*
 * taint.hpp
 *
 *  Created on: 22 Nov 2018
 *      Author: dwd
 */

#pragma once

#include <stdint.h>
#include <cstring>
#include <exception>
#include <iostream>
#include <sstream>

//#define DEBUG(x) x;
#define DEBUG(x) ;

struct TaintingException : public std::exception {
	std::string msg;
	TaintingException() : msg("Invalid tainting operation") {}
	TaintingException(std::string msg) : msg("Invalid tainting operation: " + msg) {}
	const char* what() const throw() override { return msg.c_str(); }
};

typedef uint8_t Taintlevel;
static constexpr Taintlevel mergeMask = 0b11000000;

enum MergeStrategy : Taintlevel {
	none      = 0b00000000,
	lowest    = 0b01000000,
	highest   = 0b10000000,
	forbidden = 0b11000000
};

inline std::string to_string(const Taintlevel& level) {
	std::ostringstream ss;
	switch(level & mergeMask)
	{
	case MergeStrategy::forbidden:
		ss << "forbidden ";
		break;
	case MergeStrategy::lowest:
		ss << "lowest: ";
		break;
	case MergeStrategy::highest:
		ss << "highest: ";
		break;
	default:
		ss << "none ";
		break;
	}
	ss << (level & (~mergeMask));
	return ss.str();
}

template <typename T>
class Taint {
	T value;
	Taintlevel id;

   public:
	void setTaintId(Taintlevel taintID) {
		if (!allowed(taintID, getTaintId())) {
			throw(TaintingException("Invalid setTaint from " + to_string(getTaintId()) + " to " + to_string(taintID)));
		}
		id = mergeTaintingValues(getTaintId(), taintID);
	}

	Taintlevel getTaintId() const {
		return id;
	}

	Taint() {
		// DEBUG(std::cout << "Construct empty" << std::endl);
		// intentionally left value undefined
		id = 0;
	}

	Taint(const Taint<T>& other) {
		// DEBUG(std::cout << "Construct from Taint " << int(other.value) << " id (" << int(other.getTaintId()) << ")"
		// << std::endl);
		value = other.value;
		id = other.id;
	}

	Taint(const T other) {
		// DEBUG(std::cout << "Construct from basetype " << int(other) << std::endl);
		value = other;
		id = 0;
	}

	Taint(const T other, const Taintlevel taint) {
		// DEBUG(std::cout << "Construct from basetype " << int(other) << " with taint " << int(taint) << std::endl);
		value = other;
		id = taint;
	}

	Taint(Taint<uint8_t> ar[sizeof(T)]) {
		Taintlevel taint = ar[0].getTaintId();
		for (uint8_t i = 0; i < sizeof(T); i++) {
			if (taint != ar[i].getTaintId()) {
				taint = mergeTaintingValues(taint, ar[i].getTaintId());
			}
			// magic that relies that value is first byte in ar[i]
			reinterpret_cast<uint8_t*>(&value)[i] = ar[i].require(taint);
		}
		id = taint;
	}

	friend void swap(Taint<T>& lhs, Taint<T>& rhs) {
		std::swap(lhs.value, rhs.value);
		std::swap(lhs.id, rhs.id);
	}

	static bool allowed(const Taintlevel to, const Taintlevel from)
	{
		if (to == from) {
			return true;
		} else{
			MergeStrategy tom = static_cast<MergeStrategy>(to & mergeMask);
			MergeStrategy frm = static_cast<MergeStrategy>(from & mergeMask);
			if(frm == MergeStrategy::forbidden || tom == MergeStrategy::forbidden)
				return false;
			switch (frm) {
				case MergeStrategy::lowest:
					//this includes to = none = 0 < from
					return tom == MergeStrategy::highest ? true : from > to;
				case MergeStrategy::highest:	//high/none to lowest forbidden
				case MergeStrategy::none:
					return tom == MergeStrategy::lowest ? false : from < to;
				default:
					break;
			}
		}
		return false;
	}

	static Taintlevel mergeTaintingValues(const Taintlevel a, const Taintlevel b) {
		if (a == b) {
			return a;
		} else {
			MergeStrategy am = static_cast<MergeStrategy>(a & mergeMask);
			MergeStrategy bm = static_cast<MergeStrategy>(b & mergeMask);

			if(am == MergeStrategy::forbidden || bm == MergeStrategy::forbidden)
			{
				throw(TaintingException("merging forbidden by policy"));
				return 0;
			}
			switch (am) {
			case MergeStrategy::lowest:
				switch(bm)
				{
				case MergeStrategy::lowest:	//low: low
					return a < b ? a : b;
				case MergeStrategy::highest: //lowest and highest, choose highest
					return b;
				case MergeStrategy::none:	 //lowest and none: demote to none
					return 0;
				default:
					break;
				}
				break;
			case MergeStrategy::highest:
				switch(bm)
				{
				case MergeStrategy::lowest:	//lowest and highest, choose highest
				case MergeStrategy::none:	//highest and none: promote to highest
					return a;
				case MergeStrategy::highest: //highest: highest
					return a > b ? a : b;
				default:
					break;
				}
				break;
			case MergeStrategy::none:
				switch(bm)
				{
				case MergeStrategy::none:	//none and none: why are you even here?
				case MergeStrategy::lowest:	//lowest and none: demote to none
					return 0;
				case MergeStrategy::highest: //highest and none: promote to highest
					return b;
				default:
					break;
				}
				break;
			default:
				break;
			}
		}
		throw(TaintingException("invalid merging policy"));
		return 0;
	}

	Taint<T>& operator=(const Taint<T>& other) {
		// DEBUG(std::cout << "Move operator = " << int(other.value) << " id (" << int(other.getTaintId()) << ")" <<
		// std::endl);
		//if(!allowed(getTaintId(), other.getTaintId()))
		//{
		//	throw(TaintingException("Forbidden flow from " + to_string(other.getTaintId()) + " to " + to_string(getTaintId())));
		//}
		Taint<T> temp(other);
		swap(*this, temp);

		return *this;
	}

	Taint<T> operator+(const Taint<T>& other) {
		Taint<T> ret(value + other.value, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<T> operator+(const T& other) {
		Taint<T> ret(*this);
		ret.value += other;
		return ret;
	}

	Taint<bool> operator<(const Taint<T>& other) {
		Taint<bool> ret(value < other.value, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<bool> operator<(const T& other) {
		Taint<bool> ret(value < other, getTaintId());
		return ret;
	}

	Taint<bool> operator==(const Taint<T>& other) {
		Taint<bool> ret(value == other.value, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<bool> operator==(const T& other) {
		Taint<bool> ret(value == other, getTaintId());
		return ret;
	}

	Taint<T> operator^(const Taint<T>& other) {
		Taint<T> ret(value ^ other.value, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator^(const N& other) {
		Taint<T> ret(*this);
		ret.value ^= other;
		return ret;
	}

	Taint<T> operator|(const Taint<T>& other) {
		Taint<T> ret(value | other, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator|(const N& other) {
		Taint<T> ret(*this);
		ret.value |= other;
		return ret;
	}

	Taint<T> operator&(const Taint<T>& other) {
		Taint<T> ret(value & other, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator&(const N& other) {
		Taint<T> ret(*this);
		ret.value &= other;
		return ret;
	}

	Taint<T> operator<<(const Taint<T>& other) {
		Taint<T> ret(value << other.value, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator<<(const N& other) {
		Taint<T> ret(*this);
		ret.value <<= other;
		return ret;
	}

	Taint<T> operator>>(const Taint<T>& other) {
		Taint<T> ret(value >> other.value, mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator>>(const N& other) {
		Taint<T> ret(*this);
		ret.value >>= other;
		return ret;
	}

	T require(Taintlevel level) const {
		if (!allowed(level, getTaintId())) {
			throw TaintingException("Unsatisfiable require from " + to_string(getTaintId()) +
			                        " to " + to_string(level));
		}
		return value;
	}

	operator T() const { return require(0); }

	// debugging only
	T peek() {
		if (id != 0) {
			std::cout << "Warning: Peeking into Object with taint ID " << Taintlevel(id) << std::endl;
		}
		return value;
	}

	// implicit Type conversions for Register width
	// Note: This only works with big-endian host processors
	template <typename N>
	operator Taint<N>() const {
		// DEBUG(std::cout << "Conversion of " << int(value) << " id (" << int(getTaintId()) << ")" << std::endl);
		Taint<N> temp(value, getTaintId());
		return temp;
	}

	template <typename N>
	Taint<N> as() {
		Taint<N> ret(static_cast<N>(value), getTaintId());
		return ret;
	}

	static void expand(Taint<uint8_t> ar[sizeof(T)], T value, Taintlevel taint = 0) {
		for (uint8_t i = 0; i < sizeof(T); i++) {
			ar[i] = Taint<uint8_t>(reinterpret_cast<uint8_t*>(&value)[i], taint);
		}
	}

	void expand(Taint<uint8_t> ar[sizeof(T)]) { expand(ar, value, getTaintId()); }
};
