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
	forbidden = 0b00000000,
	lowest    = 0b01000000,
	highest   = 0b10000000,
	error     = 0b11000000
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
		ss << "error ";
		break;
	}
	ss << (level & (~mergeMask));
	return ss.str();
}

template <typename T>
class Taint {
	T value;
	Taintlevel id[sizeof(T)];

   public:
	void setTaintId(Taintlevel taintID) {
		if (!allowed(taintID, getTaintId())) {
			throw(TaintingException("Invalid setTaint from " + to_string(getTaintId()) + " to " + to_string(taintID)));
		}
		memset(id, mergeTaintingValues(getTaintId(), taintID), sizeof(T));
	}

	Taintlevel getTaintId() const {
		uint8_t taintID = id[0];
		for (uint8_t i = 1; i < sizeof(T); i++) {
			if (taintID != id[i]) {
				throw(TaintingException("Unaligned read on Taint Object"));
			}
		}
		return taintID;
	}

	Taint() {
		// DEBUG(std::cout << "Construct empty" << std::endl);
		// intentionally left value undefined
		id[0] = 0;
		if (sizeof(T) > 1)  // Most instances will be uint8_t -> Size 1
		{
			memset(id, 0, sizeof(T));
		}
	}

	Taint(const Taint<T>& other) {
		// DEBUG(std::cout << "Construct from Taint " << int(other.value) << " id (" << int(other.getTaintId()) << ")"
		// << std::endl);
		value = other.value;
		memcpy(id, other.id, sizeof(T));
	}

	Taint(const T other) {
		// DEBUG(std::cout << "Construct from basetype " << int(other) << std::endl);
		value = other;
		memset(id, 0, sizeof(T));
	}

	Taint(const T other, Taintlevel taint) {
		// DEBUG(std::cout << "Construct from basetype " << int(other) << " with taint " << int(taint) << std::endl);
		value = other;
		memset(id, taint, sizeof(T));
	}

	Taint(Taint<uint8_t> ar[sizeof(T)]) {
		Taintlevel taint = ar[0].getTaintId();
		for (uint8_t i = 0; i < sizeof(T); i++) {
			if (taint != ar[i].getTaintId()) {
				if (taint == 0) {
					std::cerr << "unaligned confine on Taint Objects?" << std::endl;
					taint = ar[i].getTaintId();
				} else {
					throw(TaintingException("Unaligned confine on different tainted Objects"));
				}
			}
			// magic that relies that value is first byte in ar[i]
			reinterpret_cast<uint8_t*>(&value)[i] = ar[i].require(taint);
		}
		memset(id, taint, sizeof(T));
	}

	friend void swap(Taint<T>& lhs, Taint<T>& rhs) {
		std::swap(lhs.value, rhs.value);
		std::swap(lhs.id, rhs.id);
	}

	static bool allowed(const Taintlevel to, const Taintlevel from)
	{
		if (to == from) {
			return true;
		} else if (from == 0 || to == 0) {	//Well, technically...
			return true;
		} else{
			MergeStrategy tom = static_cast<MergeStrategy>(to & mergeMask);
			MergeStrategy frm = static_cast<MergeStrategy>(from & mergeMask);
			if (tom != frm) {
				//Special case: lowest to highest is allowed
				return frm == MergeStrategy::lowest && tom == MergeStrategy::highest;
			}
			switch (frm) {
				case MergeStrategy::forbidden:
					return false;
				case MergeStrategy::lowest:
					return from > to;
				case MergeStrategy::highest:
					return from < to;
				default:
					throw(TaintingException("invalid merging policy"));
			}
		}
	}

	static Taintlevel mergeTaintingValues(const Taintlevel a, const Taintlevel b) {
		if (a == b) {
			return a;
		} else {
			if (a > 0 && b == 0) {
				return a;
			} else if (b > 0 && a == 0) {
				return b;
			} else {
				MergeStrategy am = static_cast<MergeStrategy>(a & mergeMask);
				MergeStrategy bm = static_cast<MergeStrategy>(b & mergeMask);
				if (am != bm) {
					if( (am == MergeStrategy::lowest || bm == MergeStrategy::lowest) &&
					    (am == MergeStrategy::highest|| bm == MergeStrategy::highest))
					//Special case: lowest + highest = highest
					{
						return am == MergeStrategy::highest ? a : b;
					}else
					{
						throw(TaintingException("Invalid combination of merging policies " << to_string(a) << " and " << to_string(b)));
					}
					return 0;
				}
				switch (am) {
					case MergeStrategy::forbidden:
						throw(TaintingException("merging forbidden by policy"));
						return 0;
					case MergeStrategy::lowest:
						return a < b ? a : b;
					case MergeStrategy::highest:
						return a > b ? a : b;
					default:
						throw(TaintingException("invalid merging policy"));
				}
			}
		}
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
		Taint<T> ret(value + other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<T> operator+(const T& other) {
		Taint<T> ret(*this);
		ret.value += other;
		return ret;
	}

	Taint<bool> operator<(const Taint<T>& other) {
		Taint<bool> ret(value < other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<bool> operator<(const T& other) {
		Taint<bool> ret(value < other);
		ret.setTaintId(getTaintId());
		return ret;
	}

	Taint<bool> operator==(const Taint<T>& other) {
		Taint<bool> ret(value == other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	Taint<bool> operator==(const T& other) {
		Taint<bool> ret(value == other);
		ret.setTaintId(getTaintId());
		return ret;
	}

	Taint<T> operator^(const Taint<T>& other) {
		Taint<T> ret(value ^ other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator^(const N& other) {
		Taint<T> ret(*this);
		ret.value ^= other;
		return ret;
	}

	Taint<T> operator|(const Taint<T>& other) {
		Taint<T> ret(value | other);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator|(const N& other) {
		Taint<T> ret(*this);
		ret.value |= other;
		return ret;
	}

	Taint<T> operator&(const Taint<T>& other) {
		Taint<T> ret(value & other);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator&(const N& other) {
		Taint<T> ret(*this);
		ret.value &= other;
		return ret;
	}

	Taint<T> operator<<(const Taint<T>& other) {
		Taint<T> ret(value << other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
		return ret;
	}

	template <typename N>
	Taint<T> operator<<(const N& other) {
		Taint<T> ret(*this);
		ret.value <<= other;
		return ret;
	}

	Taint<T> operator>>(const Taint<T>& other) {
		Taint<T> ret(value >> other.value);
		ret.setTaintId(mergeTaintingValues(getTaintId(), other.getTaintId()));
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
		if (id[0] != 0) {
			std::cout << "Warning: Peeking into Object with taint ID " << Taintlevel(id[0]) << std::endl;
		}
		return value;
	}

	// implicit Type conversions for Register width
	// Note: This only works with big-endian host processors
	template <typename N>
	operator Taint<N>() const {
		// DEBUG(std::cout << "Conversion of " << int(value) << " id (" << int(getTaintId()) << ")" << std::endl);
		Taint<N> temp(value);
		temp.setTaintId(getTaintId());
		return temp;
	}

	template <typename N>
	Taint<N> as() {
		Taint<N> ret(static_cast<N>(value));
		ret.setTaintId(getTaintId());
		return ret;
	}

	static void expand(Taint<uint8_t> ar[sizeof(T)], T value, Taintlevel taint = 0) {
		for (uint8_t i = 0; i < sizeof(T); i++) {
			ar[i] = reinterpret_cast<uint8_t*>(&value)[i];
			ar[i].setTaintId(taint);
		}
	}

	void expand(Taint<uint8_t> ar[sizeof(T)]) { expand(ar, value, getTaintId()); }
};
