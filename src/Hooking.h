#pragma once
#include <Windows.h>
#include <stdint.h>
#include <type_traits>

#include "Hooking.Patterns.h"

/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 *
 * https://github.com/citizenfx/fivem/blob/master/code/client/shared/Hooking.h
 */

namespace hook
{
	extern ptrdiff_t baseAddressDifference;

	inline constexpr uintptr_t exe_end()
	{
		return 0x146000000;
	}

	template<typename T>
	inline T get_call(T address)
	{
		intptr_t target = *(int*)((uintptr_t)address + 1);
		target += ((uintptr_t)address + 5);

		return (T)target;
	}

	template<typename T, typename TAddr>
	inline T get_address(TAddr address)
	{
		intptr_t target = *(int*)(uintptr_t)address;
		target += ((uintptr_t)address + 4);

		return (T)target;
	}

	template<typename T, typename TAddr>
	inline T get_address(TAddr address, size_t offsetTo4ByteAddr, size_t numBytesInLine)
	{
		intptr_t target = *(int*)((uintptr_t)address + offsetTo4ByteAddr);
		target += ((uintptr_t)(address)+numBytesInLine);

		return (T)target;
	}

	// returns the adjusted address to the stated base
	template<typename T>
	inline uintptr_t get_adjusted(T address)
	{
		if ((uintptr_t)address >= 0x140000000 && (uintptr_t)address <= exe_end())
		{
			return (uintptr_t)address + baseAddressDifference;
		}

		return (uintptr_t)address;
	}

	template<typename AddressType>
	inline void nop(AddressType address, size_t length)
	{
		memset((void*)address, 0x90, length);
	}

	void* AllocateFunctionStub(void* origin, void* function, int type);

	template<typename T>
	struct get_func_ptr
	{
		static void* get(T func)
		{
			return (void*)func;
		}
	};

	template<int Register, typename T, typename AT>
	inline std::enable_if_t<(Register < 8 && Register >= 0)> jump_reg(AT address, T func)
	{
		LPVOID funcStub = AllocateFunctionStub((void*)GetModuleHandle(NULL), get_func_ptr<T>::get(func), Register);

		put<uint8_t>(address, 0xE9);
		put<int>((uintptr_t)address + 1, (intptr_t)funcStub - (intptr_t)address - 5);
	}

	template<typename T, typename AT>
	inline void jump(AT address, T func)
	{
		jump_reg<0>(address, func);
	}

	template<typename T, typename AT>
	inline void jump_rcx(AT address, T func)
	{
		jump_reg<1>(address, func);
	}

	template<int Register, typename T, typename AT>
	inline std::enable_if_t<(Register < 8 && Register >= 0)> call_reg(AT address, T func)
	{
		LPVOID funcStub = AllocateFunctionStub((void*)GetModuleHandle(NULL), get_func_ptr<T>::get(func), Register);

		put<uint8_t>(address, 0xE8);
		put<int>((uintptr_t)address + 1, (intptr_t)funcStub - (intptr_t)address - 5);
	}

	template<typename T, typename AT>
	inline void call(AT address, T func)
	{
		call_reg<0>(address, func);
	}

	template<typename T, typename AT>
	inline void call_rcx(AT address, T func)
	{
		call_reg<1>(address, func);
	}

	//taken most of this code is taken form cfx.re and modfified a little
	template<typename ValueType, typename AddressType>
	inline void put(AddressType address, ValueType value)
	{
		DWORD oldProtect;
		VirtualProtect((void*)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect);

		std::memcpy((void*)address, &value, sizeof(value));

		VirtualProtect((void*)address, sizeof(value), oldProtect, &oldProtect);

		FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(value));
	}
	//simple code to patch stuff
	template<typename T, size_t Bytes, typename AddressType>
	inline void patch(AddressType address, const T(&patch)[Bytes])
	{
		DWORD oldProtect;
		VirtualProtect(reinterpret_cast<void*>(address), std::size(patch), PAGE_EXECUTE_READWRITE, &oldProtect);

		std::memcpy(reinterpret_cast<void*>(address), patch, std::size(patch));

		VirtualProtect(reinterpret_cast<void*>(address), std::size(patch), oldProtect, &oldProtect);

		FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), std::size(patch));
	}

	void* AllocateStubMemory(size_t size);
}