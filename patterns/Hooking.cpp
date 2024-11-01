#include "Hooking.h"
#include <Windows.h>
#include <cassert>
#include <memory>

#pragma warning(disable:4146)

namespace hook
{
	static inline ULONG_PTR AlignUp(ULONG_PTR stack, SIZE_T align) 
	{
		assert(align > 0 && (align & (align - 1)) == 0); // Power of 2
		assert(stack != 0);

		ULONG_PTR alignedAddr = (stack + (align - 1)) & ~(align - 1);
		assert(alignedAddr >= stack);
		return alignedAddr;
	}

	static inline ULONG_PTR AlignDown(ULONG_PTR stack, SIZE_T align) 
	{
		assert(align > 0 && (align & (align - 1)) == 0); // Ensure align is a power of 2
		assert(stack != 0);

		ULONG_PTR alignedAddr = stack & ~(align - 1);
		assert(alignedAddr <= stack);
		return alignedAddr;
	}

	void* AllocateStubMemory(SIZE_T size)
	{
		// Max range for seeking a memory block. (= 1024MB)
		constexpr uint64_t MAX_MEMORY_RANGE = 0x40000000;

		void* origin = GetModuleHandle(nullptr);

		ULONG_PTR minAddr;
		ULONG_PTR maxAddr;

		MEM_ADDRESS_REQUIREMENTS addressReqs = { 0 };
		MEM_EXTENDED_PARAMETER param = { 0 };

		SYSTEM_INFO si;
		GetSystemInfo(&si);
		minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
		maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

		
		// origin ± 512MB
		if ((ULONG_PTR)origin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)origin - MAX_MEMORY_RANGE)
			minAddr = (ULONG_PTR)origin - MAX_MEMORY_RANGE;

		if (maxAddr > (ULONG_PTR)origin + MAX_MEMORY_RANGE)
			maxAddr = (ULONG_PTR)origin + MAX_MEMORY_RANGE; 
		
		auto start = AlignUp(minAddr, si.dwAllocationGranularity);
		auto end = AlignDown(maxAddr, si.dwAllocationGranularity);

		addressReqs.Alignment = NULL; // any alignment
		addressReqs.LowestStartingAddress = (PVOID)start < si.lpMinimumApplicationAddress ? si.lpMinimumApplicationAddress : (PVOID)start;
		addressReqs.HighestEndingAddress = (PVOID)(end - 1) > si.lpMaximumApplicationAddress ? si.lpMaximumApplicationAddress : (PVOID)(end - 1);

		param.Type = MemExtendedParameterAddressRequirements;
		param.Pointer = &addressReqs;

		//using VirtualAlloc2 throws linker error gotta either use this workaround or use #pragma comment(lib, "mincore") to get it to work
		auto pVirtualAlloc2 = (decltype(&::VirtualAlloc2))GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualAlloc2");

		void* stub = nullptr;

		stub = pVirtualAlloc2(GetCurrentProcess(), nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &param, 1);

		return stub;
	}
}
