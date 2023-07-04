#include "memory.h"
#include "utils.h"

NTSTATUS CleanBigPoolAllocation(uintptr_t allocation_address)
{
	uintptr_t ntoskrnlBase{};
	size_t ntoskrnlSize{};

	GetKernelModuleByName("ntoskrnl.exe", &ntoskrnlBase, &ntoskrnlSize);
	DbgPrint("%p", ntoskrnlBase);
	
	uintptr_t exProtectPoolExCallInstructionsAddress = ScanPattern(reinterpret_cast<UINT8*>(ntoskrnlBase), ntoskrnlSize, const_cast<char*>("\xE8\x00\x00\x00\x00\x83\x67\x0C\x00"), const_cast<char*>("x????xxxx"));
	DbgPrint("%p", exProtectPoolExCallInstructionsAddress);
	
	if (!exProtectPoolExCallInstructionsAddress)
		return STATUS_NOT_FOUND;
	
	void* ExProtectPoolExAddress = reinterpret_cast<void*>(exProtectPoolExCallInstructionsAddress + *reinterpret_cast<INT32*>(exProtectPoolExCallInstructionsAddress + 1) + 5);
	
	if (!ExProtectPoolExAddress)
		return STATUS_NOT_FOUND;
	
	uintptr_t PoolBigPageTableInstructionAddress = ((ULONG64)ExProtectPoolExAddress + 0x95);
	UINT64 pPoolBigPageTable = (UINT64)(PoolBigPageTableInstructionAddress + *reinterpret_cast<INT32*>(PoolBigPageTableInstructionAddress + 3) + 7);
	
	uintptr_t PoolBigPageTableSizeInstructionAddress = ((ULONG64)ExProtectPoolExAddress + 0x8E);
	UINT64 pPoolBigPageTableSize = (UINT64)(PoolBigPageTableSizeInstructionAddress + *reinterpret_cast<INT32*>(PoolBigPageTableSizeInstructionAddress + 3) + 7);
	
	if (!pPoolBigPageTableSize || !pPoolBigPageTable)
		return STATUS_NOT_FOUND;
	
	PPOOL_TRACKER_BIG_PAGES PoolBigPageTable = 0;
	RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);
	
	SIZE_T PoolBigPageTableSize = 0;
	RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);
	
	if (!PoolBigPageTableSize || !PoolBigPageTable)
		return STATUS_NOT_FOUND;
	
	for (int i = 0; i < PoolBigPageTableSize; i++)
	{
		if (PoolBigPageTable[i].Va == reinterpret_cast<void*>(allocation_address) || PoolBigPageTable[i].Va == reinterpret_cast<void*>(allocation_address + 0x1))
		{
			PoolBigPageTable[i].Va = reinterpret_cast<void*>(0x1);
			PoolBigPageTable[i].NumberOfBytes = 0x0;
	
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}