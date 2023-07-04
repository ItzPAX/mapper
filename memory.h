#pragma once
#include "include.h"

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		list;
	UNICODE_STRING	driverName;
	ULONG			driverStamp;
	NTSTATUS		loadStatus;
};

typedef struct _POOL_TRACKER_BIG_PAGES
{
	PVOID Va;
	ULONG Key;
	ULONG PoolType;
	ULONG NumberOfBytes;
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

NTSTATUS CleanBigPoolAllocation(uintptr_t allocation_address);