#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <wdm.h>

#pragma warning (disable : 4100 4996 4244 4471) // unreferenced variable

#define RelativeAddress(addr, size) ((PVOID*)((BYTE*)(addr) + *(INT*)((BYTE*)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
extern "C" VOID DrvUnload(PDRIVER_OBJECT DriverObject);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DrvUnload)