#include "mapper.h"
#include "utils.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrint("[NigMapper] DriverEntry Called");
    DriverObject->DriverUnload = DrvUnload;
	
    char* driver_buffer;
    HANDLE file;
    NTSTATUS status = LoadFileIntoBuffer(&driver_buffer, L"\\??\\C:\\Windows\\rwdriver.sys", file);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Error when reading file into buffer! %x", status);
        return STATUS_SUCCESS;
    }

    MapDriver(driver_buffer, DriverObject);

    UnloadFileBuffer(&driver_buffer, file);

    return STATUS_SUCCESS;
}

VOID DrvUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("[NigMapper] Bye from mapper :)");
    reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection)->BaseDllName.Length = 0;
}