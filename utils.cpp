#include "utils.h"


extern "C"
{
    NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
        ULONG SystemInformationLength, PULONG ReturnLength);
}

NTSTATUS GetKernelModuleByName(const char* moduleName, uintptr_t* moduleStart, size_t* moduleSize)
{
    if (!moduleStart || !moduleSize)
        return STATUS_INVALID_PARAMETER;

    size_t size{};
    ZwQuerySystemInformation(0xB, nullptr, size, reinterpret_cast<PULONG>(&size));

    const auto listHeader = ExAllocatePool(NonPagedPool, size);
    if (!listHeader)
        return STATUS_MEMORY_NOT_ALLOCATED;

    if (const auto status = ZwQuerySystemInformation(0xB, listHeader, size, reinterpret_cast<PULONG>(&size)))
        return status;

    auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;
    for (size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
    {
        const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
        if (!strcmp(moduleName, currentModuleName))
        {
            *moduleStart = reinterpret_cast<uintptr_t>(currentModule->ImageBase);
            *moduleSize = currentModule->ImageSize;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS LoadFileIntoBuffer(char** pbuf, const wchar_t* filepath, HANDLE& fileHandle)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_STANDARD_INFORMATION fileInfo;
    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, filepath);
    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InitializeObjectAttributes(&attributes, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&fileHandle,
        GENERIC_READ,
        &attributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
    {
        // handle error
        return status;
    }

    // Get file size
    status = ZwQueryInformationFile(fileHandle,
        &ioStatusBlock,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation);

    if (!NT_SUCCESS(status))
    {
        // handle error
        ZwClose(fileHandle);
        return status;
    }

    // Allocate memory according to file size
    *pbuf = (char*)ExAllocatePoolWithTag(NonPagedPool, fileInfo.EndOfFile.QuadPart, 0x69420);
    if (!*pbuf)
    {
        // handle error
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwReadFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        *pbuf,
        fileInfo.EndOfFile.QuadPart,
        &byteOffset,
        NULL);

    if (!NT_SUCCESS(status))
    {
        // handle error
        ExFreePoolWithTag(*pbuf, 0x69420);
        ZwClose(fileHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS UnloadFileBuffer(char** pbuf, HANDLE& fileHandle, ULONG tag)
{
    ExFreePoolWithTag(*pbuf, tag);
    return ZwClose(fileHandle);
}

uintptr_t ScanPattern(UINT8* base, const size_t size, char* pattern, char* mask)
{
    const auto patternSize = strlen(mask);

    for (size_t i = {}; i < size - patternSize; i++)
    {
        for (size_t j = {}; j < patternSize; j++)
        {
            if (mask[j] != '?' && *reinterpret_cast<UINT8*>(base + i + j) != static_cast<UINT8>(pattern[j]))
                break;

            if (j == patternSize - 1)
                return reinterpret_cast<uintptr_t>(base) + i;
        }
    }

    return {};
}