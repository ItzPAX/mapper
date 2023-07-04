#include "mapper.h"
#include "utils.h"
#include "memory.h"

extern "C"
{
    extern "C" NTKERNELAPI
        PVOID
        NTAPI
        RtlFindExportedRoutineByName(
            _In_ PVOID ImageBase,
            _In_ PCCH RoutineNam
        );
}

PIMAGE_SECTION_HEADER TranslateRawSection(PIMAGE_NT_HEADERS nt, UINT32 rva)
{
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
        {
            return section;
        }
    }

    return NULL;
}

PVOID TranslateRaw(BYTE* base, PIMAGE_NT_HEADERS nt, UINT32 rva)
{
    auto section = TranslateRawSection(nt, rva);
    if (!section)
    {
        return NULL;
    }

    return base + section->PointerToRawData + (rva - section->VirtualAddress);
}

BOOLEAN ResolveImports(char* driver)
{
    const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(driver);
    const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(driver + dosHeaders->e_lfanew);

    auto rva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva)
    {
        return TRUE;
    }

    auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(TranslateRaw(reinterpret_cast<PBYTE>(driver), ntHeaders, rva));
    if (!importDescriptor)
    {
        return TRUE;
    }

    for (; importDescriptor->FirstThunk; ++importDescriptor)
    {
        auto moduleName = reinterpret_cast<PCHAR>(TranslateRaw(reinterpret_cast<PBYTE>(driver), ntHeaders, importDescriptor->Name));
        if (!moduleName)
        {
            break;
        }

        uintptr_t processModuleBase = NULL;
        size_t processModuleSize = 0;

        GetKernelModuleByName(moduleName, &processModuleBase, &processModuleSize);

        if (!processModuleBase)
        {
            return FALSE;
        }

        for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(TranslateRaw(reinterpret_cast<PBYTE>(driver), ntHeaders, importDescriptor->FirstThunk)); thunk->u1.AddressOfData; ++thunk)
        {
            auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(TranslateRaw(reinterpret_cast<PBYTE>(driver), ntHeaders, static_cast<DWORD>(thunk->u1.AddressOfData)));

            std::uintptr_t funcPtr = reinterpret_cast<std::uintptr_t>(RtlFindExportedRoutineByName(reinterpret_cast<PVOID>(processModuleBase), importByName->Name));

            DbgPrint("Found import for %s in module %s at 0x%p", importByName->Name, moduleName, funcPtr);

            if (!funcPtr)
            {
                return FALSE;
            }

            thunk->u1.Function = funcPtr;
        }
    }

    return TRUE;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

BOOLEAN ResolveRelocations(uintptr_t old, uintptr_t newBase, uintptr_t delta)
{
    const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(old);
    const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(old + dosHeaders->e_lfanew);

    if (!delta)
        return TRUE;

    if (!ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        return FALSE;

    auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(newBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    DbgPrint("Magic: 0x%x", ntHeaders->OptionalHeader.Magic);

    DbgPrint("Relocation from 0x%p", current_base_relocation);
    DbgPrint("Current VA 0x%p Current Size 0x%p", current_base_relocation->VirtualAddress, current_base_relocation->SizeOfBlock);

    while (current_base_relocation->VirtualAddress)
    {
        uint64_t current_reloc_address = newBase + current_base_relocation->VirtualAddress;
        uint16_t* current_reloc_item = reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
        uint32_t current_reloc_count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
    
        DbgPrint("Addr 0x%p, item 0x%p, count %x", current_reloc_address, current_reloc_item, current_reloc_count);
    
        for (auto i = 0u; i < current_reloc_count; ++i)
        {
            const uint16_t type = current_reloc_item[i] >> 12;
            const uint16_t offset = current_reloc_item[i] & 0xFFF;
        
            if (type == IMAGE_REL_BASED_DIR64)
                *reinterpret_cast<uint64_t*>(current_reloc_address + offset) += delta;
        }
        current_base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(current_base_relocation) + current_base_relocation->SizeOfBlock);
    }

    return TRUE;
}

BOOLEAN MapDriver(char* driver, PDRIVER_OBJECT object)
{
    const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(driver);
    const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(driver + dosHeaders->e_lfanew);
    
    if (!ntHeaders)
    {
        DbgPrint("Failed to get nt header");
        return FALSE;
    }

    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        DbgPrint("Image isnt 64bit");
        return FALSE;
    }


    DbgPrint("RtlFindExportedRoutineByName -> 0x%p", RtlFindExportedRoutineByName);

    if (!ResolveImports(driver))
    {
        DbgPrint("Failed to resolve imports");
        return FALSE;
    }

    UINT32 imagesize = ntHeaders->OptionalHeader.SizeOfImage;
    void* image_base = ExAllocatePool(NonPagedPool, imagesize);

    do
    {
        if (!image_base)
        {
            DbgPrint("Failed to allocate memory for driver");
            return FALSE;
        }
        
        DbgPrint("Image allocated at 0x%p", image_base);
        
        if (!NT_SUCCESS(CleanBigPoolAllocation((uintptr_t)image_base)))
            break;

        //memcpy(image_base, driver, ntHeaders->OptionalHeader.SizeOfHeaders);
        
        PIMAGE_SECTION_HEADER curr_image_section = IMAGE_FIRST_SECTION(ntHeaders);
        
        for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            if (curr_image_section[i].SizeOfRawData)
            {
                if (strcmp((char*)curr_image_section[i].Name, ".reloc") == 0)
                {
                    DbgPrint("nulling section %s, with size %x", curr_image_section[i].Name, curr_image_section[i].SizeOfRawData);
                    auto new_section = (uintptr_t)image_base + curr_image_section[i].VirtualAddress;
                    auto section_data = ExAllocatePool(NonPagedPool, curr_image_section[i].SizeOfRawData);
                    memcpy((void*)new_section, (void*)section_data, curr_image_section[i].SizeOfRawData);
                
                    ExFreePool(section_data);
                
                    continue;
                }
                auto new_section = (uintptr_t)image_base + curr_image_section[i].VirtualAddress;
                auto section_data = (uintptr_t)driver + curr_image_section[i].PointerToRawData;
                memcpy((void*)new_section, (void*)section_data, curr_image_section[i].SizeOfRawData);

                DbgPrint("Copying section %s (size: %x) from 0x%p -> 0x%p (VA: 0x%p)", curr_image_section[i].Name, curr_image_section[i].SizeOfRawData, section_data, new_section, curr_image_section[i].VirtualAddress);
            }
            else
            {
                DbgPrint("Omitting section %s as it has no data", curr_image_section[i].Name);
            }
        }
        
        if (!ResolveRelocations((uintptr_t)driver, (uintptr_t)image_base, (uintptr_t)image_base - ntHeaders->OptionalHeader.ImageBase))
        {
            DbgPrint("Failed to relocate binary");
            break;
        }
        
        EntryFuncCall mappedEntryPoint = reinterpret_cast<EntryFuncCall>((uintptr_t)image_base + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        DbgPrint("EntryPoint at 0x%p, offset 0x%x", mappedEntryPoint, ntHeaders->OptionalHeader.AddressOfEntryPoint);
        for (int i = 0; i < 10; i++)
        {
            DbgPrint("Byte %d of EntryPoint: 0x%X", i, (*(uintptr_t*)((uintptr_t)mappedEntryPoint + i)) & 0xFF);
        }

        mappedEntryPoint();

        return TRUE;

    } while (false);

    ExFreePool(image_base);  
    return FALSE;
}
