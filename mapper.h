#pragma once

#include <ntifs.h>
#include <windef.h>

#include <ntimage.h>
#include <cstdint>
#include <cstddef>

using EntryFuncCall = NTSTATUS(__stdcall*) ();

BOOLEAN ResolveImports(char* driver);
BOOLEAN ResolveRelocations(uintptr_t old, uintptr_t newBase, uintptr_t delta);

BOOLEAN MapDriver(char* driver, PDRIVER_OBJECT object);