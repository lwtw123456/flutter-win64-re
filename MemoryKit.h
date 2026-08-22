// MemoryKit.h
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uintptr_t MemoryKit_FindPattern(uintptr_t baseAddress, size_t scanSize, const char* pattern);

int MemoryKit_Patch(uintptr_t address, const char* patch);

int MemoryKit_FindAndPatch(uintptr_t baseAddress, size_t scanSize,
                           const char* pattern, const char* patch);

#ifdef __cplusplus
}
#endif