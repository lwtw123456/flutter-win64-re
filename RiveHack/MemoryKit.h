#ifndef MEMORYKIT_H
#define MEMORYKIT_H

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
#  if defined(MEMORYKIT_BUILD_DLL)
#    define MEMORYKIT_API __declspec(dllexport)
#  elif defined(MEMORYKIT_USE_DLL)
#    define MEMORYKIT_API __declspec(dllimport)
#  else
#    define MEMORYKIT_API
#  endif
#else
#  define MEMORYKIT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MemoryKitScanResult {
    uintptr_t address;
    int found;
} MemoryKitScanResult;

MEMORYKIT_API MemoryKitScanResult MemoryKit_FindPattern(const char* pattern);

MEMORYKIT_API MemoryKitScanResult MemoryKit_Offset(MemoryKitScanResult result,
                                                   intptr_t offset);

MEMORYKIT_API int MemoryKit_Found(MemoryKitScanResult result);

MEMORYKIT_API uintptr_t MemoryKit_Address(MemoryKitScanResult result);

MEMORYKIT_API int MemoryKit_Patch(uintptr_t address, const char* patch);

MEMORYKIT_API int MemoryKit_FindAndPatch(const char* pattern, const char* patch);

#ifdef __cplusplus
} /* extern "C" */

namespace MemoryKitCpp {
class ScanResult {
public:
    explicit ScanResult(MemoryKitScanResult value) noexcept : value_(value) {}

    ScanResult& Offset(intptr_t bytes) noexcept {
        value_ = MemoryKit_Offset(value_, bytes);
        return *this;
    }

    bool Found() const noexcept {
        return MemoryKit_Found(value_) != 0;
    }

    uintptr_t Address() const noexcept {
        return MemoryKit_Address(value_);
    }

private:
    MemoryKitScanResult value_;
};

inline ScanResult FindPattern(const char* pattern) noexcept {
    return ScanResult(MemoryKit_FindPattern(pattern));
}
} /* namespace MemoryKitCpp */
#endif

#endif /* MEMORYKIT_H */