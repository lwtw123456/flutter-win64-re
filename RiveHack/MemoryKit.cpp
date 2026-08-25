#include "MemoryKit.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <TlHelp32.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using ModuleRange = std::pair<uintptr_t, uintptr_t>;

std::pair<std::vector<uint8_t>, std::vector<bool>>
ParsePattern(const char* pattern)
{
    if (!pattern)
        return {};

    std::vector<uint8_t> bytes;
    std::vector<bool> mask;
    std::istringstream ss(pattern);
    std::string token;

    while (ss >> token) {
        if (token == "??") {
            bytes.push_back(0x00);
            mask.push_back(false);
            continue;
        }

        if (token.size() != 2)
            return {};

        try {
            size_t parsed = 0;
            const unsigned long value = std::stoul(token, &parsed, 16);

            if (parsed != token.size() || value > 0xFF)
                return {};

            bytes.push_back(static_cast<uint8_t>(value));
            mask.push_back(true);
        }
        catch (...) {
            return {};
        }
    }

    return { std::move(bytes), std::move(mask) };
}

std::optional<uintptr_t>
ScanBuffer(const uint8_t* buf,
           size_t bufLen,
           uintptr_t baseAddr,
           const std::vector<uint8_t>& bytes,
           const std::vector<bool>& mask)
{
    const size_t patLen = bytes.size();

    if (!buf || patLen == 0 || mask.size() != patLen || bufLen < patLen)
        return std::nullopt;

    size_t anchorOffset = 0;
    size_t anchorLen = 0;

    for (size_t i = 0; i < patLen;) {
        while (i < patLen && !mask[i])
            ++i;

        const size_t runStart = i;

        while (i < patLen && mask[i])
            ++i;

        const size_t runLen = i - runStart;
        if (runLen > anchorLen) {
            anchorOffset = runStart;
            anchorLen = runLen;
        }
    }

    if (anchorLen == 0)
        return baseAddr;

    const uint8_t* const anchor = bytes.data() + anchorOffset;

    std::array<size_t, 256> shift{};
    shift.fill(anchorLen);

    if (anchorLen > 1) {
        for (size_t i = 0; i + 1 < anchorLen; ++i)
            shift[anchor[i]] = anchorLen - 1 - i;
    }

    const size_t anchorLast = anchorLen - 1;
    const size_t maxAnchorPos = bufLen - anchorLen;
    const size_t maxCandidate = bufLen - patLen;

    size_t anchorPos = 0;

    while (anchorPos <= maxAnchorPos) {
        const uint8_t tail = buf[anchorPos + anchorLast];

        const bool anchorMatch =
            tail == anchor[anchorLast] &&
            (anchorLen == 1 ||
             std::memcmp(buf + anchorPos, anchor, anchorLen - 1) == 0);

        if (!anchorMatch) {
            const size_t step = shift[tail];
            anchorPos += (step != 0 ? step : 1);
            continue;
        }

        if (anchorPos >= anchorOffset) {
            const size_t candidate = anchorPos - anchorOffset;

            if (candidate <= maxCandidate) {
                bool match = true;

                for (size_t j = 0; j < anchorOffset; ++j) {
                    if (mask[j] && buf[candidate + j] != bytes[j]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    const size_t afterAnchor = anchorOffset + anchorLen;
                    for (size_t j = afterAnchor; j < patLen; ++j) {
                        if (mask[j] && buf[candidate + j] != bytes[j]) {
                            match = false;
                            break;
                        }
                    }
                }

                if (match)
                    return baseAddr + candidate;
            }
        }

        ++anchorPos;
    }

    return std::nullopt;
}

std::vector<ModuleRange> GetModuleRanges()
{
    std::vector<ModuleRange> ranges;

    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());

    if (hSnap == INVALID_HANDLE_VALUE)
        return ranges;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnap, &me)) {
        do {
            const uintptr_t base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
            const uintptr_t moduleSize = static_cast<uintptr_t>(me.modBaseSize);

            if (moduleSize <= (std::numeric_limits<uintptr_t>::max)() - base)
                ranges.emplace_back(base, base + moduleSize);

        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return ranges;
}

bool OverlapsAnyModule(uintptr_t base,
                       size_t size,
                       const std::vector<ModuleRange>& ranges)
{
    if (size > (std::numeric_limits<uintptr_t>::max)() - base)
        return true;

    const uintptr_t end = base + size;

    for (const auto& range : ranges) {
        const uintptr_t mBase = range.first;
        const uintptr_t mEnd = range.second;

        if (!(end <= mBase || base >= mEnd))
            return true;
    }

    return false;
}

bool IsExecutable(DWORD protect)
{
    const DWORD p = protect &
        ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

    return (p & (PAGE_EXECUTE |
                 PAGE_EXECUTE_READ |
                 PAGE_EXECUTE_READWRITE |
                 PAGE_EXECUTE_WRITECOPY)) != 0;
}

std::optional<uintptr_t> FindPatternImpl(const char* pattern)
{
    auto parsed = ParsePattern(pattern);
    const auto& bytes = parsed.first;
    const auto& mask = parsed.second;

    if (bytes.empty() || bytes.size() != mask.size())
        return std::nullopt;

    const auto moduleRanges = GetModuleRanges();

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t address = 0;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(address),
                        &mbi,
                        sizeof(mbi)) == sizeof(mbi)) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const size_t size = mbi.RegionSize;

        if (size == 0)
            break;

        if (mbi.State == MEM_COMMIT &&
            IsExecutable(mbi.Protect) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !OverlapsAnyModule(base, size, moduleRanges)) {

            std::vector<uint8_t> buffer(size);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(GetCurrentProcess(),
                                  reinterpret_cast<LPCVOID>(base),
                                  buffer.data(),
                                  size,
                                  &bytesRead) &&
                bytesRead > 0) {

                if (auto result = ScanBuffer(buffer.data(),
                                             static_cast<size_t>(bytesRead),
                                             base,
                                             bytes,
                                             mask)) {
                    /* First match in address order: stop the whole scan. */
                    return result;
                }
            }
        }

        if (size > (std::numeric_limits<uintptr_t>::max)() - base)
            break;

        const uintptr_t next = base + size;
        if (next <= address)
            break;

        address = next;
    }

    return std::nullopt;
}

bool PatchImpl(uintptr_t address, const char* patch)
{
    if (address == 0)
        return false;

    auto parsed = ParsePattern(patch);
    const auto& bytes = parsed.first;
    const auto& mask = parsed.second;

    if (bytes.empty() || bytes.size() != mask.size())
        return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(address),
                        bytes.size(),
                        PAGE_EXECUTE_READWRITE,
                        &oldProtect)) {
        return false;
    }

    auto* mem = reinterpret_cast<uint8_t*>(address);
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (mask[i])
            mem[i] = bytes[i];
    }

    DWORD unused = 0;
    const bool restored =
        VirtualProtect(reinterpret_cast<LPVOID>(address),
                       bytes.size(),
                       oldProtect,
                       &unused) != FALSE;

    const bool flushed =
        FlushInstructionCache(GetCurrentProcess(),
                              reinterpret_cast<LPCVOID>(address),
                              bytes.size()) != FALSE;

    return restored && flushed;
}

MemoryKitScanResult NotFound() noexcept
{
    MemoryKitScanResult result{};
    result.address = 0;
    result.found = 0;
    return result;
}

MemoryKitScanResult MakeFound(uintptr_t address) noexcept
{
    MemoryKitScanResult result{};
    result.address = address;
    result.found = 1;
    return result;
}

} /* namespace */

extern "C" {

MemoryKitScanResult MemoryKit_FindPattern(const char* pattern)
{
    try {
        const auto address = FindPatternImpl(pattern);
        return address ? MakeFound(*address) : NotFound();
    }
    catch (...) {
        /* Never allow C++ exceptions to cross the C ABI boundary. */
        return NotFound();
    }
}

MemoryKitScanResult MemoryKit_Offset(MemoryKitScanResult result,
                                     intptr_t offset)
{
    if (!result.found)
        return NotFound();

    const uintptr_t address = result.address;

    if (offset >= 0) {
        const uintptr_t delta = static_cast<uintptr_t>(offset);
        if (delta > (std::numeric_limits<uintptr_t>::max)() - address)
            return NotFound();
        return MakeFound(address + delta);
    }

    /* Avoid negating INTPTR_MIN directly. */
    const uintptr_t delta =
        static_cast<uintptr_t>(-(offset + 1)) + static_cast<uintptr_t>(1);

    if (delta > address)
        return NotFound();

    return MakeFound(address - delta);
}

int MemoryKit_Found(MemoryKitScanResult result)
{
    return result.found ? 1 : 0;
}

uintptr_t MemoryKit_Address(MemoryKitScanResult result)
{
    return result.found ? result.address : static_cast<uintptr_t>(0);
}

int MemoryKit_Patch(uintptr_t address, const char* patch)
{
    try {
        return PatchImpl(address, patch) ? 1 : 0;
    }
    catch (...) {
        return 0;
    }
}

int MemoryKit_FindAndPatch(const char* pattern, const char* patch)
{
    try {
        const auto address = FindPatternImpl(pattern);
        if (!address)
            return 0;

        return PatchImpl(*address, patch) ? 1 : 0;
    }
    catch (...) {
        return 0;
    }
}

} /* extern "C" */
