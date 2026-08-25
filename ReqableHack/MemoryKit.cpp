// MemoryKit.cpp
#include "MemoryKit.h"

#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <optional>
#include <array>

class MemoryKit {
public:
	static std::optional<uintptr_t> FindPattern(uintptr_t baseAddress, size_t scanSize,
												const std::string& pattern) {
		auto [bytes, mask] = ParsePattern(pattern);
		if (bytes.empty() || scanSize < bytes.size())
			return std::nullopt;

		const auto* mem = reinterpret_cast<const uint8_t*>(baseAddress);
		const size_t patLen = bytes.size();

		struct Segment {
			const uint8_t* data;
			size_t length;
			size_t offset;
		};
		Segment firstSeg{nullptr, 0, 0};
		for (size_t i = 0; i < patLen; ) {
			while (i < patLen && !mask[i]) ++i;
			if (i >= patLen) break;
			size_t start = i;
			while (i < patLen && mask[i]) ++i;
			firstSeg = {bytes.data() + start, i - start, start};
			break;
		}

		if (firstSeg.length == 0)
			return baseAddress;

		constexpr size_t ALPHABET_SIZE = 256;
		std::array<size_t, ALPHABET_SIZE> shift;
		shift.fill(firstSeg.length);
		for (size_t j = 0; j + 1 < firstSeg.length; ++j) {
			shift[firstSeg.data[j]] = firstSeg.length - 1 - j;
		}

		const size_t scanEnd = scanSize - patLen;
		size_t pos = 0;
		while (pos <= scanEnd) {
			const size_t segStart = pos + firstSeg.offset;
			const size_t segEnd = segStart + firstSeg.length;

			bool segMatch = true;
			for (size_t j = 0; j < firstSeg.length; ++j) {
				if (mem[segStart + j] != firstSeg.data[j]) {
					segMatch = false;
					break;
				}
			}

			if (segMatch) {
				bool fullMatch = true;
				for (size_t k = 0; k < patLen; ++k) {
					if (mask[k] && mem[pos + k] != bytes[k]) {
						fullMatch = false;
						break;
					}
				}
				if (fullMatch)
					return baseAddress + pos;
			}

			uint8_t c = mem[segStart + firstSeg.length - 1];
			pos += shift[c];
		}

		return std::nullopt;
	}

    static bool Patch(uintptr_t address, const std::string& patch) {
        auto [bytes, mask] = ParsePattern(patch);
        if (bytes.empty()) return false;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<LPVOID>(address),
                            bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            char dbg[64];
            sprintf_s(dbg, "[MK] VirtualProtect FAILED: %08X\n", GetLastError());
            OutputDebugStringA(dbg);
            return false;
        }

        auto* mem = reinterpret_cast<uint8_t*>(address);

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (mask[i])
                mem[i] = bytes[i];
        }

        VirtualProtect(reinterpret_cast<LPVOID>(address),
                       bytes.size(), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(),
                              reinterpret_cast<LPCVOID>(address), bytes.size());
        return true;
    }

    static bool FindAndPatch(uintptr_t baseAddress, size_t scanSize,
                             const std::string& pattern, const std::string& patch)
    {
        auto addr = FindPattern(baseAddress, scanSize, pattern);
        if (!addr) return false;
        return Patch(*addr, patch);
    }

private:
    static std::pair<std::vector<uint8_t>, std::vector<bool>>
    ParsePattern(const std::string& pattern)
    {
        std::vector<uint8_t> bytes;
        std::vector<bool>    mask;
        std::istringstream   ss(pattern);
        std::string          token;

        while (ss >> token) {
            if (token == "??") {
                bytes.push_back(0x00);
                mask.push_back(false);
            } else {
                bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
                mask.push_back(true);
            }
        }

        return { bytes, mask };
    }
};

extern "C" {

uintptr_t MemoryKit_FindPattern(uintptr_t baseAddress, size_t scanSize, const char* pattern) {
    if (!pattern || baseAddress == 0 || scanSize == 0) return 0;
    auto result = MemoryKit::FindPattern(baseAddress, scanSize, pattern);
    return result.value_or(0);
}

int MemoryKit_Patch(uintptr_t address, const char* patch) {
    if (!patch || address == 0) return 0;
    return MemoryKit::Patch(address, patch) ? 1 : 0;
}

int MemoryKit_FindAndPatch(uintptr_t baseAddress, size_t scanSize,
                           const char* pattern, const char* patch)
{
    if (!pattern || !patch || baseAddress == 0 || scanSize == 0) return 0;
    return MemoryKit::FindAndPatch(baseAddress, scanSize, pattern, patch) ? 1 : 0;
}

} // extern "C"