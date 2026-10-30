#include "MemoryKit.h"

#define NOMINMAX
#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <optional>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <algorithm>

namespace {
	struct Piece {
		bool                 fixed = true;
		std::vector<uint8_t> bytes;
		size_t               minLen = 0;
		size_t               maxLen = 0; 
	};

	struct Pattern {
		std::vector<Piece>  pieces;
		std::vector<size_t> minRemain;
		size_t              minLen = 0;
	};

	bool ParsePattern(const std::string& text, Pattern& out)
	{
		out = Pattern{};
		std::istringstream ss(text);
		std::string token;

		std::vector<Piece> raw;
		Piece fixedRun;

		auto flushFixed = [&]() {
			if (!fixedRun.bytes.empty()) {
				raw.push_back(fixedRun);
				fixedRun = Piece{};
			}
		};

		auto pushWild = [&](size_t lo, size_t hi) {
			if (!raw.empty() && !raw.back().fixed) {
				raw.back().minLen += lo;
				raw.back().maxLen += hi;
			} else {
				Piece v;
				v.fixed  = false;
				v.minLen = lo;
				v.maxLen = hi;
				raw.push_back(std::move(v));
			}
		};

		while (ss >> token) {
			if (token.size() >= 3 && token.front() == '[' && token.back() == ']') {
				const std::string body = token.substr(1, token.size() - 2);
				size_t lo = 0, hi = 0;
				try {
					const auto dash = body.find('-');
					if (dash == std::string::npos) {
						lo = hi = std::stoul(body, nullptr, 10);
					} else {
						lo = std::stoul(body.substr(0, dash), nullptr, 10);
						hi = std::stoul(body.substr(dash + 1), nullptr, 10);
					}
				} catch (...) { return false; }
				if (hi < lo || hi > 4096) return false;
				flushFixed();
				pushWild(lo, hi);
				continue;
			}

			if (token == "??" || token == "?") {
				flushFixed();
				pushWild(1, 1);
				continue;
			}

			if (token.size() > 2) return false;
			uint8_t byte = 0;
			try { byte = static_cast<uint8_t>(std::stoul(token, nullptr, 16)); }
			catch (...) { return false; }
			fixedRun.bytes.push_back(byte);
		}
		flushFixed();

		if (raw.empty()) return false;

		out.pieces = std::move(raw);
		out.minRemain.assign(out.pieces.size() + 1, 0);
		for (size_t i = out.pieces.size(); i-- > 0; ) {
			const Piece& pc = out.pieces[i];
			out.minRemain[i] = out.minRemain[i + 1] + (pc.fixed ? pc.bytes.size() : pc.minLen);
		}
		out.minLen = out.minRemain[0];
		return true;
	}

	bool MatchRec(const uint8_t* p, size_t avail, const Pattern& pat,
				  size_t pi, size_t off)
	{
		if (pi == pat.pieces.size()) return true;
		if (off > avail || avail - off < pat.minRemain[pi]) return false;

		const Piece& pc = pat.pieces[pi];
		if (pc.fixed) {
			const size_t n = pc.bytes.size();
			for (size_t i = 0; i < n; ++i) {
				if (p[off + i] != pc.bytes[i]) return false;
			}
			return MatchRec(p, avail, pat, pi + 1, off + n);
		}

		const size_t hi = std::min(pc.maxLen, avail - off);
		for (size_t len = pc.minLen; len <= hi; ++len) {
			if (MatchRec(p, avail, pat, pi + 1, off + len)) return true;
		}
		return false;
	}

} // namespace

class MemoryKit {
public:
	static std::optional<uintptr_t> FindPattern(uintptr_t baseAddress, size_t scanSize,
												const std::string& pattern) {
		Pattern pat;
		if (!ParsePattern(pattern, pat)) return std::nullopt;
		if (scanSize < pat.minLen) return std::nullopt;

		const auto* mem = reinterpret_cast<const uint8_t*>(baseAddress);

		size_t anchorIdx = SIZE_MAX, anchorLen = 0;
		for (size_t i = 0; i < pat.pieces.size(); ++i) {
			const Piece& pc = pat.pieces[i];
			if (pc.fixed && pc.bytes.size() > anchorLen) {
				anchorLen = pc.bytes.size();
				anchorIdx = i;
			}
		}
		if (anchorIdx == SIZE_MAX) return baseAddress;

		size_t preMin = 0, preMax = 0;
		for (size_t i = 0; i < anchorIdx; ++i) {
			const Piece& pc = pat.pieces[i];
			if (pc.fixed) { preMin += pc.bytes.size(); preMax += pc.bytes.size(); }
			else          { preMin += pc.minLen;       preMax += pc.maxLen; }
		}

		const uint8_t* abytes = pat.pieces[anchorIdx].bytes.data();

		std::array<size_t, 256> shift;
		shift.fill(anchorLen);
		for (size_t j = 0; j + 1 < anchorLen; ++j) {
			shift[abytes[j]] = anchorLen - 1 - j;
		}

		const size_t lastStart = scanSize - pat.minLen;
		size_t pos = 0;
		while (pos <= lastStart) {
			const size_t aPos = pos + preMin;
			if (aPos + anchorLen > scanSize) break;

			bool hit = true;
			for (size_t j = 0; j < anchorLen; ++j) {
				if (mem[aPos + j] != abytes[j]) { hit = false; break; }
			}

			if (hit) {
				const size_t hiStart = aPos - preMin;
				const size_t loStart = (aPos >= preMax) ? (aPos - preMax) : 0;
				for (size_t s = loStart; s <= hiStart && s <= lastStart; ++s) {
					if (MatchRec(mem + s, scanSize - s, pat, 0, 0)) {
						return baseAddress + s;
					}
				}
			}

			pos += shift[mem[aPos + anchorLen - 1]];
		}

		return std::nullopt;
	}

	static bool Patch(uintptr_t address, const std::string& patch) {
		Pattern pat;
		if (!ParsePattern(patch, pat) || pat.minLen == 0) return false;

		DWORD oldProtect = 0;
		if (!VirtualProtect(reinterpret_cast<LPVOID>(address), pat.minLen,
							PAGE_EXECUTE_READWRITE, &oldProtect)) {
			char dbg[64];
			sprintf_s(dbg, "[MK] VirtualProtect FAILED: %08X\n", GetLastError());
			OutputDebugStringA(dbg);
			return false;
		}

		auto* mem = reinterpret_cast<uint8_t*>(address);
		size_t off = 0;
		for (const auto& pc : pat.pieces) {
			if (pc.fixed) {
				memcpy(mem + off, pc.bytes.data(), pc.bytes.size());
				off += pc.bytes.size();
			} else {
				off += pc.minLen;
			}
		}

		VirtualProtect(reinterpret_cast<LPVOID>(address), pat.minLen,
					   oldProtect, &oldProtect);
		FlushInstructionCache(GetCurrentProcess(),
							  reinterpret_cast<LPCVOID>(address), pat.minLen);
		return true;
	}

	static bool FindAndPatch(uintptr_t baseAddress, size_t scanSize,
							 const std::string& pattern, const std::string& patch) {
		auto addr = FindPattern(baseAddress, scanSize, pattern);
		if (!addr) return false;
		return Patch(*addr, patch);
	}
};

extern "C" {

uintptr_t MemoryKit_FindPattern(uintptr_t baseAddress, size_t scanSize, const char* pattern) {
	if (!pattern || baseAddress == 0 || scanSize == 0) return 0;
	auto result = MemoryKit::FindPattern(baseAddress, scanSize, pattern);
	return result.value_or(0);
}

uintptr_t MemoryKit_FindAnyPattern(uintptr_t baseAddress, size_t scanSize, const char* patterns) {
	if (!patterns || baseAddress == 0 || scanSize == 0) return 0;
	std::istringstream ss(patterns);
	std::string one;
	while (std::getline(ss, one, '|')) {
		auto r = MemoryKit::FindPattern(baseAddress, scanSize, one);
		if (r) return *r;
	}
	return 0;
}

int MemoryKit_Patch(uintptr_t address, const char* patch) {
	if (!patch || address == 0) return 0;
	return MemoryKit::Patch(address, patch) ? 1 : 0;
}

int MemoryKit_FindAndPatch(uintptr_t baseAddress, size_t scanSize,
						   const char* pattern, const char* patch) {
	if (!pattern || !patch || baseAddress == 0 || scanSize == 0) return 0;
	return MemoryKit::FindAndPatch(baseAddress, scanSize, pattern, patch) ? 1 : 0;
}

} // extern "C"
