DartPP = DartPP or {}
local T = DartPP
local function bandCompat(v, mask)
    v = tonumber(v) or 0
    mask = tonumber(mask) or 0
    if type(bAnd) == "function" then
        local ok, r = pcall(bAnd, v, mask)
        if ok and r ~= nil then return r end
    end
    local out, bit = 0, 1
    while v > 0 or mask > 0 do
        if v % 2 == 1 and mask % 2 == 1 then out = out + bit end
        v = math.floor(v / 2)
        mask = math.floor(mask / 2)
        bit = bit * 2
    end
    return out
end
local function safeReadQ(addr)
    local ok, v = pcall(readQword, addr)
    if ok and v ~= nil then return v end
    return nil
end
local function fieldHasR15(v)
    if type(v) ~= "string" then return false end
    return string.lower(v):gsub("%s+", ""):find("[r15", 1, true) ~= nil
end
local function extractOpcodeFromDisasmString(ds)
    local text = tostring(ds)
    local p1 = text:find(" - ", 1, true)
    if not p1 then return nil end
    local p2 = text:find(" - ", p1 + 3, true)
    if not p2 then return nil end
    local tail = text:sub(p2 + 3)
    local colon = tail:find(" : ", 1, true)
    if colon then tail = tail:sub(1, colon - 1) end
    return tail
end
local function countInstructionBytes(s)
    local n = 0
    for _ in tostring(s):gmatch("%x%x") do n = n + 1 end
    if n < 1 or n > 15 then return nil end
    return n
end
local function getDisasmInfo(addr)
    local ok, ds = pcall(disassemble, addr)
    if not ok or ds == nil then return nil, nil end
    local opcode, size = nil, nil
    local ok2, f1, f2, f3, f4 = pcall(splitDisassembledString, ds)
    if ok2 then
        local fields = { f1, f2, f3, f4 }
        for i = 1, 4 do
            if fieldHasR15(fields[i]) then opcode = fields[i]; break end
        end
        for i = 1, 4 do
            local v = fields[i]
            if type(v) == "string" then
                local trimmed = v:gsub("^%s+", ""):gsub("%s+$", "")
                if trimmed:match("^[%x%s]+$")
                    and (trimmed:find(" ", 1, true) or trimmed:match("^%x%x$")) then
                    local n = countInstructionBytes(trimmed)
                    if n then size = n; break end
                end
            end
        end
    end
    if opcode == nil then
        local fb = extractOpcodeFromDisasmString(ds)
        if fieldHasR15(fb) then opcode = fb end
    end
    if size == nil then
        local okS, s2 = pcall(getInstructionSize, addr)
        if okS and s2 and s2 >= 1 and s2 <= 15 then size = s2 end
    end
    return opcode, size
end
local function isDirectR15Ref(opcode)
    if opcode == nil then return false end
    local s = string.lower(opcode):gsub("%s+", "")
    if s:match("^lea") then return false end
    local expr = s:match("%[r15([^%]]*)%]")
    if expr == nil then return false end
    if expr == "" then return true end
    if expr:match("^[+-][0-9a-f]+$") then return true end
    return false
end
local function isExecutable(r)
    if r == nil then return false end
    local state   = tonumber(r.State)      or 0
    local protect = tonumber(r.Protect)    or 0
    local size    = tonumber(r.RegionSize) or 0
    if state ~= 0x1000 then return false end
    if size <= 0 then return false end
    if bandCompat(protect, 0x01) ~= 0 then return false end
    if bandCompat(protect, 0x100) ~= 0 then return false end
    if bandCompat(protect, 0xF0) == 0 then return false end
    return true
end
local function buildModuleBaseSet()
    local set = {}
    if type(enumModules) ~= "function" then return set end
    local ok, list = pcall(enumModules)
    if not ok or type(list) ~= "table" then return set end
    for _, m in ipairs(list) do
        if m and m.Address then set[m.Address] = true end
    end
    return set
end
local function belongsToModule(r, moduleBaseSet)
    local allocBase = r.AllocationBase or r.BaseAddress
    return moduleBaseSet[allocBase] == true
end
local PROBE_BUDGET  = 0x00400000
local PROBE_WINDOWS = 8
local YIELD_BYTES   = 0x00020000
local function buildProbeWindows(first, regionSize)
    local out = {}
    local budget = math.min(regionSize, PROBE_BUDGET)
    if regionSize <= budget or PROBE_WINDOWS <= 1 then
        table.insert(out, { first = first, last = first + budget })
        return out
    end
    local winSize = math.max(0x4000, math.floor(budget / PROBE_WINDOWS))
    local maxOff  = math.max(0, regionSize - winSize)
    local seen = {}
    for i = 0, PROBE_WINDOWS - 1 do
        local ratio = (PROBE_WINDOWS > 1) and (i / (PROBE_WINDOWS - 1)) or 0
        local off = math.floor(math.floor(maxOff * ratio / 0x1000) * 0x1000)
        local wf = first + off
        local wl = math.min(first + regionSize, wf + winSize)
        if not seen[wf] and wl > wf then
            seen[wf] = true
            table.insert(out, { first = wf, last = wl })
        end
    end
    return out
end
local function scanRegionForR15Refs(r, cap)
    cap = cap or 512
    local first = r.BaseAddress
    local regionSize = tonumber(r.RegionSize) or 0
    local windows = buildProbeWindows(first, regionSize)
    local refs = {}
    for _, w in ipairs(windows) do
        local p = w.first
        local nextYield = p + YIELD_BYTES
        while p < w.last do
            local opcode, size = getDisasmInfo(p)
            if size == nil or size < 1 or size > 15 then
                p = p + 1
            else
                if opcode and isDirectR15Ref(opcode) then
                    table.insert(refs, { addr = p, opcode = opcode })
                    if #refs >= cap then break end
                end
                p = p + size
            end
            if p >= nextYield then
                processMessages()
                nextYield = nextYield + YIELD_BYTES
            end
        end
        if #refs >= cap then break end
        processMessages()
    end
    return refs
end
T._state = {
    active    = false,
    ownedBP   = {},
    callbacks = {},
    votes     = {},
}
local function removeAllBP()
    local n = 0
    for addr in pairs(T._state.ownedBP) do
        pcall(debug_removeBreakpoint, addr)
        n = n + 1
    end
    T._state.ownedBP   = {}
    T._state.callbacks = {}
    return n
end
local function plausiblePP(v)
    return v ~= nil and v ~= 0 and v >= 0x10000
end
local function chooseEvenly(refs, count)
    local n = #refs
    if n <= count then
        local out = {}
        for i = 1, n do out[i] = refs[i] end
        return out
    end
    local out, used = {}, {}
    for i = 1, count do
        local idx = math.floor((i - 0.5) * n / count) + 1
        idx = math.max(1, math.min(n, idx))
        while used[idx] and idx < n do idx = idx + 1 end
        if not used[idx] then
            used[idx] = true
            table.insert(out, refs[idx])
        end
    end
    return out
end
local outputPath = [[C:\Users\Public\dart_objectpool_plus.txt]]
local refsPath   = [[C:\Users\Public\dart_objectpool_refs.txt]]
local entrySize  = 8
local unknownSizeScanLimit = 0x100

local POOL_TYPE = {
    IMMEDIATE       = 0,
    TAGGED_OBJECT   = 1,
    NATIVE_FUNCTION = 2,
    IMMEDIATE128    = 3,
}
local POOL_TYPE_NAME = {
    [0] = "Immediate",
    [1] = "TaggedObject",
    [2] = "NativeFunction",
    [3] = "Immediate128",
}
local SNAPSHOT_BEHAVIOR_NAME = {
    [0] = "Snapshotable",
    [1] = "NotSnapshotable",
    [2] = "ResetToBootstrapNative",
    [3] = "ResetToSwitchableCallMissEP",
    [4] = "SetToZero",
}

local WRITE_REFERENCE_GRAPH = true
local SCAN_OBJECT_FIELDS = false
local function safeReadQword(addr)
    local ok, v = pcall(readQword, addr)
    if not ok then return nil end
    return v
end
local function safeReadDword(addr)
    local ok, v = pcall(readInteger, addr)
    if not ok then return nil end
    return v
end
local function safeReadByte(addr)
    local ok, bytes = pcall(readBytes, addr, 1, true)
    if not ok or type(bytes) ~= "table" or bytes[1] == nil then return nil end
    return bytes[1] & 0xFF
end
local function parseHeader(rawAddr)
    local tag = safeReadDword(rawAddr)
    if tag == nil then return nil end
    local cid     = (tag >> 12) & 0xFFFFF
    local sizeTag = (tag >> 8) & 0xF
    local objSize = (sizeTag ~= 0) and (sizeTag * 0x10) or nil
    return { tag = tag, cid = cid, sizeTag = sizeTag, size = objSize }
end

local FORCE_ONE_BYTE_STRING_CID = nil
local dartStringCids = {
    one = FORCE_ONE_BYTE_STRING_CID,
    two = FORCE_ONE_BYTE_STRING_CID and (FORCE_ONE_BYTE_STRING_CID + 1) or nil
}

local function readTaggedStringLength(rawAddr)
    local q = safeReadQword(rawAddr + 8)
    if q ~= nil and (q & 1) == 0 then
        local n = q >> 1
        if n >= 0 and n <= 0x10000 then return n end
    end

    local d = safeReadDword(rawAddr + 8)
    if d ~= nil then
        d = d & 0xFFFFFFFF
        if (d & 1) == 0 then
            local n = d >> 1
            if n >= 0 and n <= 0x10000 then return n end
        end
    end
    return nil
end

local function tryLearnOneByteStringCid(rawAddr)
    if dartStringCids.one ~= nil then return true end
    local h = parseHeader(rawAddr)
    if h == nil then return false end

    local low  = h.tag & 0xFF
    local next = (h.tag >> 8) & 0xFF
    if low ~= 0x32 or (next ~= 0xD2 and next ~= 0xD3) then
        return false
    end

    if readTaggedStringLength(rawAddr) == nil then return false end

    dartStringCids.one = h.cid
    dartStringCids.two = h.cid + 1
    return true
end

local function decodePoolEntryBits(bits)
    if bits == nil then
        return nil, "Unknown", nil, nil, "Unknown"
    end

    local typeId       = bits & 0x0F
    local patchBit     = (bits >> 4) & 0x01
    local snapshotId   = (bits >> 5) & 0x07
    local typeName     = POOL_TYPE_NAME[typeId] or string.format("Type%d", typeId)
    local patchable    = patchBit == 0
    local snapshotName = SNAPSHOT_BEHAVIOR_NAME[snapshotId]
                      or string.format("SnapshotBehavior%d", snapshotId)

    return typeId, typeName, patchable, snapshotId, snapshotName
end

local function calibrateStringCids(startAddr, entryBitsAddr, entryCount)
    if dartStringCids.one ~= nil then return true end
    local limit = math.min(entryCount, 0x40000)
    for i = 0, limit - 1 do
        local bits = safeReadByte(entryBitsAddr + i)
        local typeId = bits and (bits & 0x0F) or nil
        if typeId == POOL_TYPE.TAGGED_OBJECT then
            local tagged = safeReadQword(startAddr + i * entrySize)
            if tagged ~= nil and tagged >= 0x10000 and (tagged & 1) ~= 0 then
                if tryLearnOneByteStringCid(tagged - 1) then
                    print(string.format(
                        "[String] OneByte CID=0x%X TwoByte CID=0x%X",
                        dartStringCids.one, dartStringCids.two))
                    return true
                end
            end
        end
        if (i + 1) % 8192 == 0 then processMessages() end
    end
    return false
end

local function utf8Char(cp)
    if cp < 0 then cp = 0xFFFD end
    if cp <= 0x7F then
        return string.char(cp)
    elseif cp <= 0x7FF then
        return string.char(
            0xC0 | (cp >> 6),
            0x80 | (cp & 0x3F))
    elseif cp <= 0xFFFF then
        if cp >= 0xD800 and cp <= 0xDFFF then cp = 0xFFFD end
        return string.char(
            0xE0 | (cp >> 12),
            0x80 | ((cp >> 6) & 0x3F),
            0x80 | (cp & 0x3F))
    elseif cp <= 0x10FFFF then
        return string.char(
            0xF0 | (cp >> 18),
            0x80 | ((cp >> 12) & 0x3F),
            0x80 | ((cp >> 6) & 0x3F),
            0x80 | (cp & 0x3F))
    end
    return utf8Char(0xFFFD)
end

local function readExactBytes(addr, count)
    if count == 0 then return {} end
    local ok, bytes = pcall(readBytes, addr, count, true)
    if not ok or type(bytes) ~= "table" or #bytes < count then return nil end
    return bytes
end

local function latin1BytesToUtf8(bytes, len)
    local out = {}
    for i = 1, len do
        out[#out + 1] = utf8Char(bytes[i] or 0)
    end
    return table.concat(out)
end

local function utf16leBytesToUtf8(bytes, codeUnits)
    local out = {}
    local i = 0
    while i < codeUnits do
        local p = i * 2 + 1
        local u = (bytes[p] or 0) | ((bytes[p + 1] or 0) << 8)
        i = i + 1

        if u >= 0xD800 and u <= 0xDBFF and i < codeUnits then
            local p2 = i * 2 + 1
            local u2 = (bytes[p2] or 0) | ((bytes[p2 + 1] or 0) << 8)
            if u2 >= 0xDC00 and u2 <= 0xDFFF then
                local cp = 0x10000 + ((u - 0xD800) << 10) + (u2 - 0xDC00)
                out[#out + 1] = utf8Char(cp)
                i = i + 1
            else
                out[#out + 1] = utf8Char(0xFFFD)
            end
        elseif u >= 0xDC00 and u <= 0xDFFF then
            out[#out + 1] = utf8Char(0xFFFD)
        else
            out[#out + 1] = utf8Char(u)
        end
    end
    return table.concat(out)
end

local function readDartString(rawAddr)
    local h = parseHeader(rawAddr)
    if h == nil then return nil end

    if dartStringCids.one == nil then
        tryLearnOneByteStringCid(rawAddr)
    end
    if dartStringCids.one == nil then return nil end

    local kind
    if h.cid == dartStringCids.one then
        kind = "OneByte"
    elseif h.cid == dartStringCids.two then
        kind = "TwoByte"
    else
        return nil
    end

    local len = readTaggedStringLength(rawAddr)
    if len == nil or len > 4096 then return nil end
    if len == 0 then return "", 0, kind end

    local byteCount = (kind == "TwoByte") and (len * 2) or len
    local bytes = readExactBytes(rawAddr + 16, byteCount)
    if bytes == nil then return nil end

    local str
    if kind == "TwoByte" then
        str = utf16leBytesToUtf8(bytes, len)
    else
        str = latin1BytesToUtf8(bytes, len)
    end
    return str, len, kind
end
local function describeValue(v)
    if v == nil then return "" end
    if (v & 1) == 0 then
        return string.format(
            "Smi(tagged=0x%016X value=0x%X)", v, v >> 1)
    end
    local raw = v - 1
    local h = parseHeader(raw)
    if h == nil then
        return string.format(
            "Ptr(tagged=0x%016X raw=0x%016X unreadable)", v, raw)
    end
    local str, len, kind = readDartString(raw)
    if str ~= nil then
        local display = str
            :gsub("\\", "\\\\")
            :gsub('"', '\\"')
            :gsub("[%c]", function(c)
                return string.format("\\x%02X", string.byte(c))
            end)
        return string.format(
            'String[%s](tagged=0x%016X raw=0x%016X CID=0x%X len=%d "%s")',
            kind or "?", v, raw, h.cid, len, display)
    end
    local sizeText = h.size and string.format("0x%X", h.size) or "unknown"
    return string.format(
        "Object(tagged=0x%016X raw=0x%016X tag=0x%08X CID=0x%X size=%s)",
        v, raw, h.tag, h.cid, sizeText)
end
local function isPlausibleTaggedObject(v)
    if v == nil or v < 0x10000 or (v & 1) == 0 then
        return false, nil, nil
    end
    local raw = v - 1
    local h = parseHeader(raw)
    if h == nil then
        return false, raw, nil
    end
    return true, raw, h
end

local function describePoolEntry(rawValue, typeId)
    if rawValue == nil then return "<unreadable>" end
    if typeId == POOL_TYPE.TAGGED_OBJECT then
        return describeValue(rawValue)
    elseif typeId == POOL_TYPE.IMMEDIATE then
        return string.format("Immediate(raw=0x%016X)", rawValue)
    elseif typeId == POOL_TYPE.NATIVE_FUNCTION then
        return string.format("NativeFunction(addr=0x%016X)", rawValue)
    elseif typeId == POOL_TYPE.IMMEDIATE128 then
        return string.format("Immediate128Word(raw=0x%016X)", rawValue)
    end
    return string.format("Raw(type=%d value=0x%016X)", typeId or -1, rawValue)
end

local function isStringHeader(h)
    return h ~= nil and dartStringCids.one ~= nil and
        (h.cid == dartStringCids.one or h.cid == dartStringCids.two)
end

local function dumpObjectPool(pp)
    local base        = pp - 1
    local entryCount  = safeReadQ(base + 0x08) or 0
    local startAddr   = base + 0x10
    local entryBitsAddr = startAddr + entryCount * entrySize
    local entryBitsEnd  = entryBitsAddr + entryCount

    print(string.format("[DumpPP] PP         = %016X", pp))
    print(string.format("[DumpPP] base       = %016X", base))
    print(string.format("[DumpPP] length     = %d (0x%X)", entryCount, entryCount))
    print(string.format("[DumpPP] entry[0]   = %016X", startAddr))
    print(string.format("[DumpPP] entry_bits = %016X", entryBitsAddr))
    print(string.format("[DumpPP] bits end   = %016X", entryBitsEnd))

    if entryCount <= 0 or entryCount > 0x200000 then
        print("[DumpPP] ObjectPool length 不合理，中止 dump")
        return
    end

    if safeReadQword(startAddr) == nil or
       safeReadQword(startAddr + (entryCount - 1) * entrySize) == nil or
       safeReadByte(entryBitsAddr) == nil or
       safeReadByte(entryBitsAddr + entryCount - 1) == nil then
        print("[DumpPP] ObjectPool data/entry_bits 不可读，中止 dump")
        return
    end

    if not calibrateStringCids(startAddr, entryBitsAddr, entryCount) then
        print("[String] 未自动识别 OneByteString CID；字符串将保守按普通 Object 输出")
    end

    local ppBase = base + 1
    local file = io.open(outputPath, "w")
    if not file then
        print("无法打开: " .. outputPath)
        return
    end

    local refs = nil
    if WRITE_REFERENCE_GRAPH then
        refs = io.open(refsPath, "w")
        if not refs then
            file:close()
            print("无法打开: " .. refsPath)
            return
        end
    end

    file:write("Flutter ObjectPool Enhanced Dump (correct entry_bits decoding)\n")
    file:write(string.format(
        "Start      : 0x%016X\nPP/R15     : 0x%016X\nCount      : %d\nEntryBits  : 0x%016X\nBitsEndExcl: 0x%016X\n\n",
        startAddr, ppBase, entryCount, entryBitsAddr, entryBitsEnd))
    file:write(string.format(
        "%-7s %-10s %-12s %-18s %-6s %-16s %-13s %-31s %s\n",
        "Index", "DumpOff", "PP Disp", "Pool Address", "Bits", "Type",
        "Patchability", "SnapshotBehavior", "Value"))
    file:write(string.rep("-", 220) .. "\n")

    if refs then
        refs:write("Flutter ObjectPool Reference Graph (correct entry_bits decoding)\n")
        refs:write(string.format(
            "PP/R15    : 0x%016X\nStart     : 0x%016X\nCount     : %d\nEntryBits : 0x%016X\n\n",
            ppBase, startAddr, entryCount, entryBitsAddr))
        refs:write("entry_bits decode: type=bits&0x0F, patch=(bits>>4)&1, snapshot=(bits>>5)&7.\n[DIRECT] is emitted only for entries whose official EntryType is TaggedObject.\n")
        if SCAN_OBJECT_FIELDS then
            refs:write("[FIELD] scanning is ENABLED; it is heuristic and may contain false references.\n\n")
        else
            refs:write("[FIELD] scanning is DISABLED by default to avoid the old ~30 MB noisy graph.\n\n")
        end
    end

    local scannedObjects     = {}
    local taggedEntryCount   = 0
    local directHeapObjects  = 0
    local directSmiCount     = 0
    local fieldRefCount      = 0
    local scannedParentCount = 0
    local unreadableBits     = 0
    local typeCounts         = {}
    local snapshotCounts     = {}
    local patchableCount     = 0
    local notPatchableCount  = 0

    for i = 0, entryCount - 1 do
        local dumpOffset = i * entrySize
        local poolAddr   = startAddr + dumpOffset
        local ppDisp     = poolAddr - ppBase
        local rawValue   = safeReadQword(poolAddr)
        local bits       = safeReadByte(entryBitsAddr + i)
        local typeId, typeName, patchable, snapshotId, snapshotName =
            decodePoolEntryBits(bits)

        if bits == nil then
            unreadableBits = unreadableBits + 1
        else
            typeCounts[typeId] = (typeCounts[typeId] or 0) + 1
            snapshotCounts[snapshotId] = (snapshotCounts[snapshotId] or 0) + 1
            if patchable then
                patchableCount = patchableCount + 1
            else
                notPatchableCount = notPatchableCount + 1
            end
        end

        local bitsText  = bits and string.format("0x%02X", bits) or "<nil>"
        local patchText = (patchable == nil) and "Unknown"
                       or (patchable and "Patchable" or "NotPatchable")
        local valueText = (typeId ~= nil)
                       and describePoolEntry(rawValue, typeId)
                       or (rawValue and string.format("Raw(0x%016X)", rawValue) or "<unreadable>")

        file:write(string.format(
            "[%05d] +0x%06X [r15+0x%X] 0x%016X %-6s %-16s %-13s %-31s %s\n",
            i, dumpOffset, ppDisp, poolAddr,
            bitsText, typeName, patchText, snapshotName, valueText))

        if typeId == POOL_TYPE.TAGGED_OBJECT and rawValue ~= nil then
            taggedEntryCount = taggedEntryCount + 1

            if (rawValue & 1) == 0 then
                directSmiCount = directSmiCount + 1
                if refs then
                    refs:write(string.format(
                        "[DIRECT] Pool[%d] dump=+0x%X PP=[r15+0x%X] " ..
                        "pool=0x%016X bits=0x%02X -> %s\n",
                        i, dumpOffset, ppDisp, poolAddr, bits, describeValue(rawValue)))
                end
            else
                local isObject, raw, h = isPlausibleTaggedObject(rawValue)
                if isObject then
                    directHeapObjects = directHeapObjects + 1
                    if refs then
                        refs:write(string.format(
                            "[DIRECT] Pool[%d] dump=+0x%X PP=[r15+0x%X] " ..
                            "pool=0x%016X bits=0x%02X -> tagged=0x%016X raw=0x%016X " ..
                            "CID=0x%X %s\n",
                            i, dumpOffset, ppDisp, poolAddr, bits,
                            rawValue, raw, h.cid, describeValue(rawValue)))
                    end

                    if SCAN_OBJECT_FIELDS and not isStringHeader(h) then
                        local key = string.format("%016X", raw)
                        if not scannedObjects[key] then
                            scannedObjects[key] = true
                            scannedParentCount = scannedParentCount + 1
                            local scanSize = h.size or unknownSizeScanLimit
                            if scanSize >= 0x10 then
                                for fieldOff = 0x08, scanSize - 8, 8 do
                                    local fieldAddr = raw + fieldOff
                                    local childTagged = safeReadQword(fieldAddr)
                                    local childIsObject, childRaw, childHeader =
                                        isPlausibleTaggedObject(childTagged)
                                    if childIsObject then
                                        fieldRefCount = fieldRefCount + 1
                                        if refs then
                                            refs:write(string.format(
                                                "[FIELD] Pool[%d] PP=[r15+0x%X] " ..
                                                "parentTagged=0x%016X parentRaw=0x%016X " ..
                                                "parentCID=0x%X fieldRawOff=+0x%X " ..
                                                "fieldAddr=0x%016X -> childTagged=0x%016X " ..
                                                "childRaw=0x%016X childCID=0x%X %s\n",
                                                i, ppDisp,
                                                rawValue, raw, h.cid,
                                                fieldOff, fieldAddr,
                                                childTagged, childRaw, childHeader.cid,
                                                describeValue(childTagged)))
                                        end
                                    end
                                end
                            end
                        end
                    end
                elseif refs then
                    refs:write(string.format(
                        "[DIRECT] Pool[%d] dump=+0x%X PP=[r15+0x%X] " ..
                        "pool=0x%016X bits=0x%02X -> %s\n",
                        i, dumpOffset, ppDisp, poolAddr, bits,
                        describeValue(rawValue)))
                end
            end
        end

        if (i + 1) % 5000 == 0 then
            print(string.format(
                "进度 %d / %d | Tagged=%d heap=%d smi=%d fieldRefs=%d",
                i + 1, entryCount,
                taggedEntryCount, directHeapObjects, directSmiCount, fieldRefCount))
            processMessages()
        end
    end

    file:write("\nEntry type summary:\n")
    local knownTypes = {0, 1, 2, 3}
    for _, id in ipairs(knownTypes) do
        file:write(string.format("  %-22s : %d\n",
            POOL_TYPE_NAME[id], typeCounts[id] or 0))
    end
    local otherCount = 0
    for id, count in pairs(typeCounts) do
        if POOL_TYPE_NAME[id] == nil then otherCount = otherCount + count end
    end
    file:write(string.format("  %-22s : %d\n", "Other/UnknownType", otherCount))
    file:write(string.format("  %-22s : %d\n", "UnreadableBits", unreadableBits))

    file:write("\nPatchability summary:\n")
    file:write(string.format("  %-22s : %d\n", "Patchable", patchableCount))
    file:write(string.format("  %-22s : %d\n", "NotPatchable", notPatchableCount))

    file:write("\nSnapshot behavior summary:\n")
    for id = 0, 4 do
        file:write(string.format("  %-31s : %d\n",
            SNAPSHOT_BEHAVIOR_NAME[id], snapshotCounts[id] or 0))
    end
    local otherSnapshotCount = 0
    for id, count in pairs(snapshotCounts) do
        if SNAPSHOT_BEHAVIOR_NAME[id] == nil then
            otherSnapshotCount = otherSnapshotCount + count
        end
    end
    file:write(string.format("  %-31s : %d\n", "Other/UnknownSnapshotBehavior", otherSnapshotCount))
    file:write(string.format(
        "\nReference summary: taggedEntries=%d heapObjects=%d smi=%d scannedParents=%d fieldRefs=%d\n",
        taggedEntryCount, directHeapObjects, directSmiCount,
        scannedParentCount, fieldRefCount))

    if refs then
        refs:write("\n")
        refs:write(string.format(
            "完成: taggedEntries=%d heapObjects=%d smi=%d scannedParents=%d fieldRefs=%d\n",
            taggedEntryCount, directHeapObjects, directSmiCount,
            scannedParentCount, fieldRefCount))
        refs:close()
    end
    file:close()

    print("")
    print("[DumpPP] 完成")
    print("ObjectPool : " .. outputPath)
    if refs then print("References : " .. refsPath) end
    print(string.format(
        "Pool       : count=%d Tagged=%d heap=%d smi=%d",
        entryCount, taggedEntryCount, directHeapObjects, directSmiCount))
    print(string.format(
        "EntryBits  : 0x%016X .. 0x%016X", entryBitsAddr, entryBitsEnd - 1))
    if SCAN_OBJECT_FIELDS then
        print(string.format("Refs       : parents=%d fieldRefs=%d",
            scannedParentCount, fieldRefCount))
    else
        print("Refs       : DIRECT only (FIELD scan disabled)")
    end
end

function T._onHit(addr)
    local S = T._state
    if not S.active then
        pcall(debug_continueFromBreakpoint, co_run)
        return 1
    end
    pcall(debug_getContext, false)
    local pp = R15
    if not plausiblePP(pp) then
        pcall(debug_continueFromBreakpoint, co_run)
        return 1
    end
    local vote = S.votes[pp]
    if vote == nil then
        vote = { unique = 0, seen = {} }
        S.votes[pp] = vote
    end
    if not vote.seen[addr] then
        vote.seen[addr] = true
        vote.unique = vote.unique + 1
    end
    if vote.unique >= 2 then
        S.active = false
        removeAllBP()
        dumpObjectPool(pp)
    end
    pcall(debug_continueFromBreakpoint, co_run)
    return 1
end
local AUTO_RESUME_WHEN_BROKEN = true

function T.run()
    if not debug_isDebugging() then
        pcall(debugProcess, 2)
        processMessages()
    end
    T._state.active = false
    removeAllBP()
    T._state.votes = {}
    local moduleBaseSet = buildModuleBaseSet()
    local regions = enumMemoryRegions() or {}
    local candidates = {}
    for _, r in ipairs(regions) do
        if isExecutable(r)
            and not belongsToModule(r, moduleBaseSet)
            and (tonumber(r.RegionSize) or 0) <= 0x20000000
        then
            local typeValue = tonumber(r.Type) or 0
            local tier = (typeValue == 0x20000) and 1
                      or (typeValue == 0x40000) and 2
                      or 3
            table.insert(candidates,
                { r = r, tier = tier, size = tonumber(r.RegionSize) or 0 })
        end
    end
    table.sort(candidates, function(a, b)
        if a.tier ~= b.tier then return a.tier < b.tier end
        return a.size < b.size
    end)
    local best    = nil
    local scanned = 0
    for i, c in ipairs(candidates) do
        if i > 64 then break end
        if scanned > 0x08000000 then break end
        local refs = scanRegionForR15Refs(c.r, 4096)
        scanned = scanned + math.min(c.size, PROBE_BUDGET)
        if #refs >= 4 then
            if best == nil or #refs > best.refCount
                or (best.tier > c.tier and #refs >= 4) then
                best = { r = c.r, refs = refs,
                         tier = c.tier, refCount = #refs }
            end
        end
        if best ~= nil and best.refCount >= 64 and best.tier <= 2 then break end
        processMessages()
    end
    if best == nil then
        print("[!] 未找到匿名 RX Region")
        return
    end
    local selected = chooseEvenly(best.refs, 512)
    local existing = {}
    local okL, old = pcall(debug_getBreakpointList)
    if okL and type(old) == "table" then
        for _, a in ipairs(old) do existing[a] = true end
    end
    for i, ref in ipairs(selected) do
        local bpAddr = ref.addr
        if not existing[bpAddr] then
            local cb = function()
                local ok2, res = pcall(T._onHit, bpAddr)
                if ok2 then return res end
                pcall(debug_continueFromBreakpoint, co_run)
                return 1
            end
            T._state.callbacks[bpAddr] = cb
            local okBP, result = pcall(
                debug_setBreakpoint, bpAddr, 1, bptExecute, bpmInt3, cb)
            if okBP and result ~= false then
                T._state.ownedBP[bpAddr] = true
            else
                T._state.callbacks[bpAddr] = nil
            end
        end
        if i % 64 == 0 then processMessages() end
    end
    T._state.active = true
    processMessages()
    if debug_isBroken() then
        if AUTO_RESUME_WHEN_BROKEN then
            local okResume = pcall(debug_continueFromBreakpoint, co_run)
            if okResume then
                print("[+] Debugger 已自动 Resume，等待命中 R15/ObjectPool 断点")
            else
                print("[!] 自动 Resume 失败，请手动 Resume")
            end
        else
            print("[!] Debugger 当前暂停，请 Resume")
        end
    end
end
function T.cancel()
    T._state.active = false
    removeAllBP()
    T._state.votes = {}
end