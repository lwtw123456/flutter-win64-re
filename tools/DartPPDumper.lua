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
local targetTagged = 0x000001AB2436D891
local unknownSizeScanLimit = 0x100
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
local function parseHeader(rawAddr)
    local tag = safeReadDword(rawAddr)
    if tag == nil then return nil end
    local cid     = (tag >> 12) & 0xFFFFF
    local sizeTag = (tag >> 8) & 0xF
    local objSize = (sizeTag ~= 0) and (sizeTag * 0x10) or nil
    return { tag = tag, cid = cid, sizeTag = sizeTag, size = objSize }
end
local function readDartString(rawAddr)
    local tag = safeReadDword(rawAddr)
    if tag == nil then return nil end
    local low  = tag & 0xFF
    local next = (tag >> 8) & 0xFF
    if low ~= 0x32 or (next ~= 0xD2 and next ~= 0xD3) then return nil end
    local lenTagged = safeReadQword(rawAddr + 8)
    if lenTagged == nil or (lenTagged & 1) ~= 0 then return nil end
    local len = lenTagged >> 1
    if len < 0 or len > 4096 then return nil end
    if len == 0 then return "", 0 end
    local ok, str = pcall(readString, rawAddr + 16, len, false)
    if not ok or str == nil then return nil end
    return str, len
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
    local str, len = readDartString(raw)
    if str ~= nil then
        local display = str:gsub("[%c]", function(c)
            return string.format("\\x%02X", string.byte(c))
        end)
		return string.format(
			'String(tagged=0x%016X raw=0x%016X CID=0x%X len=%d "%s")',
			v, raw, h.cid, len, display)
    end
    local sizeText = h.size and string.format("0x%X", h.size) or "unknown"
    return string.format(
        "Object(tagged=0x%016X raw=0x%016X tag=0x%08X CID=0x%X size=%s)",
        v, raw, h.tag, h.cid, sizeText)
end
local function dumpObjectPool(pp)
    local base       = pp - 1
    local lenSMI     = safeReadQ(base + 0x08)
    local entryCount = lenSMI and math.floor(lenSMI / 2) or 0
    local startAddr  = base + 0x10
    print(string.format("[DumpPP] PP       = %016X", pp))
    print(string.format("[DumpPP] base     = %016X", base))
    print(string.format("[DumpPP] lenSMI   = %s",
        lenSMI and string.format("%016X", lenSMI) or "nil"))
    print(string.format("[DumpPP] count    = %d", entryCount))
    print(string.format("[DumpPP] entry[0] = %016X", startAddr))
    if entryCount <= 0 or entryCount > 0x100000 then
        print("[DumpPP] entryCount 不合理，中止 dump")
        return
    end
    local ppBase = base + 1   -- == pp
    local file = io.open(outputPath, "w")
    if not file then
        print("无法打开: " .. outputPath)
        return
    end
    local refs = io.open(refsPath, "w")
    if not refs then
        file:close()
        print("无法打开: " .. refsPath)
        return
    end
    file:write("Flutter ObjectPool Enhanced Dump\n")
    file:write(string.format(
        "Start  : 0x%016X\nPP/R15 : 0x%016X\nCount  : %d\n\n",
        startAddr, ppBase, entryCount))
    file:write(string.format(
        "%-7s %-10s %-12s %-18s %s\n",
        "Index", "DumpOff", "PP Disp", "Pool Address", "Value"))
    file:write(string.rep("-", 150) .. "\n")
    refs:write("Flutter ObjectPool Target Reference Scan\n")
    refs:write(string.format(
        "Target tagged: 0x%016X\nTarget raw   : 0x%016X\n\n",
        targetTagged, targetTagged - 1))
    local scannedObjects  = {}
    local directHitCount  = 0
    local nestedHitCount  = 0
    for i = 0, entryCount - 1 do
        local dumpOffset = i * entrySize
        local poolAddr   = startAddr + dumpOffset
        -- [r15 + disp]：r15 == ppBase（tagged），
        -- poolAddr = base + 0x10 + i*8 = (ppBase-1) + 0x10 + i*8
        -- disp = poolAddr - ppBase = 0x0F + i*8
        local ppDisp = poolAddr - ppBase
        local tagged = safeReadQword(poolAddr)
        if tagged == nil then
            file:write(string.format(
                "[%05d] +0x%06X [r15+0x%X] 0x%016X \n",
                i, dumpOffset, ppDisp, poolAddr))
        else
            file:write(string.format(
                "[%05d] +0x%06X [r15+0x%X] 0x%016X %s\n",
                i, dumpOffset, ppDisp, poolAddr, describeValue(tagged)))
            if tagged == targetTagged then
                directHitCount = directHitCount + 1
                refs:write(string.format(
                    "[DIRECT] Pool[%d] dump=+0x%X PP=[r15+0x%X] pool=0x%016X\n",
                    i, dumpOffset, ppDisp, poolAddr))
            end
            if (tagged & 1) ~= 0 then
                local raw = tagged - 1
                local key = string.format("%016X", raw)
                if not scannedObjects[key] then
                    scannedObjects[key] = true
                    local h = parseHeader(raw)
                    if h ~= nil then
                        local scanSize = h.size or unknownSizeScanLimit
                        if scanSize >= 0x10 then
                            for fieldOff = 0x08, scanSize - 8, 8 do
                                local fieldAddr = raw + fieldOff
                                local q = safeReadQword(fieldAddr)
                                if q == targetTagged then
                                    nestedHitCount = nestedHitCount + 1
                                    refs:write(string.format(
                                        "[FIELD] Pool[%d] PP=[r15+0x%X] "..
                                        "parentTagged=0x%016X parentRaw=0x%016X "..
                                        "parentCID=0x%X fieldRawOff=+0x%X "..
                                        "fieldAddr=0x%016X -> target\n",
                                        i, ppDisp,
                                        tagged, raw, h.cid,
                                        fieldOff, fieldAddr))
                                end
                            end
                        end
                    end
                end
            end
        end
        if (i + 1) % 5000 == 0 then
            print(string.format(
                "进度 %d / %d | direct=%d nested=%d",
                i + 1, entryCount, directHitCount, nestedHitCount))
            processMessages()
        end
    end
    file:write("\n")
    file:write(string.format(
        "Target refs: direct=%d nested=%d\n",
        directHitCount, nestedHitCount))
    refs:write("\n")
    refs:write(string.format(
        "完成: direct=%d nested=%d\n",
        directHitCount, nestedHitCount))
    file:close()
    refs:close()
    print("")
    print("[DumpPP] 完成")
    print("ObjectPool : " .. outputPath)
    print("References : " .. refsPath)
    print(string.format(
        "D891 refs  : direct=%d nested=%d",
        directHitCount, nestedHitCount))
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
function T.run()
    if not debug_isDebugging() then
        pcall(debugProcess, 2)
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
    if debug_isBroken() then
        print("[!] 请先 Resume")
    end
end
function T.cancel()
    T._state.active = false
    removeAllBP()
    T._state.votes = {}
end