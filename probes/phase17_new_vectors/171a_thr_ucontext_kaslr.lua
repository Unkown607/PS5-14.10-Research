-- CRASH_CLASS: LOW (read-only introspection, no blind writes)
-- PROBE 171a: thr_get_ucontext / getcontext KASLR leak hunt
-- Tests whether getcontext(421) or thr_get_ucontext(634) leak kernel addresses
-- in the saved register state (mcontext).
-- Sections:
--   A: getcontext(421) on current thread — zero crash risk
--   B: thr_get_ucontext(634) on a sleeping child thread's TID
--   C: thr_get_ucontext(634) on a child blocked in nanosleep (kernel stack leak?)

print("=== PROBE 171a: THR_GET_UCONTEXT / GETCONTEXT KASLR LEAK HUNT ===")
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

----------------------------------------------------------------
-- scan a buffer for kernel pointers (qword-aligned)
----------------------------------------------------------------
local function scan_for_kptrs(buf, len, label)
    local found = 0
    local changed = 0
    for off = 0, len - 8, 8 do
        local v = rq(buf + off)
        local h, l = get_hi_lo(v)
        if h ~= 0 or l ~= 0 then
            changed = changed + 1
            if is_kptr(h) then
                print(string.format("  *** KPTR_CANDIDATE %s+0x%03X = %s ***",
                    label, off, q(v)))
                found = found + 1
            end
        end
    end
    return found, changed
end

----------------------------------------------------------------
-- dump ucontext/mcontext fields with named registers
-- PS5 14.10 mcontext offsets (differ from FreeBSD by -0x10):
--   +0x018: onstack  +0x048: rdi  +0x050: rsi  +0x058: rdx
--   +0x060: rcx  +0x068: r8   +0x070: r9   +0x078: rax
--   +0x080: rbx  +0x088: rbp  +0x090: r10  +0x098: r11
--   +0x0A0: r12  +0x0A8: r13  +0x0B0: r14  +0x0B8: r15
--   +0x0C0: cs   +0x0C8: rflags  +0x0D0: err  +0x0D8: trapno
--   +0x0E0: rip  +0x0E8: ds   +0x0F0: es   +0x0F8: rsp
--   +0x100: ss   +0x108: mc_len (+0x110: mc_fpformat, +0x118: mc_ownedfp)
----------------------------------------------------------------
local reg_names = {
    [0x048] = "rdi",  [0x050] = "rsi",  [0x058] = "rdx",  [0x060] = "rcx",
    [0x068] = "r8",   [0x070] = "r9",   [0x078] = "rax",  [0x080] = "rbx",
    [0x088] = "rbp",  [0x090] = "r10",  [0x098] = "r11",  [0x0A0] = "r12",
    [0x0A8] = "r13",  [0x0B0] = "r14",  [0x0B8] = "r15",  [0x0C0] = "cs",
    [0x0C8] = "rflags", [0x0D0] = "err", [0x0D8] = "trapno",
    [0x0E0] = "rip",  [0x0E8] = "ds",   [0x0F0] = "es",   [0x0F8] = "rsp",
    [0x100] = "ss",   [0x108] = "mc_len", [0x110] = "mc_fpformat",
    [0x118] = "mc_ownedfp",
}

local function dump_mcontext(buf, label)
    local kptrs = 0
    -- dump all non-zero qwords in the first 0x500 bytes
    print(string.format("  [%s] non-zero qwords in ucontext buffer:", label))
    for off = 0, 0x4F8, 8 do
        local v = rq(buf + off)
        local h, l = get_hi_lo(v)
        if h ~= 0 or l ~= 0 then
            local name = reg_names[off]
            local suffix = ""
            if is_kptr(h) then
                suffix = " *** KPTR_CANDIDATE ***"
                kptrs = kptrs + 1
            end
            if name then
                print(string.format("    +0x%03X (%s) = %s%s", off, name, q(v), suffix))
            else
                print(string.format("    +0x%03X = %s%s", off, q(v), suffix))
            end
        end
    end
    return kptrs
end

----------------------------------------------------------------
-- syscalls
----------------------------------------------------------------
local sc_getcontext     = make_syscall(421)
local sc_thr_get_uctx   = make_syscall(634)
local sc_thr_self       = make_syscall(432)
local sc_thr_create     = make_syscall(430)
local sc_thr_kill       = make_syscall(433)
local sc_nanosleep      = make_syscall(240)
local sc_getpid         = make_syscall(20)
local sc_mmap           = make_syscall(477)

local pid = to_num(sc_getpid())
print("pid=" .. pid)

local total_kptrs = 0

----------------------------------------------------------------
-- SECTION A: getcontext(421) on current thread
----------------------------------------------------------------
print("")
print("=== SECTION A: getcontext(421) on current thread ===")
local ok_a, err_a = pcall(function()
    local ctx = memory.alloc(0x500)
    -- fill with sentinel pattern to detect which bytes the kernel writes
    for off = 0, 0x4FC, 4 do wd(ctx + off, 0xA5A5A5A5) end

    print("  calling getcontext(421)...")
    local ok_gc, rv_gc = pcall(function()
        return sc_getcontext(uint64(ctx))
    end)
    print("  getcontext ok=" .. tostring(ok_gc) .. " rv=" .. tostring(rv_gc))

    -- count changed bytes
    local changed = 0
    for off = 0, 0x4FC, 4 do
        if rd(ctx + off) ~= 0xA5A5A5A5 then changed = changed + 1 end
    end
    print("  changed dwords: " .. changed .. " / " .. math.floor(0x500 / 4))

    if changed > 0 then
        local k = dump_mcontext(ctx, "A")
        total_kptrs = total_kptrs + k
    else
        print("  getcontext did not modify the buffer (syscall may have failed)")
    end

    -- also do a full byte-level scan for 0xFFFF8 prefix
    print("  [A] byte-level scan for 0xFFFF8xxx pattern:")
    local byte_hits = 0
    for off = 0, 0x4F8, 8 do
        local hi = rd(ctx + off + 4)
        if hi ~= 0xA5A5A5A5 and bit32.band(bit32.rshift(hi, 12), 0xFFFFF) == 0xFFFF8 then
            local lo = rd(ctx + off)
            print(string.format("    +0x%03X = 0x%08X%08X *** KPTR_CANDIDATE ***", off, hi, lo))
            byte_hits = byte_hits + 1
        end
    end
    if byte_hits == 0 then print("    (none)") end
    total_kptrs = total_kptrs + byte_hits
end)
if not ok_a then print("  SECTION A pcall error: " .. tostring(err_a)) end

----------------------------------------------------------------
-- SECTION B: thr_get_ucontext(634) on child thread TID
----------------------------------------------------------------
print("")
print("=== SECTION B: thr_get_ucontext(634) on sleeping child thread ===")
local ok_b, err_b = pcall(function()
    -- Find a 'ret' gadget and a spin gadget for child thread
    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local text_lo = rd(info + 0x108)
    local text_hi = rd(info + 0x10C)
    local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
    print("  eboot_base=" .. q(eboot_base))

    -- find EB FE (jmp $) for spin loop
    local spin_addr = nil
    for off = 0, 0x10000 do
        local ok_r, b0 = pcall(function() return to_num(memory.read_byte(eboot_base + off)) end)
        local ok_r2, b1 = pcall(function() return to_num(memory.read_byte(eboot_base + off + 1)) end)
        if ok_r and ok_r2 and b0 == 0xEB and b1 == 0xFE then
            spin_addr = eboot_base + off
            break
        end
    end
    if not spin_addr then
        -- fallback: use nop;jmp $ pattern or just pause;jmp $ — scan for C3
        -- and use a ret gadget; child will exit but that's ok for section B
        print("  no jmp$ found, scanning for ret...")
        for off = 0, 0x10000 do
            local ok_r, b = pcall(function() return to_num(memory.read_byte(eboot_base + off)) end)
            if ok_r and b == 0xC3 then
                spin_addr = eboot_base + off
                break
            end
        end
    end
    if not spin_addr then
        print("  no gadget found, aborting section B")
        return
    end
    print("  child RIP gadget=" .. q(spin_addr))

    -- ucontext for child: spin forever (or ret immediately)
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
    wq(ctx + C_RIP, spin_addr)
    wq(ctx + C_RSP, stack_top)

    local tid_buf = memory.alloc(8)
    zero(tid_buf, 8)

    print("  creating child thread (spinning)...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = rq(tid_buf)
    print("  thr_create ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc))
        .. " child_tid=" .. q(child_tid))

    -- let child settle
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(100000000))  -- 100ms
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- check child alive
    local ok_ck, rv_ck = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
    print("  thr_kill(child,0) rv=" .. tostring(to_num(rv_ck)) .. " (0=alive)")

    -- now call thr_get_ucontext(634) with child TID
    local uctx = memory.alloc(0x500)
    for off = 0, 0x4FC, 4 do wd(uctx + off, 0xA5A5A5A5) end

    -- thr_get_ucontext(634) takes: (lwpid_t tid, ucontext_t *ucp)
    -- But it might only work on self. Try anyway.
    print("  calling thr_get_ucontext(634, child_tid, uctx_buf)...")
    local ok_gu, rv_gu = pcall(function()
        return sc_thr_get_uctx(child_tid, uint64(uctx))
    end)
    print("  thr_get_ucontext ok=" .. tostring(ok_gu) .. " rv=" .. tostring(rv_gu))

    -- also try single-arg form (like getcontext, just with TID as first arg)
    local uctx2 = memory.alloc(0x500)
    for off = 0, 0x4FC, 4 do wd(uctx2 + off, 0xB5B5B5B5) end
    print("  trying single-arg thr_get_ucontext(634, uctx_buf)...")
    local ok_gu2, rv_gu2 = pcall(function()
        return sc_thr_get_uctx(uint64(uctx2))
    end)
    print("  single-arg ok=" .. tostring(ok_gu2) .. " rv=" .. tostring(rv_gu2))

    -- check which buffer got modified
    local changed1, changed2 = 0, 0
    for off = 0, 0x4FC, 4 do
        if rd(uctx + off) ~= 0xA5A5A5A5 then changed1 = changed1 + 1 end
        if rd(uctx2 + off) ~= 0xB5B5B5B5 then changed2 = changed2 + 1 end
    end
    print("  two-arg form: changed dwords=" .. changed1)
    print("  single-arg form: changed dwords=" .. changed2)

    if changed1 > 0 then
        print("  [B.two-arg] dumping child context:")
        local k = dump_mcontext(uctx, "B.2arg")
        total_kptrs = total_kptrs + k
    end
    if changed2 > 0 then
        print("  [B.single-arg] dumping context:")
        local k = dump_mcontext(uctx2, "B.1arg")
        total_kptrs = total_kptrs + k
    end

    -- kill the spinning child
    pcall(function() sc_thr_kill(child_tid, uint64(9)) end)
end)
if not ok_b then print("  SECTION B pcall error: " .. tostring(err_b)) end

----------------------------------------------------------------
-- SECTION C: thr_get_ucontext on child blocked in nanosleep
----------------------------------------------------------------
print("")
print("=== SECTION C: thr_get_ucontext(634) on child in nanosleep ===")
local ok_c, err_c = pcall(function()
    -- The idea: create a child thread that calls nanosleep(long duration).
    -- While the child is blocked in-kernel, read its ucontext — the saved
    -- RIP should be inside libkernel's syscall wrapper, and kernel may save
    -- additional state that leaks pointers.
    --
    -- Challenge: thr_create gives us a raw thread that jumps to RIP. We can't
    -- easily make it call nanosleep. Instead, we'll do the next best thing:
    -- create a thread that spins (jmp $), and use the kernel's trap delivery
    -- mechanism — the thread is in user-space but its kernel stack may still
    -- contain interesting data if we read at the right moment.
    --
    -- Alternatively: use the parent's own thread. Call thr_get_ucontext on
    -- our own TID while we're in the middle of the syscall (recursive).

    -- approach 1: self-introspect via thr_self TID
    local tidp = memory.alloc(8)
    zero(tidp, 8)
    pcall(function() sc_thr_self(uint64(tidp)) end)
    local my_tid = rq(tidp)
    print("  my TID=" .. q(my_tid))

    local uctx = memory.alloc(0x500)
    for off = 0, 0x4FC, 4 do wd(uctx + off, 0xC5C5C5C5) end

    print("  calling thr_get_ucontext(634) on self TID...")
    local ok_gu, rv_gu = pcall(function()
        return sc_thr_get_uctx(my_tid, uint64(uctx))
    end)
    print("  thr_get_ucontext(self) ok=" .. tostring(ok_gu) .. " rv=" .. tostring(rv_gu))

    local changed = 0
    for off = 0, 0x4FC, 4 do
        if rd(uctx + off) ~= 0xC5C5C5C5 then changed = changed + 1 end
    end
    print("  changed dwords=" .. changed)

    if changed > 0 then
        local k = dump_mcontext(uctx, "C.self")
        total_kptrs = total_kptrs + k
    end

    -- approach 2: alternative syscall number 416 (getcontext variant in some FreeBSD)
    -- sysarch(165) can also leak — try it as a bonus
    print("")
    print("  [C.bonus] trying sysarch(165) with AMD64_GET_GSBASE (0x83)...")
    local sc_sysarch = make_syscall(165)
    local gsbase_buf = memory.alloc(16)
    zero(gsbase_buf, 16)
    local ok_sa, rv_sa = pcall(function()
        return sc_sysarch(uint64(0x83), uint64(gsbase_buf))  -- AMD64_GET_GSBASE
    end)
    print("  sysarch(GET_GSBASE) ok=" .. tostring(ok_sa) .. " rv=" .. tostring(rv_sa))
    local gsbase = rq(gsbase_buf)
    print("  gsbase=" .. q(gsbase))
    local gh, gl = get_hi_lo(gsbase)
    if is_kptr(gh) then
        print("  *** KPTR_CANDIDATE in GSBASE: " .. q(gsbase) .. " ***")
        total_kptrs = total_kptrs + 1
    end

    -- try AMD64_GET_FSBASE (0x81)
    zero(gsbase_buf, 16)
    local ok_fs, rv_fs = pcall(function()
        return sc_sysarch(uint64(0x81), uint64(gsbase_buf))  -- AMD64_GET_FSBASE
    end)
    print("  sysarch(GET_FSBASE) ok=" .. tostring(ok_fs) .. " rv=" .. tostring(rv_fs))
    local fsbase = rq(gsbase_buf)
    print("  fsbase=" .. q(fsbase))
    local fh, fl = get_hi_lo(fsbase)
    if is_kptr(fh) then
        print("  *** KPTR_CANDIDATE in FSBASE: " .. q(fsbase) .. " ***")
        total_kptrs = total_kptrs + 1
    end

    -- approach 3: full dump of getcontext comparing with A to look for stale kernel data
    -- allocate oversized buffer and scan far past expected ucontext size
    print("")
    print("  [C.oversized] getcontext into 4096-byte buffer, scan for kernel VA prefix...")
    local big_ctx = memory.alloc(0x1000)
    for off = 0, 0xFFC, 4 do wd(big_ctx + off, 0) end
    local ok_gc2, rv_gc2 = pcall(function()
        return sc_getcontext(uint64(big_ctx))
    end)
    print("  getcontext ok=" .. tostring(ok_gc2) .. " rv=" .. tostring(rv_gc2))

    local hits = 0
    for off = 0, 0xFF8, 8 do
        local v = rq(big_ctx + off)
        local h, l = get_hi_lo(v)
        if is_kptr(h) then
            local name = reg_names[off]
            local tag = name and (" (" .. name .. ")") or ""
            print(string.format("    +0x%03X%s = %s *** KPTR_CANDIDATE ***",
                off, tag, q(v)))
            hits = hits + 1
        end
    end
    if hits == 0 then print("    (no kernel pointers in oversized buffer)") end
    total_kptrs = total_kptrs + hits
end)
if not ok_c then print("  SECTION C pcall error: " .. tostring(err_c)) end

----------------------------------------------------------------
-- SUMMARY
----------------------------------------------------------------
print("")
print("=== PROBE 171a SUMMARY ===")
print("total KPTR_CANDIDATE values found: " .. total_kptrs)
if total_kptrs > 0 then
    print("RESULT: UCONTEXT/GETCONTEXT LEAKS KERNEL POINTERS — KASLR DEFEAT CANDIDATE")
else
    print("RESULT: no kernel pointer leak detected via getcontext/thr_get_ucontext")
end
print("=== PROBE 171a COMPLETE ===")
