# First Code Execution on PS5 Firmware 14.20

**Date:** 2026-10-21
**Firmware:** 26.07-14.20.00.07 (released 2026-10-21)
**Console:** PS5 Pro (no disc drive)
**Researcher:** Unkown607 / wsjardijn

## Entry Vector
Lua 5.1 loader via Hamidashi Creative Demo (CUSA27390) save-file injection.
Save decrypted/encrypted via garlicsaves.com (server-side PFS processing).

## Proof
```
hello world from lua!
platform ps5 (14.20)
pid 106  ppid 55
eboot base @ 0x4bf74000
libc base @ 0x1245a0000
libkernel base @ 0x837008000
```

## Confirmed Primitives on 14.20

| Primitive | Status | Evidence |
|-----------|--------|----------|
| Lua loader TCP :9026 | ✅ | hello_world.lua |
| ASLR randomization | ✅ | Different bases across sessions |
| make_syscall(N) | ✅ | 20+ syscalls tested |
| native.fcall | ✅ | Jump to arbitrary address |
| native.fcall_with_rax | ✅ | Available |
| native.read_buffer | ✅ | Available |
| native.write_buffer | ✅ | Available |
| memory.alloc/read/write | ✅ | All tests |
| thr_create(430) threading | ✅ | rv=0, real TIDs, child executes |
| Event flags (sys 538-546) | ✅ | handle=0x4205 |
| Semaphores (sys 549-556) | ✅ | handle=0x208 |
| Generic objects (sys 557/558) | ✅ | All types accepted |
| Handle recycling (8 rounds) | ✅ | Handles wrap and reuse |
| sys 660 module info | ✅ | 3 modules, names+bases |
| getcontext(421) | ✅ | Full mcontext, 304 dwords |

## Confirmed Dead on 14.20

| Vector | Status | Evidence |
|--------|--------|----------|
| KASLR info-leak (20+ paths) | ❌ | 0 kernel pointers |
| W^X bypass (mmap/mprotect/588/620) | ❌ | Exec bit stripped |
| sys 625 MSR controller | ❌ | All -1 |
| PMU configure/read (565/567) | ❌ | Refused |
| sys 630 mount enum | ❌ | All -1 |
| sys 532 GPU data | ❌ | Sony error codes only |
| Stale handle UAF | ❌ | Kernel invalidates mapping |
| Thrd_create (C11, demo offsets) | ❌ | Wrong offsets for demo build |

## Key Findings

1. **14.20 is uncharted territory.** Released same day as our testing. All results are first-ever.
2. **Threading WORKS** via thr_create(430) with ZigZagBoi1 mcontext offsets.
3. **native.fcall WORKS** — can jump to any address (ROP enabler).
4. **W^X is firm** — mmap accepts prot=7 but strips exec bit at PTE level.
5. **IPC primitives are LIVE** — event flags, semaphores, generic objects all functional.
6. **KASLR is undefeated** — every conventional info-leak is sanitized.
7. **Handle recycling is exploitable** with threading (race condition window).
