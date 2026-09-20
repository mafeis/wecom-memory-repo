# -*- coding: utf-8 -*-
"""
Parallel memory scan for WXWork DB key, chunked across cores, strict validation.
Validation: decrypt FULL page2 + page3 of message.db copy; both must be valid b-tree pages.
"""
import ctypes, ctypes.wintypes as wt, sys, os
from multiprocessing import Pool
from Crypto.Cipher import AES

RAW = r"__BASE__\wxwork_data\raw"
MSG_DB = os.path.join(RAW, "message.db")
PAGE = 4096

with open(MSG_DB, "rb") as f:
    DATA = f.read()
SALT = DATA[:16]
CT_P2 = DATA[PAGE:2*PAGE]
CT_P3 = DATA[2*PAGE:3*PAGE]
CT_PRE = DATA[4072:4088]
CT_STR = DATA[4088:4104]
CHAIN = DATA[4080:4096]
PTYPES = {0x02, 0x05, 0x0A, 0x0D}
Z16 = b"\x00"*16

def _hdr_ok(pt):
    if pt[0] not in PTYPES: return False
    fb = int.from_bytes(pt[1:3], "big"); nc = int.from_bytes(pt[3:5], "big"); cc = int.from_bytes(pt[5:7], "big")
    return fb <= PAGE and 0 < nc <= 600 and 480 <= cc <= PAGE

def strict_stream_cbc(key):
    """whole-file CBC from 24: pt[4096..4111] = D(ct[4088:4104]) xor ct[4072:4088]; page type at pt[8]."""
    d = AES.new(key, AES.MODE_ECB).decrypt(CT_STR)
    pt2first = bytes(a ^ b for a, b in zip(d, CT_PRE))
    if pt2first[8] not in PTYPES or not _hdr_ok(pt2first[8:24]):
        return None
    # decrypt page2 fully: stream pt = for each 16-byte block D(ct) xor prev ct block
    c = AES.new(key, AES.MODE_ECB)
    blocks = [DATA[24+i:24+i+16] for i in range(0, len(DATA)-24-16, 16)]
    # too slow to do whole file per candidate; instead validate page3 via chain: pt3_first = D(ct[8184:8200]) xor ct[8168:8184]
    d3 = c.decrypt(DATA[8184:8200])
    pt3 = bytes(a ^ b for a, b in zip(d3, DATA[8168:8184]))
    # pt3 corresponds to file offset 8192 -> pt3[8] is page3 type
    if pt3[8] in PTYPES and _hdr_ok(pt3[8:24]):
        return "stream_cbc"
    return None

def strict_page_cbc(key):
    try:
        d2 = AES.new(key, AES.MODE_ECB).decrypt(CT_P2[:16])
    except ValueError:
        return None
    cands = [("cbc_zero", Z16), ("cbc_salt", SALT), ("cbc_chain", CHAIN), ("cbc_key0", key[:16]), ("cbc_key1", key[16:32])]
    for name, iv in cands:
        pt2_0 = bytes(a ^ b for a, b in zip(d2, iv))
        if pt2_0[0] not in PTYPES or not _hdr_ok(pt2_0):
            continue
        # full page2 cbc check
        try:
            full2 = AES.new(key, AES.MODE_CBC, iv).decrypt(CT_P2)
        except ValueError:
            continue
        if not _hdr_ok(full2): continue
        # page3 with same scheme
        d3 = AES.new(key, AES.MODE_ECB).decrypt(CT_P3[:16])
        pt3_0 = bytes(a ^ b for a, b in zip(d3, iv))
        if pt3_0[0] in PTYPES and _hdr_ok(pt3_0):
            return name
    if d2[0] in PTYPES and _hdr_ok(d2):
        # ECB full check
        full2 = AES.new(key, AES.MODE_ECB).decrypt(CT_P2)
        if _hdr_ok(full2):
            d3 = AES.new(key, AES.MODE_ECB).decrypt(CT_P3[:16])
            if d3[0] in PTYPES:
                return "ecb"
    return None

def strict_aes128(key):
    for k in (key[:16], key[16:32]):
        try:
            d2 = AES.new(k, AES.MODE_ECB).decrypt(CT_P2[:16])
        except ValueError:
            continue
        for name, iv in (("128_cbc_zero", Z16), ("128_cbc_salt", SALT), ("128_cbc_chain", CHAIN)):
            pt0 = bytes(a ^ b for a, b in zip(d2, iv))
            if pt0[0] in PTYPES and _hdr_ok(pt0):
                full2 = AES.new(k, AES.MODE_CBC, iv).decrypt(CT_P2)
                if _hdr_ok(full2):
                    return name
        if d2[0] in PTYPES and _hdr_ok(d2):
            return "128_ecb"
    return None

def test_key(key):
    r = strict_page_cbc(key)
    if r: return r
    r = strict_stream_cbc(key)
    if r: return r
    return strict_aes128(key)

KERNEL32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
KERNEL32.OpenProcess.restype = ctypes.c_void_p
KERNEL32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
KERNEL32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

def get_regions(pid):
    h = KERNEL32.OpenProcess(0x0410, False, pid)
    if not h: return []
    out, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFEFFFF:
        if KERNEL32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        rs = mbi.RegionSize
        if mbi.State == 0x1000 and mbi.Protect in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80):
            out.append((addr, rs))
        addr += rs
    KERNEL32.CloseHandle(h)
    return out

CHUNK = 8*1024*1024
def scan_chunk(args):
    pid, addr, size = args
    h = KERNEL32.OpenProcess(0x0410, False, pid)
    if not h: return []
    buf = (ctypes.c_char * size)()
    got = ctypes.c_size_t()
    ok = KERNEL32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    KERNEL32.CloseHandle(h)
    if not ok: return []
    buf = bytes(buf[:got.value])
    hits = []
    n = len(buf) - 32
    for off in range(0, n, 4):
        r = test_key(buf[off:off+32])
        if r:
            hits.append((pid, hex(addr+off), r, buf[off:off+32].hex()))
    return hits

def worker(pid):
    regions = get_regions(pid)
    tasks = []
    for a, s in regions:
        for off in range(0, s, CHUNK):
            tasks.append((pid, a+off, min(CHUNK, s-off)))
    print(f"[pid {pid}] {len(tasks)} chunks (~{sum(t[2] for t in tasks)/1e6:.0f} MB)", flush=True)
    hits = []
    for t in tasks:
        hits += scan_chunk(t)
    print(f"[pid {pid}] done, hits={len(hits)}", flush=True)
    return hits

if __name__ == "__main__":
    pids = [int(x) for x in sys.argv[1:]]
    print(f"salt={SALT.hex()} pids={pids}", flush=True)
    with Pool(min(len(pids), 12)) as pool:
        results = pool.map(worker, pids)
    print("=== DONE ===", flush=True)
    hits = [h for rs in results for h in rs]
    for h in hits[:50]:
        print("HIT:", h)
    print(f"total strict hits: {len(hits)}")
    with open(r"__BASE__\tools\hits.txt", "w") as f:
        for h in hits:
            f.write(repr(h)+"\n")
