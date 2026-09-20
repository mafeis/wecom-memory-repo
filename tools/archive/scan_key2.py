# -*- coding: utf-8 -*-
"""
Scan all WXWork processes' private memory for the DB key.
Hypotheses (validated against a COPY of message.db, source untouched):
  A: whole-file CBC stream from offset 24, IV unknown {zero, salt}
  B: per-page CBC, page2 IV in {zero, salt, key[:16], key[16:], chain}
  C: ECB (per-page or stream)
  D: AES-128 variants with key[:16] / key[16:]
  E: hex-encoded 64-char key strings
Validation: decrypted page-2 (and page-3) must look like valid SQLite b-tree pages.
"""
import ctypes, ctypes.wintypes as wt, sys, os, re
from multiprocessing import Pool
from Crypto.Cipher import AES

RAW = r"__BASE__\wxwork_data\raw"
MSG_DB = os.path.join(RAW, "message.db")
PAGE = 4096

with open(MSG_DB, "rb") as f:
    DATA = f.read()
SALT = DATA[:16]
# candidate ciphertext spans
CT_PAGE2 = DATA[PAGE:2*PAGE]          # file offsets 4096..8191
CT_PRE   = DATA[4072:4088]            # last full ct block before offset 4096
CT_STR   = DATA[4088:4104]            # ct block straddling offset 4096 (stream model)
CHAIN_IV = DATA[4080:4096]            # last block of page1 ct
PAGE_TYPES = {0x02, 0x05, 0x0A, 0x0D}
Z16 = b"\x00" * 16

def btree_ok(pt):
    if pt[0] not in PAGE_TYPES:
        return False
    fb = int.from_bytes(pt[1:3], "big")
    nc = int.from_bytes(pt[3:5], "big")
    cc = int.from_bytes(pt[5:7], "big")   # cell content start
    if fb > PAGE or nc == 0 or nc > 600:
        return False
    if cc > PAGE or cc < 480:
        return False
    return True

def stream_check(key):
    """Whole-file CBC from 24. pt for file offsets 4096..4111 = D(ct[4088:4104]) xor ct[4072:4088]."""
    d = AES.new(key, AES.MODE_ECB).decrypt(CT_STR)
    pt = bytes(a ^ b for a, b in zip(d, CT_PRE))
    if pt[8] in PAGE_TYPES and btree_ok(pt[8:]):
        return "stream_cbc(iv from stream)"
    return None

def page_check(key):
    """Per-page schemes: page2 first block decrypt."""
    try:
        d = AES.new(key, AES.MODE_ECB).decrypt(CT_PAGE2[:16])
    except ValueError:
        return None
    ivs = [("cbc_zero", Z16), ("cbc_salt", SALT), ("cbc_chain", CHAIN_IV),
           ("cbc_key0", key[:16]), ("cbc_key1", key[16:32])]
    for name, iv in ivs:
        pt0 = bytes(a ^ b for a, b in zip(d, iv))
        if pt0[0] in PAGE_TYPES and btree_ok(pt0):
            return name
    if d[0] in PAGE_TYPES and btree_ok(d):
        return "ecb"
    return None

def test_key(key):
    r = page_check(key)
    if r:
        return r
    return stream_check(key)

KERNEL32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
KERNEL32.OpenProcess.restype = ctypes.c_void_p
KERNEL32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
KERNEL32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]

def get_regions(pid):
    h = KERNEL32.OpenProcess(0x0410, False, pid)  # QUERY_INFO | VM_READ
    if not h:
        return []
    out = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFEFFFF:
        if KERNEL32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        rs = mbi.RegionSize
        if mbi.State == 0x1000 and mbi.Type == 0x20000 and mbi.Protect in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80):
            out.append((addr, rs))
        addr += rs
    KERNEL32.CloseHandle(h)
    return out

def read_region(pid, addr, size):
    h = KERNEL32.OpenProcess(0x0410, False, pid)
    if not h:
        return b""
    buf = (ctypes.c_char * size)()
    got = ctypes.c_size_t()
    ok = KERNEL32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    KERNEL32.CloseHandle(h)
    return bytes(buf[:got.value]) if ok else b""

def scan_region(args):
    pid, addr, size = args
    buf = read_region(pid, addr, size)
    hits = []
    if not buf:
        return hits
    n = len(buf) - 32
    # hex-string candidates
    for m in re.finditer(rb"[0-9a-fA-F]{64}", buf):
        try:
            key = bytes.fromhex(m.group().decode())
            h = test_key(key)
            if h:
                hits.append((pid, hex(addr + m.start()), "hexstr", h, key.hex()))
        except Exception:
            pass
    for off in range(0, n, 4):
        key = buf[off:off+32]
        h = test_key(key)
        if h:
            hits.append((pid, hex(addr + off), "raw", h, key.hex()))
    return hits

def worker(pid):
    total = 0
    all_hits = []
    regions = get_regions(pid)
    est = sum(r[1] for r in regions)
    print(f"[pid {pid}] {len(regions)} private regions, ~{est/1e6:.0f} MB", flush=True)
    tasks = [(pid, a, s) for a, s in regions if s < 64*1024*1024]
    for i, (pid2, a, s) in enumerate(tasks):
        all_hits += scan_region((pid2, a, s))
        total += s
    print(f"[pid {pid}] done {total/1e6:.0f} MB, hits={len(all_hits)}", flush=True)
    return all_hits

if __name__ == "__main__":
    pids = [int(x) for x in sys.argv[1:]]
    print(f"salt={SALT.hex()}  pids={pids}", flush=True)
    with Pool(min(len(pids), 12)) as pool:
        results = pool.map(worker, pids)
    print("=== DONE ===", flush=True)
    for rs in results:
        for h in rs:
            print("HIT:", h)
    n = sum(len(r) for r in results)
    print(f"total hits: {n}")
    if n == 0:
        with open(r"__BASE__\tools\nohit.txt", "w") as f:
            f.write("no key found\n")
