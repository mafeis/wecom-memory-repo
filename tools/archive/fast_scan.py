# -*- coding: utf-8 -*-
"""
Fast parallel scan: find 16-byte wxSQLite3 raw keys in all WXWork processes.
Validation: single-block decrypt of page1 first block -> pt[8:16] must equal the
plaintext header fragment (8 known bytes) -> then full page1 verify.
Scans COPIES of DBs in RAW dir; source files untouched.
"""
import ctypes, ctypes.wintypes as wt, os, sys, struct, hashlib
from multiprocessing import Pool
from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wxwork_crypto import (PAGE_SZ, SQLITE_HDR, is_wxsqlite3_aes128_page1,
                           decrypt_page, verify_key, decrypt_database,
                           derive_page_key, generate_initial_vector)

RAW = r"__BASE__\wxwork_data\raw"
OUT = r"__BASE__\wxwork_data\decrypted"
IV1 = generate_initial_vector(1)  # page 1 IV, precomputed

# load candidate db page1s
DBS = {}  # name -> page1 bytes
for f in os.listdir(RAW):
    if f.endswith(".db"):
        with open(os.path.join(RAW, f), "rb") as fh:
            p1 = fh.read(PAGE_SZ)
        if len(p1) == PAGE_SZ and is_wxsqlite3_aes128_page1(p1):
            DBS[f] = p1

# precompute per-db: ciphertext block0 (after fragment copy), expected plaintext fragment
DB_PROBES = []
for name, p1 in DBS.items():
    frag = p1[16:24]
    ct = bytearray(p1)
    ct[16:24] = ct[8:16]
    block0 = bytes(ct[16:32])
    DB_PROBES.append((name, frag, block0))

def quick_hit(key16):
    """Return list of db names this 16-byte key decrypts (single-block check)."""
    pk = derive_page_key(key16, 1)
    ecb = AES.new(pk, AES.MODE_ECB)
    hits = []
    for name, frag, block0 in DB_PROBES:
        d = ecb.decrypt(block0)
        pt0 = bytes(a ^ b for a, b in zip(d, IV1))
        if pt0[8:16] == frag:
            hits.append(name)
    return hits

def full_verify(key16, dbname):
    return verify_key(key16, DBS[dbname])

KERNEL32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
KERNEL32.OpenProcess.restype = ctypes.c_void_p
KERNEL32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
KERNEL32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
                ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD)]

def get_regions(pid):
    h = KERNEL32.OpenProcess(0x0410, False, pid)
    if not h:
        return []
    out, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFEFFFF:
        if KERNEL32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        rs = mbi.RegionSize
        if mbi.State == 0x1000 and mbi.Protect in (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) and rs < 500*1024*1024:
            out.append((addr, rs))
        nxt = addr + rs
        if nxt <= addr:
            break
        addr = nxt
    KERNEL32.CloseHandle(h)
    return out

def read_chunk(pid, addr, size):
    h = KERNEL32.OpenProcess(0x0410, False, pid)
    if not h:
        return b""
    buf = (ctypes.c_char * size)()
    got = ctypes.c_size_t()
    ok = KERNEL32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    KERNEL32.CloseHandle(h)
    return bytes(buf[:got.value]) if ok else b""

CHUNK = 4 * 1024 * 1024
def scan_chunk(args):
    pid, addr, size = args
    buf = read_chunk(pid, addr, size)
    hits = []
    if not buf:
        return hits
    n = len(buf) - 16
    zero = b"\x00" * 16
    for off in range(0, n, 4):
        c = buf[off:off+16]
        if c == zero or c == b"\xff" * 16:
            continue
        hs = quick_hit(c)
        if hs:
            for name in hs:
                if full_verify(c, name):
                    hits.append((name, pid, hex(addr+off), c.hex()))
                    print(f"  [FOUND] {name} pid={pid} addr={hex(addr+off)} key={c.hex()}", flush=True)
    return hits

def worker(pid):
    regions = get_regions(pid)
    tasks = []
    for a, s in regions:
        for o in range(0, s, CHUNK):
            tasks.append((pid, a+o, min(CHUNK, s-o)))
    est = sum(t[2] for t in tasks)
    print(f"[pid {pid}] {len(tasks)} chunks ~{est/1e6:.0f} MB", flush=True)
    hits = []
    for t in tasks:
        hits += scan_chunk(t)
    print(f"[pid {pid}] done hits={len(hits)}", flush=True)
    return hits

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    print(f"encrypted DBs to solve: {list(DBS.keys())}", flush=True)
    # find all WXWork.exe pids
    import subprocess
    out = subprocess.check_output(["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"], text=True)
    pids = []
    for line in out.strip().splitlines():
        parts = line.replace('"', "").split(",")
        if len(parts) >= 2 and "WXWork.exe" in parts[0]:
            pids.append(int(parts[1].strip()))
    print(f"WXWork pids: {pids}", flush=True)
    with Pool(min(len(pids), 5)) as pool:
        results = pool.map(worker, pids)
    # merge keys per db
    keymap = {}
    for rs in results:
        for name, pid, addr, keyhex in rs:
            keymap.setdefault(name, keyhex)
    print("=== keymap ===")
    for k, v in keymap.items():
        print(f"  {k}: {v}")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.json"), "w") as f:
        import json
        json.dump(keymap, f, indent=2)
    # decrypt all dbs we have keys for
    for name, keyhex in keymap.items():
        src = os.path.join(RAW, name)
        dst = os.path.join(OUT, name)
        decrypt_database(src, dst, bytes.fromhex(keyhex))
        from wxwork_crypto import verify_sqlite
        try:
            tables = verify_sqlite(dst)
            print(f"decrypted {name}: {len(tables)} tables: {tables}")
        except Exception as e:
            print(f"decrypted {name} but sqlite error: {e}")
    missing = set(DBS) - set(keymap)
    if missing:
        print(f"[!] no key found for: {missing}")
