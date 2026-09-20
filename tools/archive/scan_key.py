# -*- coding: utf-8 -*-
"""
Scan WXWork process memory for the DB decryption key.
- Only reads process memory (no writes, no source-file modification).
- Validates candidates against the COPY of message.db in workspace.
"""
import ctypes, ctypes.wintypes as wt, sys, os
from Crypto.Cipher import AES

KERNEL32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

RAW = r"__BASE__\wxwork_data\raw"
MSG_DB = os.path.join(RAW, "message.db")

PAGE = 4096
with open(MSG_DB, "rb") as f:
    data = f.read()
salt = data[:16]
page1_ct = data[:PAGE]
page2_ct = data[PAGE:2*PAGE]
# CBC chain hypothesis: IV for page2 = last 16-byte block of page1 ciphertext
chain_iv = page1_ct[-16:]

PAGE_TYPES = {0x02, 0x05, 0x0A, 0x0D}

def raw_block_decrypt(key, ct_block):
    return AES.new(key, AES.MODE_ECB).decrypt(ct_block)

# cache raw decrypt of page2 first block per key is pointless; but per candidate we do 1 block decrypt
def test_key(key):
    """Return hypothesis name if key decrypts page2 into a valid b-tree page."""
    try:
        d0 = raw_block_decrypt(key, page2_ct[:16])
    except ValueError:
        return None
    # h_ecb: whole page ECB -> pt[0] is page type directly
    if d0[0] in PAGE_TYPES:
        if _check_more_ecb(key):
            return "ecb"
    # h_cbc variants: pt = d0 xor IV
    for name, iv in (("cbc_zero", b"\x00"*16), ("cbc_salt", salt),
                     ("cbc_key16", key[:16]), ("cbc_chain", chain_iv),
                     ("cbc_md5salt", None)):
        if iv is None:
            continue
        pt0 = bytes(a ^ b for a, b in zip(d0, iv))
        if pt0[0] in PAGE_TYPES and pt0[1:4] in (b"\x00\x00\x00",) or (pt0[0] in PAGE_TYPES and pt0[1] == 0 and pt0[2] == 0):
            # stronger check: decrypt full page and verify internal structure
            if _check_full_cbc(key, iv):
                return name
    return None

def _check_more_ecb(key):
    c = AES.new(key, AES.MODE_ECB)
    pt = c.decrypt(page2_ct)
    if pt[0] not in PAGE_TYPES:
        return False
    # b-tree page header sanity: freeblock offset <= pagesize, cell count sane
    fb = int.from_bytes(pt[1:3], "big"); nc = int.from_bytes(pt[3:5], "big")
    return fb <= PAGE and 0 < nc < 500

def _check_full_cbc(key, iv):
    c = AES.new(key, AES.MODE_CBC, iv)
    pt = c.decrypt(page2_ct)
    if pt[0] not in PAGE_TYPES:
        return False
    fb = int.from_bytes(pt[1:3], "big"); nc = int.from_bytes(pt[3:5], "big")
    return fb <= PAGE and 0 < nc < 500

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD)]

def read_regions(pid):
    """Yield (addr, bytes) for committed, readable, private regions."""
    h = KERNEL32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    size = ctypes.sizeof(mbi)
    MEM_COMMIT = 0x1000
    PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x80}
    while addr < 0x7FFFFFFFFFFF:
        if ctypes.windll.kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), size) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE and mbi.Type == 0x20000:  # MEM_PRIVATE
            rsize = mbi.RegionSize
            buf = (ctypes.c_char * rsize)()
            got = ctypes.c_size_t()
            if KERNEL32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rsize, ctypes.byref(got)):
                yield addr, bytes(buf[:got.value])
        addr += mbi.RegionSize
    KERNEL32.CloseHandle(h)

def scan_pid(pid, salt):
    hits = []
    print(f"[pid {pid}] scanning...", flush=True)
    total = 0
    for base, buf in read_regions(pid):
        total += len(buf)
        idx = buf.find(salt)
        while idx != -1:
            # candidate keys near salt occurrence
            for delta in range(-1024, 1025, 4):
                off = idx + delta
                if 0 <= off and off + 32 <= len(buf):
                    key = buf[off:off+32]
                    h = test_key(key)
                    if h:
                        print(f"  !! HIT pid={pid} base={hex(base)} salt_off={hex(idx)} delta={delta} hyp={h} key={key.hex()}", flush=True)
                        hits.append((pid, base, idx, delta, h, key.hex()))
            idx = buf.find(salt, idx + 1)
    print(f"[pid {pid}] scanned {total/1e6:.0f} MB, salt-context candidates tested", flush=True)
    return hits

def full_scan_pid(pid):
    """Fallback: test every 4-byte-aligned 32-byte window (page2 cbc_chain + cbc_zero quick check)."""
    print(f"[pid {pid}] FULL scan...", flush=True)
    total = 0
    found = []
    for base, buf in read_regions(pid):
        total += len(buf)
        n = len(buf) - 32
        for off in range(0, n, 4):
            key = buf[off:off+32]
            try:
                d0 = raw_block_decrypt(key, page2_ct[:16])
            except ValueError:
                continue
            for iv in (chain_iv, b"\x00"*16, salt, key[:16]):
                pt0 = d0[0] ^ iv[0]
                if pt0 in PAGE_TYPES:
                    if _check_full_cbc(key, iv):
                        name = {chain_iv: "cbc_chain", b"\x00"*16: "cbc_zero", salt: "cbc_salt"}.get(iv, "cbc_key16")
                        print(f"  !! FULL HIT pid={pid} base={hex(base)} off={hex(off)} hyp={name} key={key.hex()}", flush=True)
                        found.append((pid, hex(base), hex(off), name, key.hex()))
    print(f"[pid {pid}] full scan done, {total/1e6:.0f} MB", flush=True)
    return found

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "salt"
    pids = [int(x) for x in sys.argv[2:]] or [6072, 14368, 19116, 23036, 23388]
    print(f"salt = {salt.hex()}")
    all_hits = []
    for pid in pids:
        try:
            if mode == "salt":
                all_hits += scan_pid(pid, salt)
            else:
                all_hits += full_scan_pid(pid)
        except Exception as e:
            print(f"[pid {pid}] error: {e}")
    print("=== DONE ===")
    for h in all_hits:
        print(h)
