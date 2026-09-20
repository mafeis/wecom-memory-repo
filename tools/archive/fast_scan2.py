# -*- coding: utf-8 -*-
"""
加速版 WXWork 密钥提取。

原理：密钥在 WXWork.exe 内存中以 cipher 结构体缓存（见 jiebao776/wxwork-decrypt find_keys.py 文档）：
    +0x00: flag0 (dword, 恒 0)      <- key 前面 8 字节
    +0x08: raw_key (16 bytes)      <- 我们要的
    +0x2C: aes_ctx 指针

加速策略（对比社区原版逐偏移 + 全页验证，快 3~4 个数量级）：
  1. 用 bytes.find 在 C 速度下找 "4 连零"(flag0) -> 候选位置 = 零串后 4 字节
  2. 候选再做 aes_ctx 指针合理性检查（x64 用户态指针范围）
  3. 幸存者做单块 AES 验证（只解 16 字节，非整页）
  4. 命中后用完整 page1 解密做最终确认
只读进程内存，源数据库不动。
"""
import ctypes, ctypes.wintypes as wt, os, sys, json, struct
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wxwork_crypto import PAGE_SZ, verify_key, generate_initial_vector
from Crypto.Cipher import AES

RAW = r"__BASE__\wxwork_data\raw"
OUT = r"__BASE__\wxwork_data\decrypted"

# ---- 预置验证探针（message.db page1） ----
with open(os.path.join(RAW, "message.db"), "rb") as f:
    P1 = f.read(PAGE_SZ)
FRAG = P1[16:24]                      # 明文 header fragment（最终比对用）
_ct = bytearray(P1)
_ct[16:24] = _ct[8:16]                # wxSQLite3 page1 重组
BLOCK0 = bytes(_ct[16:32])            # 第一个密文块
IV1 = generate_initial_vector(1)      # page1 的 IV
Z4 = b"\x00" * 4

def quick_hit(key16):
    """单块验证：True 则极可能是真 key。"""
    pk = __import__("hashlib").md5(
        key16 + struct.pack("<I", 1) + b"sAlT").digest()
    d = AES.new(pk, AES.MODE_ECB).decrypt(BLOCK0)
    pt0 = bytes(a ^ b for a, b in zip(d, IV1))
    return pt0[0:8] == FRAG

# ---- Windows 内存读取 ----
K32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
K32.OpenProcess.restype = ctypes.c_void_p
K32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
K32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
                ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD)]

def get_pids():
    import subprocess
    out = subprocess.check_output(
        ["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"], text=True)
    pids = []
    for line in out.strip().splitlines():
        parts = line.replace('"', "").split(",")
        if len(parts) >= 2 and "WXWork.exe" in parts[0]:
            pids.append(int(parts[1].strip()))
    return pids

def get_regions(pid):
    h = K32.OpenProcess(0x0410, False, pid)
    if not h:
        return []
    out, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFEFFFF:
        if K32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                              ctypes.sizeof(mbi)) == 0:
            break
        rs = mbi.RegionSize
        if mbi.State == 0x1000 and mbi.Protect in (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) \
                and rs < 500 * 1024 * 1024:
            out.append((addr, rs))
        nxt = addr + rs
        if nxt <= addr:
            break
        addr = nxt
    K32.CloseHandle(h)
    return out

def read_chunk(pid, addr, size):
    h = K32.OpenProcess(0x0410, False, pid)
    if not h:
        return b""
    buf = (ctypes.c_char * size)()
    got = ctypes.c_size_t()
    ok = K32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    K32.CloseHandle(h)
    return bytes(buf[:got.value]) if ok else b""

CHUNK = 4 * 1024 * 1024

def scan_chunk(task):
    pid, addr, size = task
    buf = read_chunk(pid, addr, size)
    hits, n_zerofilter, n_aestest = [], 0, 0
    if not buf:
        return hits, 0, 0
    n = len(buf)
    pos = buf.find(Z4)
    while pos != -1:
        i = pos + 4                      # 候选 key 偏移（flag0 在 key-8）
        pos = buf.find(Z4, pos + 1)
        if i < 8 or i + 44 > n:          # 需要 key(16) + 到 +0x2C 指针的空间
            continue
        c = buf[i:i + 16]
        if c == b"\x00" * 16 or c == b"\xff" * 16:
            continue
        n_zerofilter += 1
        # aes_ctx 指针合理性（x64 用户态）
        ptr = struct.unpack_from("<Q", buf, i + 36)[0]
        if not (0x10000 <= ptr < 0x800000000000):
            continue
        n_aestest += 1
        if quick_hit(c):
            if verify_key(c, P1):
                hits.append((pid, hex(addr + i), c.hex()))
                print(f"  [FOUND] pid={pid} addr={hex(addr + i)} key={c.hex()}", flush=True)
    return hits, n_zerofilter, n_aestest

def worker(pid):
    regions = get_regions(pid)
    tasks = []
    for a, s in regions:
        for o in range(0, s, CHUNK):
            tasks.append((pid, a + o, min(CHUNK, s - o)))
    mb = sum(t[2] for t in tasks) / 1e6
    print(f"[pid {pid}] {len(tasks)} chunks ~{mb:.0f} MB", flush=True)
    hits, zf, ae = [], 0, 0
    for t in tasks:
        h, z, a = scan_chunk(t)
        hits += h; zf += z; ae += a
    print(f"[pid {pid}] done: hits={len(hits)} 零串候选={zf} AES测试={ae}", flush=True)
    return hits

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    pids = get_pids()
    print(f"WXWork pids: {pids}", flush=True)
    if not pids:
        sys.exit("[!] 未找到 WXWork.exe")
    with Pool(min(cpu_count(), 8)) as pool:
        results = pool.map(worker, pids)
    keymap = {}
    for rs in results:
        for pid, addr, keyhex in rs:
            keymap.setdefault(keyhex, []).append((pid, addr))
    print("=== keymap ===")
    for k, v in keymap.items():
        print(f"  {k}  @ {v}")
    if keymap:
        keys_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.json")
        with open(keys_file, "w") as f:
            json.dump({k: v[0][1] for k, v in keymap.items()}, f, indent=2)
        print(f"saved -> {keys_file}")
        # 直接解密 message.db
        keyhex = next(iter(keymap))
        from wxwork_crypto import decrypt_database, verify_sqlite
        dst = os.path.join(OUT, "message.db")
        print(f"decrypting message.db with {keyhex} ...", flush=True)
        decrypt_database(os.path.join(RAW, "message.db"), dst, bytes.fromhex(keyhex))
        try:
            print("tables:", verify_sqlite(dst))
        except Exception as e:
            print(f"sqlite error: {e}")
    else:
        print("[!] 未找到密钥（零串候选为 0 的话说明结构体假设不成立，需回退全扫描）")
