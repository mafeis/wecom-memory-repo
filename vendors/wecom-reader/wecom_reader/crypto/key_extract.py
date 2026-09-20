"""Extract WeCom (企业微信) database decryption key from WXWork.exe process memory.

Two scanning strategies:
1. x'...' pattern: Fast regex match for SQL-embedded hex keys
2. cipher struct: Slower but more reliable heap object layout scan

Requires: Windows, admin privileges, WXWork.exe running.
"""

import bisect
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import subprocess
import time
from typing import Optional

from .decrypt import is_plain_sqlite, is_wxsqlite3_aes128_page1, verify_key

# Windows API constants
kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}


class MBI(ctypes.Structure):
    """MEMORY_BASIC_INFORMATION for VirtualQueryEx."""
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD),
        ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("_pad2", wt.DWORD),
    ]


def _read_process_memory(handle, addr: int, size: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(
        handle, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)
    ):
        return buf.raw[: n.value]
    return None


def _enum_memory_regions(handle) -> list[tuple[int, int]]:
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(
            handle, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ) == 0:
            break
        if (
            mbi.State == MEM_COMMIT
            and mbi.Protect in READABLE
            and 0 < mbi.RegionSize < 500 * 1024 * 1024
        ):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def _get_wxwork_pids() -> list[tuple[int, int]]:
    """Get WXWork.exe PIDs sorted by memory usage (descending)."""
    r = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
    )
    pids = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(",", "").replace(" K", "").strip() or "0")
            pids.append((pid, mem))
    pids.sort(key=lambda x: x[1], reverse=True)
    return pids


def _auto_detect_db_dir() -> Optional[str]:
    """Scan %USERPROFILE%\\Documents\\WXWork\\*\\Data for encrypted DBs."""
    docs = os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "WXWork")
    if not os.path.isdir(docs):
        return None

    candidates = []
    for name in os.listdir(docs):
        data_dir = os.path.join(docs, name, "Data")
        if not os.path.isdir(data_dir):
            continue
        for fname in os.listdir(data_dir):
            if not fname.endswith(".db"):
                continue
            fpath = os.path.join(data_dir, fname)
            if os.path.getsize(fpath) < 4096:
                continue
            with open(fpath, "rb") as f:
                header = f.read(16)
            if header != b"SQLite format 3\x00":
                candidates.append(data_dir)
                break

    if not candidates:
        return None
    # Return most recently modified
    candidates.sort(key=lambda d: os.path.getmtime(d), reverse=True)
    return candidates[0]


def _collect_db_files(db_dir: str) -> tuple[list, dict]:
    """Collect all .db files with their salts and page 1 data."""
    db_files = []  # (rel_path, abs_path, size, salt_hex, page1_bytes)
    salt_to_dbs = {}  # salt_hex -> [rel_path, ...]

    for root, dirs, files in os.walk(db_dir):
        dirs[:] = [d for d in dirs if d not in ("-journal",)]
        for name in files:
            if not name.endswith(".db") or name.endswith("-wal") or name.endswith("-shm"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, db_dir)
            sz = os.path.getsize(path)
            if sz < 4096:
                continue
            with open(path, "rb") as f:
                page1 = f.read(4096)
            if is_plain_sqlite(page1):
                continue
            salt_hex = page1[:16].hex()
            db_files.append((rel, path, sz, salt_hex, page1))
            salt_to_dbs.setdefault(salt_hex, []).append(rel)

    return db_files, salt_to_dbs


def _verify_key_wxwork(enc_key: bytes, db_page1: bytes) -> tuple[bool, str]:
    """Verify key against database page 1 with multiple parameter sets."""
    if len(enc_key) == 16 and verify_key(enc_key, db_page1):
        return True, "wxSQLite3 AES-128-CBC, per-page MD5 key/IV, no HMAC"
    return False, ""


def extract_key(
    db_dir: Optional[str] = None,
    timeout: int = 120,
    verbose: bool = False,
) -> dict[str, str]:
    """Extract decryption keys from WXWork.exe process memory.

    Args:
        db_dir: Path to WeCom data directory. Auto-detected if None.
        timeout: Max seconds for struct scan per process.
        verbose: Print progress to stderr.

    Returns:
        Dict mapping salt_hex -> enc_key_hex for each database found.
        Also includes "_db_dir" key with the database directory path.

    Raises:
        RuntimeError: If WXWork.exe is not running or no keys found.
    """
    if db_dir is None:
        db_dir = _auto_detect_db_dir()
    if not db_dir or not os.path.isdir(db_dir):
        raise RuntimeError(
            "Cannot find WeCom data directory. "
            "Set db_dir or ensure %USERPROFILE%\\Documents\\WXWork\\*\\Data exists."
        )

    db_files, salt_to_dbs = _collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"No encrypted databases found in {db_dir}")

    pids = _get_wxwork_pids()
    if not pids:
        raise RuntimeError("WXWork.exe is not running")

    key_map = {}
    remaining_salts = set(salt_to_dbs.keys())
    hex_re = re.compile(b"x'([0-9a-fA-F]{32,192})'")

    for pid, mem_kb in pids:
        handle = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            continue

        try:
            regions = _enum_memory_regions(handle)
            total_bytes = sum(s for _, s in regions)

            # Strategy 1: x'...' pattern scan
            for base, size in regions:
                data = _read_process_memory(handle, base, size)
                if not data:
                    continue

                for m in hex_re.finditer(data):
                    hex_str = m.group(1).decode()
                    addr = base + m.start()
                    hex_len = len(hex_str)

                    candidates = []
                    if hex_len == 32:
                        candidates.append((hex_str, None))
                    elif hex_len == 64:
                        candidates.append((hex_str[:32], hex_str[32:]))
                        candidates.append((hex_str, None))
                    elif hex_len == 96:
                        candidates.append((hex_str[:64], hex_str[64:]))
                        candidates.append((hex_str[:32], hex_str[-32:]))

                    for enc_key_hex, salt_hex in candidates:
                        if len(enc_key_hex) not in (32, 64):
                            continue
                        enc_key = bytes.fromhex(enc_key_hex)

                        targets = (
                            [(s, salt_to_dbs[s]) for s in remaining_salts if s == salt_hex]
                            if salt_hex
                            else [(s, salt_to_dbs[s]) for s in remaining_salts]
                        )

                        for s, dbs in targets:
                            for rel, path, sz, salt, page1 in db_files:
                                if salt == s:
                                    ok, desc = _verify_key_wxwork(enc_key, page1)
                                    if ok:
                                        key_map[s] = enc_key_hex
                                        remaining_salts.discard(s)
                                    break

                        if not remaining_salts:
                            break
                    if not remaining_salts:
                        break
                if not remaining_salts:
                    break

            # Strategy 2: cipher struct scan (if x'...' didn't find all)
            if remaining_salts:
                memory_regions = []
                for base, size in regions:
                    data = _read_process_memory(handle, base, size)
                    if data:
                        memory_regions.append((int(base), int(base) + len(data), data))
                memory_regions.sort(key=lambda item: item[0])
                starts = [item[0] for item in memory_regions]

                page_sizes = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
                t0 = time.time()

                for base, end, data in memory_regions:
                    if time.time() - t0 > timeout:
                        break
                    max_off = len(data) - 0x40
                    off = 0
                    while off >= 0 and off < max_off:
                        flag0, flag4 = struct.unpack_from("<II", data, off)
                        if flag0 in (1, 2) and flag4 in (1, 2, 4096, 8192, 16384):
                            cipher_addr = base + off
                            aes_ctx = struct.unpack_from("<I", data, off + 0x2C)[0]
                            # Validate page_size pointer chain
                            ps_holder = _read_u32(memory_regions, starts, cipher_addr + 0x30)
                            if ps_holder and _valid_ptr(memory_regions, starts, ps_holder, 8):
                                ps_obj = _read_u32(memory_regions, starts, ps_holder + 4)
                                if ps_obj and _valid_ptr(memory_regions, starts, ps_obj + 0x24, 4):
                                    page_size = _read_u32(memory_regions, starts, ps_obj + 0x24)
                                    if page_size in page_sizes:
                                        enc_key = data[off + 8 : off + 24]
                                        if enc_key != b"\x00" * 16 and len(set(enc_key)) >= 6:
                                            for s in list(remaining_salts):
                                                for rel, path, sz, salt, page1 in db_files:
                                                    if salt == s:
                                                        ok, _ = _verify_key_wxwork(enc_key, page1)
                                                        if ok:
                                                            key_map[s] = enc_key.hex()
                                                            remaining_salts.discard(s)
                                                        break
                                            if not remaining_salts:
                                                break
                        off += 4
                    if not remaining_salts:
                        break

        finally:
            kernel32.CloseHandle(handle)

        if not remaining_salts:
            break

    # Cross-verify: try known keys against unmatched salts
    if remaining_salts and key_map:
        for salt_hex in list(remaining_salts):
            for rel, path, sz, s, page1 in db_files:
                if s == salt_hex:
                    for known_key_hex in key_map.values():
                        enc_key = bytes.fromhex(known_key_hex)
                        ok, _ = _verify_key_wxwork(enc_key, page1)
                        if ok:
                            key_map[salt_hex] = known_key_hex
                            remaining_salts.discard(salt_hex)
                    break

    if not key_map:
        raise RuntimeError("Failed to extract any decryption keys from WXWork.exe")

    key_map["_db_dir"] = db_dir
    return key_map


def _read_u32(memory_regions, starts, addr):
    idx = bisect.bisect_right(starts, addr) - 1
    if idx < 0:
        return None
    base, end, data = memory_regions[idx]
    if base <= addr and addr + 4 <= end:
        return struct.unpack_from("<I", data, addr - base)[0]
    return None


def _valid_ptr(memory_regions, starts, addr, length=4):
    idx = bisect.bisect_right(starts, addr) - 1
    if idx < 0:
        return False
    base, end, _ = memory_regions[idx]
    return base <= addr and addr + length <= end
