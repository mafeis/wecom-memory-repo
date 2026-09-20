# -*- coding: utf-8 -*-
"""Full refresh pipeline: snapshot -> keys -> decrypt(+WAL) -> FTS index -> wiki html.
Used by server /api/refresh, scheduled task, and update_wiki.ps1."""
import os, sys, json, shutil, subprocess, ctypes, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "wxwork_data", "raw")
DEC = os.path.join(BASE, "wxwork_data", "decrypted")
DOCS = os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "WXWork")
VEND = os.path.join(BASE, "vendors", "wecom-reader")
sys.path.insert(0, os.path.join(BASE, "tools"))
sys.path.insert(0, VEND)

PAGE_MIN = 4096

def log(msg):
    print(time.strftime("[%H:%M:%S]") + " " + msg, flush=True)

def snapshot_accounts():
    """Shared-read snapshot of every account's Data dir."""
    n = 0
    for name in os.listdir(DOCS):
        if not name.isdigit():
            continue
        src = os.path.join(DOCS, name, "Data")
        if not os.path.isdir(src):
            continue
        dst = os.path.join(RAW, name)
        os.makedirs(dst, exist_ok=True)
        for fn in os.listdir(src):
            if not fn.endswith((".db", ".db-wal", ".db-shm")):
                continue
            s = os.path.join(src, fn)
            try:
                with open(s, "rb") as fi, open(os.path.join(dst, fn), "wb") as fo:
                    shutil.copyfileobj(fi, fo)
                n += 1
            except OSError:
                pass
    log(f"snapshot: {n} files")
    return n

def _wxwork_session_id():
    """Fingerprint of running WXWork.exe processes via native Windows API (no subprocess)."""
    import ctypes, hashlib
    k = ctypes.WinDLL("kernel32.dll")
    k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    class PES(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("pid", ctypes.c_ulong), ("threads", ctypes.c_ulong),
                    ("pidParent", ctypes.c_ulong), ("pcPri", ctypes.c_long),
                    ("flags", ctypes.c_ulong), ("exe", ctypes.c_wchar * 260)]

    h = k.CreateToolhelp32Snapshot(0x2, 0)
    pids = []
    if h:
        pe = PES(); pe.dwSize = ctypes.sizeof(PES)
        if k.Process32FirstW(h, ctypes.byref(pe)):
            while True:
                if pe.exe == "WXWork.exe":
                    pids.append(pe.pid)
                if not k.Process32NextW(h, ctypes.byref(pe)):
                    break
        k.CloseHandle(h)
    # NOTE: do NOT include memory usage in the fingerprint - it changes every second,
    # which previously invalidated the cache on every run. PIDs are stable while running.
    pids.sort()
    return hashlib.md5(str(pids).encode()).hexdigest()

def _cached_keys_usable():
    """Quick check: cached keys still decrypt the main message.db page1 AND
    the WXWork process fingerprint matches. Returns old keymap or None."""
    from wecom_reader.crypto.decrypt import verify_key
    keyfile = os.path.join(BASE, "wxwork_data", "keys.json")
    if not os.path.exists(keyfile):
        return None
    try:
        old = json.load(open(keyfile, encoding="utf-8"))
    except Exception:
        return None
    if not any(not k.startswith("_") and isinstance(v, dict) and v for k, v in old.items()):
        return None
    try:
        if old.get("_session") != _wxwork_session_id():
            return None
    except Exception:
        return None
    # verify against largest message.db snapshot
    best, best_sz = None, -1
    for name in os.listdir(RAW):
        p = os.path.join(RAW, name, "message.db")
        if os.path.exists(p):
            sz = os.path.getsize(p)
            if sz > best_sz:
                best, best_sz = p, sz
    if not best:
        return old
    with open(best, "rb") as f:
        page1 = f.read(4096)
    keys = old.get(os.path.basename(os.path.dirname(best)), {})
    khex = keys.get(page1[:16].hex())
    if khex and verify_key(bytes.fromhex(khex), page1):
        return old
    return None

def extract_keys():
    """Extract keys once per WXWork session; reuse cached keys when session unchanged."""
    from wecom_reader.crypto.key_extract import extract_key
    from wecom_reader.crypto.decrypt import verify_key, is_wxsqlite3_aes128_page1
    keyfile = os.path.join(BASE, "wxwork_data", "keys.json")
    old = {}
    if os.path.exists(keyfile):
        try:
            old = json.load(open(keyfile, encoding="utf-8"))
        except Exception:
            old = {}
    cached = _cached_keys_usable()
    if cached is not None:
        log("keys cached for this WXWork session - skip extraction")
        return cached
    session = _wxwork_session_id()
    # extract once from the largest account's Data (most db salts to verify against)
    accounts = [d for d in os.listdir(RAW) if os.path.isdir(os.path.join(RAW, d))]
    accounts.sort(key=lambda d: -sum(os.path.getsize(os.path.join(RAW, d, f))
                 for f in os.listdir(os.path.join(RAW, d)) if f.endswith(".db")))
    km = None
    for acc in accounts:
        try:
            km = extract_key(db_dir=os.path.join(RAW, acc), timeout=240)
            km.pop("_db_dir", None)
            log(f"keys extracted via {acc}: {len(km)}")
            break
        except Exception as e:
            log(f"extract via {acc} failed: {e}")
    if not km:
        log("no keys extracted; keeping old keys")
        return old
    # spread keys to every account by verifying against each db's page1
    out = {}
    for acc in accounts:
        salts = {}
        d = os.path.join(RAW, acc)
        # skip accounts with no real message data (e.g. logged-out stubs) - saves ~45s each
        msg_db = os.path.join(d, "message.db")
        if not os.path.exists(msg_db) or os.path.getsize(msg_db) < PAGE_MIN:
            log(f"keys skipped {acc}: empty account")
            out[acc] = salts
            continue
        for fn in os.listdir(d):
            if not fn.endswith(".db"):
                continue
            with open(os.path.join(d, fn), "rb") as f:
                page1 = f.read(4096)
            if len(page1) < 4096 or not is_wxsqlite3_aes128_page1(page1):
                continue
            salt = page1[:16].hex()
            if salt in salts:
                continue
            for khex in km.values():
                if verify_key(bytes.fromhex(khex), page1):
                    salts[salt] = khex
                    break
        if not salts and old.get(acc):
            # fallback: keep previous session keys for this account
            salts = {k: v for k, v in old[acc].items() if not k.startswith("_")}
            log(f"keys matched {acc}: 0 fresh, {len(salts)} from cache")
        else:
            log(f"keys matched {acc}: {len(salts)}")
        if not salts and acc != accounts[0]:
            # last resort: short per-account extraction
            try:
                km2 = extract_key(db_dir=d, timeout=60)
                km2.pop("_db_dir", None)
                n = 0
                for fn in os.listdir(d):
                    if not fn.endswith(".db"):
                        continue
                    with open(os.path.join(d, fn), "rb") as f:
                        page1 = f.read(4096)
                    if len(page1) < 4096 or not is_wxsqlite3_aes128_page1(page1):
                        continue
                    salt = page1[:16].hex()
                    if salt in salts:
                        continue
                    for khex in km2.values():
                        if verify_key(bytes.fromhex(khex), page1):
                            salts[salt] = khex
                            n += 1
                            break
                log(f"keys re-extracted {acc}: +{n}")
            except Exception as e:
                log(f"re-extract {acc} failed: {e}")
        out[acc] = salts
    out["_session"] = session
    with open(keyfile, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    return out

def decrypt_all():
    import build_wiki as bw
    keys = json.load(open(os.path.join(BASE, "wxwork_data", "keys.json"), encoding="utf-8"))
    for acc, salts in keys.items():
        if acc.startswith("_") or not isinstance(salts, dict):
            continue
        rawd = os.path.join(RAW, acc)
        decd = os.path.join(DEC, acc)
        os.makedirs(decd, exist_ok=True)
        if not os.path.isdir(rawd):
            continue
        for fn in os.listdir(rawd):
            if not fn.endswith(".db"):
                continue
            dbp = os.path.join(rawd, fn)
            with open(dbp, "rb") as f:
                page1 = f.read(4096)
            if page1[:16] == bw.SQLITE_HDR:
                continue
            key_hex = salts.get(page1[:16].hex())
            if not key_hex:
                continue
            try:
                bw.decrypt_db_with_wal(dbp, dbp + "-wal", bytes.fromhex(key_hex),
                                       os.path.join(decd, fn))
            except Exception as e:
                log(f"decrypt fail {acc}/{fn}: {e}")
        log(f"decrypted: {acc}")

def rebuild_indexes():
    import build_fts
    build_fts.main()
    import gen_html
    # gen_html has no main(); run as subprocess-free import by exec
    log("fts + html rebuilt")

def _count_main_msgs():
    import sqlite3
    total = 0
    for acc in os.listdir(DEC):
        p = os.path.join(DEC, acc, "message.db")
        if os.path.exists(p):
            try:
                con = sqlite3.connect(p)
                total += con.execute("SELECT COUNT(*) FROM message_table").fetchone()[0]
                con.close()
            except Exception:
                pass
    return total

def main(steps=None):
    wxwork_running = False
    try:
        import subprocess as sp
        r = sp.run(["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
                   capture_output=True, text=True)
        wxwork_running = "WXWork.exe" in r.stdout
    except Exception:
        pass
    if not wxwork_running:
        log("WXWork.exe not running - refresh aborted (start WeCom first)")
        return {"ok": False, "error": "WXWork.exe not running"}
    snapshot_accounts()
    extract_keys()
    decrypt_all()
    # safeguard: if re-login rotated keys without process restart, decryption yields 0 rows.
    # invalidate the session cache and redo keys+decrypt once.
    if _count_main_msgs() == 0:
        log("decrypt yielded 0 messages - possible key rotation; forcing re-extract")
        keyfile = os.path.join(BASE, "wxwork_data", "keys.json")
        try:
            old = json.load(open(keyfile, encoding="utf-8"))
        except Exception:
            old = {}
        old.pop("_session", None)
        for acc in list(old):
            if isinstance(old[acc], dict):
                old[acc] = {}
        with open(keyfile, "w", encoding="utf-8") as f:
            json.dump(old, f, indent=2)
        extract_keys()
        decrypt_all()
    rebuild_indexes()
    log("refresh complete")
    return {"ok": True}

if __name__ == "__main__":
    main()
