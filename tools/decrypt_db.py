# -*- coding: utf-8 -*-
"""
Decrypt WXWork DB copies (source files untouched) given a candidate key.
Tries multiple schemes, validates with sqlite3 integrity check, writes to decrypted/.
Usage: python decrypt_db.py <keyhex>
"""
import sys, os, sqlite3, shutil
from Crypto.Cipher import AES

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "wxwork_data", "raw")
OUT = os.path.join(BASE, "wxwork_data", "decrypted")
PAGE = 4096
Z16 = b"\x00" * 16
SQLITE_MAGIC = b"SQLite format 3\x00"

DBS = ["message.db", "message_lookup.db", "session.db", "user.db", "user_extend.db",
       "company.db", "crm.db", "kv.db", "forever_store.db", "file.db"]

def try_open(buf, label):
    """Write buf to temp file and try sqlite3 integrity check."""
    tmp = os.path.join(OUT, f"_probe_{label}.db")
    with open(tmp, "wb") as f:
        f.write(buf)
    try:
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        cur.execute("PRAGMA integrity_check")
        res = cur.fetchone()[0]
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        con.close()
        return res, tables
    except Exception as e:
        return f"ERR {e}", []
    finally:
        os.remove(tmp)

def build_page1(salt_orig, dec_page1):
    """Rebuild page 1: restore SQLite magic, keep decrypted rest."""
    p = bytearray(dec_page1)
    p[0:16] = SQLITE_MAGIC
    return bytes(p)

def decrypt_stream_cbc(data, key, iv0, cts_fix=True):
    """Whole-file CBC from offset 24. Handles 8-byte dangling tail via CTS guess or zero-pad."""
    body = data[24:]
    n = len(body)
    full = n - (n % 16)
    pt = bytearray(AES.new(key, AES.MODE_CBC, iv0).decrypt(body[:full]))
    tail = body[full:]
    if tail:
        # try CTS: last full block is actually ct[n-16-8? ...] - simplified: decrypt tail block combined
        # Standard CBC-CTS form 3: C[n-1] = E(P[n] xor C[n-2]...) - try common variant:
        # plaintext tail = last 8 bytes of D(last_full_block_ct) xor prev_ct? guess: treat tail+last8 of prev
        pass
    out = bytes(pt)
    return out, tail  # tail = leftover ct bytes (8)

def attempt_db(path, key, label):
    with open(path, "rb") as f:
        data = f.read()
    salt = data[:16]
    results = []

    # Scheme A: whole-file CBC from 24, IV in {zero, salt}
    for ivname, iv0 in (("zero", Z16), ("salt", salt)):
        try:
            pt, tail = decrypt_stream_cbc(data, key, iv0)
        except ValueError:
            continue
        # page1: pt[0:4072] corresponds to file offsets 24..4096
        page1 = data[:24] + pt[:4072]
        rebuilt = build_page1(salt, page1)
        rest = pt[4072:]
        # assemble: header(24 fixed) + pt... -> full file: magic16 + data[16:24] + pt
        full = SQLITE_MAGIC + data[16:24] + pt
        if tail:
            full += b"\x00" * (16 - len(tail))  # pad guess
            full = full[:len(data)]
        res, tables = try_open(full, f"A_{ivname}")
        results.append((f"stream_cbc_iv={ivname}", res, tables[:12]))

    # Scheme B: per-page CBC; page1: 24 plaintext + CBC(24..4088) + 8 bytes tail-plaintext guess
    for ivname, iv0 in (("zero", Z16), ("salt", salt), ("chain", None), ("key0", key[:16])):
        pages = [data[:PAGE]]
        ok = True
        prev_ct_last = data[4080:4096]
        for pno in range(1, len(data)//PAGE):
            ct = data[pno*PAGE:(pno+1)*PAGE]
            iv = iv0
            if ivname == "chain":
                iv = prev_ct_last
            try:
                dpt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
            except ValueError:
                ok = False; break
            pages.append(dpt)
            prev_ct_last = ct[4080:4096]
        if not ok:
            continue
        # page1 special: we encrypted nothing; for ivname we didn't handle page1 tail region.
        # Reconstruct page1: assume 0..23 plaintext + 24..4096 decrypted with iv0 (4072 bytes -> pad)
        ct1 = data[24:PAGE]
        pad = (-len(ct1)) % 16
        try:
            dpt1 = AES.new(key, AES.MODE_CBC, iv0 if ivname != "chain" else Z16).decrypt(ct1 + b"\x00"*pad)
        except ValueError:
            continue
        page1 = data[:24] + dpt1[:len(ct1)]
        rebuilt = build_page1(salt, page1)
        blob = rebuilt + b"".join(pages[1:])
        res, tables = try_open(blob, f"B_{ivname}")
        results.append((f"page_cbc_iv={ivname}", res, tables[:12]))

    # Scheme C: per-page ECB
    pages = []
    for pno in range(len(data)//PAGE):
        ct = data[pno*PAGE:(pno+1)*PAGE]
        pages.append(AES.new(key, AES.MODE_ECB).decrypt(ct))
    page1 = data[:24] + pages[0][24:]
    rebuilt = build_page1(salt, page1)
    blob = rebuilt + b"".join(pages[1:])
    res, tables = try_open(blob, "C_ecb")
    results.append(("page_ecb", res, tables[:12]))

    return results

if __name__ == "__main__":
    keyhex = sys.argv[1]
    key = bytes.fromhex(keyhex)
    os.makedirs(OUT, exist_ok=True)
    for db in DBS:
        p = os.path.join(RAW, db)
        if not os.path.exists(p):
            continue
        print(f"--- {db} ---")
        for label, res, tables in attempt_db(p, key, db):
            print(f"  {label}: {res}  tables={tables}")
