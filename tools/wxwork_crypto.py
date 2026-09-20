# -*- coding: utf-8 -*-
"""
wxSQLite3 AES-128-CBC 加解密核心（来自社区方案 jiebao776/wxwork-decrypt，本地化保存）
企业微信(WXWork)使用的数据库加密方案。

每页独立密钥：page_key = MD5(raw_key + pack("<I", page_no) + "sAlT")
每页独立IV：   IV = MD5( LCG(page_no + 1) )
第1页特殊处理：保留明文 fragment(bytes 16-23)，重组后解密
"""

import hashlib
import os
import sqlite3
import struct

from Crypto.Cipher import AES

PAGE_SZ = 4096
SQLITE_HDR = b"SQLite format 3\x00"
WXSQLITE3_SALT = b"sAlT"


def _modmult(a, b, c, m, s):
    q = s // a
    s = b * (s - a * q) - c * q
    if s < 0:
        s += m
    return s


def generate_initial_vector(page_no):
    z = page_no + 1
    initkey = bytearray(16)
    for idx in range(4):
        z = _modmult(52774, 40692, 3791, 2147483399, z)
        initkey[idx * 4: idx * 4 + 4] = struct.pack("<I", z & 0xFFFFFFFF)
    return hashlib.md5(initkey).digest()


def derive_page_key(raw_key, page_no):
    if len(raw_key) != 16:
        raise ValueError("wxSQLite3 AES-128 raw key must be 16 bytes")
    material = raw_key + struct.pack("<I", page_no) + WXSQLITE3_SALT
    return hashlib.md5(material).digest()


def has_wxsqlite3_plain_header_fragment(page):
    if len(page) < 24:
        return False
    header = page[16:24]
    page_size = (header[0] << 8) | header[1]
    if page_size == 1:
        page_size = 65536
    return (
        page_size >= 512
        and page_size <= 65536
        and (page_size & (page_size - 1)) == 0
        and header[5] == 0x40
        and header[6] == 0x20
        and header[7] == 0x20
    )


def is_wxsqlite3_aes128_page1(page):
    return page[: len(SQLITE_HDR)] != SQLITE_HDR and has_wxsqlite3_plain_header_fragment(page)


def decrypt_page(raw_key, page_data, page_no):
    if len(page_data) != PAGE_SZ:
        raise ValueError(f"page must be exactly {PAGE_SZ} bytes")

    page_key = derive_page_key(raw_key, page_no)
    iv = generate_initial_vector(page_no)

    data = bytearray(page_data)
    if page_no == 1 and has_wxsqlite3_plain_header_fragment(data):
        db_header_fragment = bytes(data[16:24])
        data[16:24] = data[8:16]
        decrypted_tail = AES.new(page_key, AES.MODE_CBC, iv).decrypt(bytes(data[16:]))
        data[16:] = decrypted_tail
        if bytes(data[16:24]) != db_header_fragment:
            raise ValueError("wxSQLite3 AES-128 key validation failed")
        data[:16] = SQLITE_HDR
        return bytes(data)

    return AES.new(page_key, AES.MODE_CBC, iv).decrypt(bytes(data))


def verify_key(raw_key, page1):
    if len(raw_key) != 16 or len(page1) < PAGE_SZ:
        return False
    try:
        decrypted = decrypt_page(raw_key, page1[:PAGE_SZ], 1)
        return decrypted[:16] == SQLITE_HDR
    except (ValueError, KeyError):
        return False


def decrypt_database(db_path, output_path, raw_key):
    file_size = os.path.getsize(db_path)
    total_pages = (file_size + PAGE_SZ - 1) // PAGE_SZ

    with open(db_path, "rb") as fin, open(output_path, "wb") as fout:
        for page_idx in range(total_pages):
            page_data = fin.read(PAGE_SZ)
            if not page_data:
                break
            if len(page_data) < PAGE_SZ:
                page_data += b"\x00" * (PAGE_SZ - len(page_data))

            page_no = page_idx + 1
            fout.write(decrypt_page(raw_key, page_data, page_no))

    return total_pages


def verify_sqlite(path):
    conn = sqlite3.connect(path)
    try:
        return [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()]
    finally:
        conn.close()
