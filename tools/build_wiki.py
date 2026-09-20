# -*- coding: utf-8 -*-
"""
Build a wiki-style memory repo from decrypted WeCom databases.
- Re-decrypts from RAW snapshots using saved keys.json
- Merges WAL frames so the latest messages are included
- Emits: wiki/index.md, contacts.md, conversations/*.md, search payload JSON
- Emits: single-file HTML wiki with client-side search
Source files are never modified.
"""
import os, re, json, struct, sqlite3, hashlib, datetime, html
from Crypto.Cipher import AES

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE, "wxwork_data", "raw")
DEC = os.path.join(BASE, "wxwork_data", "decrypted")
WIKI = os.path.join(BASE, "wiki")
KEYS = json.load(open(os.path.join(BASE, "wxwork_data", "keys.json"), encoding="utf-8"))

PAGE = 4096
SQLITE_HDR = b"SQLite format 3\x00"
SALT_STR = b"sAlT"

# ---------------- crypto ----------------

def _modmult(a, b, c, m, s):
    q = s // a
    s = b * (s - a * q) - c * q
    if s < 0:
        s += m
    return s

def gen_iv(page_no):
    z = page_no + 1
    ik = bytearray(16)
    for i in range(4):
        z = _modmult(52774, 40692, 3791, 2147483399, z)
        ik[i*4:i*4+4] = struct.pack("<I", z & 0xFFFFFFFF)
    return hashlib.md5(ik).digest()

def page_key(raw_key, page_no):
    return hashlib.md5(raw_key + struct.pack("<I", page_no) + SALT_STR).digest()

def decrypt_page(raw_key, page_data, page_no):
    if len(page_data) != PAGE:
        page_data = page_data + b"\x00" * (PAGE - len(page_data))
    k = page_key(raw_key, page_no)
    iv = gen_iv(page_no)
    data = bytearray(page_data)
    if page_no == 1:
        frag = bytes(data[16:24])
        data[16:24] = data[8:16]
        tail = AES.new(k, AES.MODE_CBC, iv).decrypt(bytes(data[16:]))
        data[16:] = tail
        if bytes(data[16:24]) != frag:
            raise ValueError("key mismatch")
        data[:16] = SQLITE_HDR
        return bytes(data)
    return AES.new(k, AES.MODE_CBC, iv).decrypt(bytes(data))

def parse_wal(wal_bytes):
    """Return list of (pgno, page_bytes) applied in order, and last commit dbsize."""
    if len(wal_bytes) < 32:
        return [], 0
    magic, fmt, psz, ckpt, s1, s2 = struct.unpack(">6I", wal_bytes[:24])
    if psz != PAGE:
        return [], 0
    frames = []
    off = 32
    dbsize = 0
    while off + 24 + PAGE <= len(wal_bytes):
        pgno, dbsz, fs1, fs2 = struct.unpack(">4I", wal_bytes[off:off+16])
        if fs1 != s1 or fs2 != s2:
            break
        data = wal_bytes[off+24:off+24+PAGE]
        frames.append((pgno, data))
        if dbsz > 0:
            dbsize = dbsz
        off += 24 + PAGE
    return frames, dbsize

def decrypt_db_with_wal(db_path, wal_path, raw_key, out_path):
    with open(db_path, "rb") as f:
        data = f.read()
    npages = (len(data) + PAGE - 1) // PAGE
    pages = {}
    for i in range(npages):
        pages[i + 1] = data[i*PAGE:(i+1)*PAGE]
    final_size = npages
    if wal_path and os.path.exists(wal_path):
        with open(wal_path, "rb") as f:
            wal = f.read()
        frames, dbsize = parse_wal(wal)
        for pgno, pdata in frames:
            pages[pgno] = pdata
        if dbsize > 0:
            final_size = max(final_size, dbsize)
    with open(out_path, "wb") as f:
        for pno in range(1, final_size + 1):
            pdata = pages.get(pno, b"\x00" * PAGE)
            f.write(decrypt_page(raw_key, pdata, pno))

# ---------------- protobuf text extraction ----------------

HEXRE = re.compile(r"^[0-9a-fA-F]{40,}$")

def parse_pb_texts(buf, depth=0, out=None):
    if out is None:
        out = []
    if depth > 6 or not buf:
        return out
    i = 0
    n = len(buf)
    while i < n:
        shift = 0; tag = 0
        while i < n:
            b = buf[i]; i += 1; tag |= (b & 0x7f) << shift; shift += 7
            if not b & 0x80:
                break
        wt = tag & 7
        if wt == 0:
            while i < n:
                b = buf[i]; i += 1
                if not b & 0x80:
                    break
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        elif wt == 2:
            shift = 0; ln = 0
            while i < n:
                b = buf[i]; i += 1; ln |= (b & 0x7f) << shift; shift += 7
                if not b & 0x80:
                    break
            if i + ln > n:
                break
            chunk = buf[i:i+ln]; i += ln
            try:
                s = chunk.decode("utf-8")
                if len(s) >= 2 and all(c in "\n\r\t" or ord(c) >= 32 for c in s):
                    out.append(s)
                    continue
            except UnicodeDecodeError:
                pass
            parse_pb_texts(chunk, depth + 1, out)
        else:
            break
    return out

def render_message(content_type, content):
    """Return (kind_label, display_text)."""
    if content is None:
        return "系统", ""
    if isinstance(content, str):
        return "文本", content.strip()
    if not isinstance(content, bytes):
        return "其他", str(content)
    texts = parse_pb_texts(content)
    if content_type in (0, 2):
        txt = " ".join(t for t in texts if not HEXRE.match(t)).strip()
        return "文本", txt or "[空消息]"
    if content_type == 4:
        return "图片", ""
    if content_type == 7:
        return "语音", ""
    if content_type == 10:
        return "邮件", " ".join(texts[:4])[:600]
    if content_type == 13:
        keep = [t for t in texts if not HEXRE.match(t)]
        return "文档", " | ".join(keep[:3])[:400]
    if content_type in (14, 123):
        fn = next((t for t in texts if re.search(r"\.(png|jpe?g|gif|bmp|webp)$", t, re.I)), None)
        txt = " ".join(t for t in texts if not HEXRE.match(t) and t != fn).strip()
        label = "图片" if fn else "消息"
        disp = (f"[图片: {fn}] " if fn else "") + txt
        return label, disp.strip()[:600]
    if content_type == 15:
        fn = next((t for t in texts if re.search(r"\.[a-z0-9]{1,6}$", t, re.I) and not t.startswith("http")), "")
        return "文件", fn or " ".join(texts[:2])[:200]
    if content_type == 20:
        fn = next((t for t in texts if re.search(r"\.[a-z0-9]{1,6}$", t, re.I) and not t.startswith("http") and not HEXRE.match(t)), "")
        return "文件", fn or " ".join(texts[:2])[:200]
    if content_type in (31, 35, 561, 573, 81):
        title = next((t for t in texts if len(t) >= 4 and not t.startswith("http") and not t.startswith("{")), "")
        return "卡片", title[:300]
    if content_type == 36:
        txt = " ".join(t for t in texts if not HEXRE.match(t)).strip()
        return "引用回复", txt[:600]
    if content_type == 38:
        return "应用消息", " ".join(texts[:3])[:400]
    if content_type == 80:
        return "Markdown", texts[0] if texts else ""
    if content_type == 40:
        return "通话", ""
    if content_type == 1011:
        return "会议", " ".join(texts[:2])[:300]
    txt = " ".join(t for t in texts if not HEXRE.match(t)).strip()
    return f"类型{content_type}", txt[:400] or ""

# ---------------- data loading ----------------

MSG_TYPES = {0: "text", 2: "text", 4: "image", 7: "voice", 15: "file", 38: "app",
             40: "call", 1011: "meeting"}

def load_account(acc):
    dec = os.path.join(DEC, acc)
    salts = KEYS.get(acc, {})
    # user map
    users = {}
    depts = {}
    try:
        con = sqlite3.connect(os.path.join(dec, "user.db"))
        con.row_factory = sqlite3.Row
        for r in con.execute("SELECT id, name, position, mobile, email FROM user_table"):
            users[r["id"]] = {"name": r["name"] or f"用户{r['id']}", "position": r["position"] or "",
                              "mobile": r["mobile"] or "", "email": r["email"] or ""}
        for r in con.execute("SELECT id, name, parent_id FROM department_tableV2"):
            depts[r["id"]] = r["name"]
        con.close()
    except Exception:
        pass
    my_id = int(acc)
    my_name = users.get(my_id, {}).get("name", "我")

    # conversations
    convs = {}
    members = {}
    try:
        con = sqlite3.connect(os.path.join(dec, "session.db"))
        con.row_factory = sqlite3.Row
        for r in con.execute("SELECT con_numeric_id, id, name, roomname_remark, last_message_time FROM conversation_table"):
            cid = r["id"]
            convs[cid] = {"num_id": r["con_numeric_id"], "id": cid,
                          "name": r["roomname_remark"] or r["name"] or cid,
                          "last_time": r["last_message_time"] or 0}
        try:
            for r in con.execute("SELECT conversation_id, user_id, nick_name FROM conversation_user_table"):
                members.setdefault(r["conversation_id"], []).append(
                    {"uid": r["user_id"], "nick": r["nick_name"] or ""})
        except Exception:
            pass
        con.close()
    except Exception:
        pass

    # messages
    msgs = []
    md = os.path.join(dec, "message.db")
    con = sqlite3.connect(md)
    con.row_factory = sqlite3.Row
    for table in ("message_table", "message_small_table", "kf_message_tableV1"):
        try:
            for r in con.execute(f"SELECT message_id, sender_id, conversation_id, content_type, send_time, content, flag FROM {table}"):
                msgs.append(dict(r))
        except Exception:
            pass
    con.close()
    msgs.sort(key=lambda m: (m["send_time"] or 0, m["message_id"]))
    return {"acc": acc, "my_id": my_id, "my_name": my_name, "users": users,
            "depts": depts, "convs": convs, "members": members, "msgs": msgs}

def conv_type(cid):
    if cid.startswith("R:"): return "群聊"
    if cid.startswith("S:"): return "单聊"
    if cid.startswith("M:"): return "微信联系人"
    if cid.startswith("O:"): return "应用"
    if cid.startswith("Y:"): return "系统"
    return "其他"

def peer_of_single(cid, my_id):
    try:
        parts = cid[2:].split("_")
        vids = [int(p) for p in parts if p]
        for v in vids:
            if v != my_id:
                return v
        return vids[0] if vids else None
    except Exception:
        return None

def safe_name(s):
    s = re.sub(r"[\\/:*?\"<>|\r\n\t]", "_", s).strip(". ")
    return s[:60] or "unnamed"

def ts(t):
    if not t:
        return ""
    return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")

# ---------------- build ----------------

def main():
    os.makedirs(WIKI, exist_ok=True)
    os.makedirs(os.path.join(WIKI, "conversations"), exist_ok=True)

    # 1) re-decrypt with WAL merge (skip unchanged dbs without wal)
    for acc, salts in KEYS.items():
        rawd = os.path.join(RAW, acc)
        decd = os.path.join(DEC, acc)
        os.makedirs(decd, exist_ok=True)
        for fn in os.listdir(rawd):
            if not fn.endswith(".db"):
                continue
            dbp = os.path.join(rawd, fn)
            walp = dbp + "-wal"
            outp = os.path.join(decd, fn)
            with open(dbp, "rb") as f:
                page1 = f.read(PAGE)
            if page1[:16] == SQLITE_HDR:
                continue
            salt_hex = page1[:16].hex()
            key_hex = salts.get(salt_hex)
            if not key_hex:
                print(f"[skip] {acc}/{fn}: no key for salt {salt_hex[:12]}...")
                continue
            try:
                decrypt_db_with_wal(dbp, walp, bytes.fromhex(key_hex), outp)
            except Exception as e:
                print(f"[fail] {acc}/{fn}: {e}")
        print(f"[decrypt] {acc} done")

    # 2) load accounts
    accounts = [load_account(a) for a in sorted(KEYS.keys())]

    # 3) build wiki
    index_lines = ["# 企业微信记忆仓库", ""]
    index_lines.append(f"> 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　|　数据来源: 本地解密数据库副本（源文件未改动）")
    index_lines.append("")
    all_payload = []
    contact_rows = {}

    for A in accounts:
        acc = A["acc"]
        total = len(A["msgs"])
        my_msg = sum(1 for m in A["msgs"] if m["sender_id"] == A["my_id"])
        span = ""
        if A["msgs"]:
            span = f"{ts(A['msgs'][0]['send_time'])} ~ {ts(A['msgs'][-1]['send_time'])}"
        index_lines.append(f"## 账号 {acc}（{A['my_name']}）")
        index_lines.append("")
        index_lines.append(f"- 消息总数: **{total}**（我发送 {my_msg}）")
        index_lines.append(f"- 会话数: **{len(A['convs'])}**　|　联系人: **{len(A['users'])}**")
        if span:
            index_lines.append(f"- 时间范围: {span}")
        index_lines.append("")
        index_lines.append("| 会话 | 类型 | 消息数 | 最新消息 | 页面 |")
        index_lines.append("|---|---|---:|---|---|")

        # group messages per conversation
        by_conv = {}
        for m in A["msgs"]:
            by_conv.setdefault(m["conversation_id"], []).append(m)

        used_names = set()
        rows = sorted(A["convs"].values(), key=lambda c: -(c["last_time"] or 0))
        payload_convs = []
        for c in rows:
            cid = c["id"]
            ms = by_conv.get(cid, [])
            ctype = conv_type(cid)
            cname = c["name"]
            if ctype == "单聊":
                peer = peer_of_single(cid, A["my_id"])
                uname = A["users"].get(peer, {}).get("name")
                if uname:
                    cname = uname
            if ctype == "群聊" and (not cname or cname == cid):
                member_ids = [x["uid"] for x in A["members"].get(cid, [])]
                names = [A["users"].get(u, {}).get("name", str(u)) for u in member_ids[:4]]
                cname = "、".join(names) + (f" 等{len(member_ids)}人群" if len(member_ids) > 4 else "")
            base = safe_name(cname)
            fname = f"{base}__{cid.replace(':', '_').replace('/', '_')}"
            k = 1
            while fname in used_names:
                k += 1
                fname = f"{base}({k})__{cid.replace(':', '_').replace('/', '_')}"
            used_names.add(fname)

            # conversation markdown
            mem_lines = []
            if ctype == "群聊" and cid in A["members"]:
                ml = []
                for x in A["members"][cid]:
                    nm = x["nick"] or A["users"].get(x["uid"], {}).get("name", str(x["uid"]))
                    ml.append(nm)
                mem_lines = ["**群成员**: " + "、".join(ml)]
            lines = [f"# {cname}", "",
                     f"- 会话ID: `{cid}`　|　类型: {ctype}　|　消息数: {len(ms)}",
                     f"- 最新消息时间: {ts(c['last_time'])}"]
            lines += mem_lines
            lines.append("")
            cur_day = ""
            conv_payload_msgs = []
            for m in ms:
                kind, text = render_message(m["content_type"], m["content"])
                t = m["send_time"] or 0
                day = datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d") if t else "未知日期"
                if day != cur_day:
                    cur_day = day
                    lines.append(f"## {day}")
                    lines.append("")
                sender = A["users"].get(m["sender_id"], {}).get("name")
                if sender is None:
                    sender = "我" if m["sender_id"] == A["my_id"] else f"用户{m['sender_id']}"
                clock = datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S") if t else "--:--:--"
                if kind == "图片":
                    body = "📷 *[图片]*"
                elif kind == "语音":
                    body = "🎙️ *[语音]*"
                elif kind == "通话":
                    body = "📞 *[通话]*"
                elif kind == "Markdown":
                    body = text
                else:
                    body = (text.replace("\n", " / ") if text else f"_[{kind}]_")
                prefix = "" if sender == "我" else f"**{sender}** "
                lines.append(f"- `{clock}` {prefix}{body}")
                conv_payload_msgs.append({"t": t, "s": sender, "k": kind, "x": body})
            with open(os.path.join(WIKI, "conversations", fname + ".md"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

            if ms:
                index_lines.append(f"| [{cname}](conversations/{fname}.md) | {ctype} | {len(ms)} | {ts(ms[-1]['send_time'])} | {fname[:28]}… |")
            payload_convs.append({"name": cname, "cid": cid, "type": ctype,
                                  "count": len(ms), "last": c["last_time"] or 0,
                                  "msgs": conv_payload_msgs})
        index_lines.append("")
        all_payload.append({"acc": acc, "my_name": A["my_name"], "convs": payload_convs})

        # contacts
        for uid, u in A["users"].items():
            contact_rows.setdefault(uid, u)

    # contacts.md
    cl = ["# 联系人目录", ""]
    cl.append("| 用户ID | 姓名 | 职位 | 手机 | 邮箱 |")
    cl.append("|---|---|---|---|---|")
    for uid, u in sorted(contact_rows.items()):
        cl.append(f"| {uid} | {u['name']} | {u['position']} | {u['mobile']} | {u['email']} |")
    with open(os.path.join(WIKI, "contacts.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(cl) + "\n")

    with open(os.path.join(WIKI, "index.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(index_lines) + "\n")

    # 4) data payload for HTML
    payload = json.dumps({"accounts": all_payload, "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                         ensure_ascii=False, separators=(",", ":"))
    with open(os.path.join(WIKI, "_data.json"), "w", encoding="utf-8") as f:
        f.write(payload)
    print(f"payload size: {len(payload)/1e6:.1f} MB")
    print("markdown wiki done ->", WIKI)

if __name__ == "__main__":
    main()
