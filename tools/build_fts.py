# -*- coding: utf-8 -*-
"""Build unified FTS5 search index over all decrypted WeCom messages."""
import os, re, json, sqlite3, datetime, struct, hashlib, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pb import extract_texts

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "wxwork_data", "decrypted")
KEYS = json.load(open(os.path.join(BASE, "wxwork_data", "keys.json"), encoding="utf-8"))
IDX = os.path.join(BASE, "wxwork_data", "search_index.db")

def conv_type(cid):
    if cid.startswith("R:"): return "群聊"
    if cid.startswith("S:"): return "单聊"
    if cid.startswith("M:"): return "微信联系人"
    if cid.startswith("O:"): return "应用"
    if cid.startswith("Y:"): return "系统"
    return "其他"

def peer_of_single(cid, my_id):
    try:
        vids = [int(p) for p in cid[2:].split("_") if p]
        for v in vids:
            if v != my_id:
                return v
        return vids[0] if vids else None
    except Exception:
        return None

def render(content_type, content):
    texts = extract_texts(content)
    join2 = lambda ts: " ".join(ts)[:800]
    if content_type in (0, 2):
        return "文本", join2(texts)
    if content_type == 4: return "图片", ""
    if content_type == 7: return "语音", ""
    if content_type == 10: return "邮件", join2(texts[:5])
    if content_type == 13: return "文档", join2(texts[:3])
    if content_type in (14, 123):
        fn = next((t for t in texts if re.search(r"\.(png|jpe?g|gif|bmp|webp)$", t, re.I)), None)
        rest = [t for t in texts if t != fn]
        return "图片", (("图片:" + fn + " ") if fn else "") + join2(rest)
    if content_type in (15, 20):
        fn = next((t for t in texts if re.search(r"\.[a-z0-9]{1,6}$", t, re.I) and not t.startswith("http")), "")
        return "文件", fn or join2(texts[:2])
    if content_type in (31, 35, 561, 573, 81):
        title = next((t for t in texts if len(t) >= 4 and not t.startswith("http") and not t.startswith("{")), "")
        return "卡片", title[:300]
    if content_type == 36: return "引用回复", join2(texts)
    if content_type == 38: return "应用消息", join2(texts[:3])
    if content_type == 80: return "Markdown", texts[0] if texts else ""
    if content_type == 40: return "通话", ""
    if content_type == 1011: return "会议", join2(texts[:2])
    return f"类型{content_type}", join2(texts)

def main():
    if os.path.exists(IDX):
        os.remove(IDX)
    con = sqlite3.connect(IDX)
    con.execute("""CREATE TABLE messages(
        acc TEXT, cid TEXT, conv_name TEXT, conv_type TEXT,
        sender_id INTEGER, sender TEXT, ts INTEGER, kind TEXT, text TEXT)""")
    con.execute("""CREATE VIRTUAL TABLE fts USING fts5(text, sender, conv_name,
        content='messages', content_rowid='rowid', tokenize='trigram')""")
    con.execute("CREATE TABLE convs(acc TEXT, cid TEXT, name TEXT, ctype TEXT, n INTEGER, last INTEGER, PRIMARY KEY(acc,cid))")
    con.execute("CREATE TABLE users(acc TEXT, uid INTEGER, name TEXT, position TEXT, mobile TEXT, email TEXT, PRIMARY KEY(acc,uid))")

    ins = "INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?)"
    total = 0
    for acc in sorted(KEYS.keys()):
        dec = os.path.join(DEC, acc)
        if not os.path.isdir(dec):
            continue
        my_id = int(acc)
        users = {}
        try:
            u = sqlite3.connect(os.path.join(dec, "user.db"))
            u.row_factory = sqlite3.Row
            for r in u.execute("SELECT id,name,position,mobile,email FROM user_table"):
                users[r["id"]] = (r["name"] or f"用户{r['id']}", r["position"] or "", r["mobile"] or "", r["email"] or "")
            u.close()
        except Exception:
            pass
        for uid, v in users.items():
            con.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?,?,?)", (acc, uid, v[0], v[1], v[2], v[3]))

        convs = {}
        try:
            s = sqlite3.connect(os.path.join(dec, "session.db"))
            s.row_factory = sqlite3.Row
            for r in s.execute("SELECT id,name,roomname_remark,last_message_time FROM conversation_table"):
                convs[r["id"]] = [r["roomname_remark"] or r["name"] or r["id"], r["last_message_time"] or 0]
            s.close()
        except Exception:
            pass

        msgs = []
        m = sqlite3.connect(os.path.join(dec, "message.db"))
        m.row_factory = sqlite3.Row
        for table in ("message_table", "message_small_table", "kf_message_tableV1"):
            try:
                for r in m.execute(f"SELECT sender_id,conversation_id,content_type,send_time,content FROM {table}"):
                    msgs.append(dict(r))
            except Exception:
                pass
        m.close()
        msgs.sort(key=lambda x: (x["send_time"] or 0))

        by_conv = {}
        for i, msg in enumerate(msgs):
            by_conv.setdefault(msg["conversation_id"], []).append(msg)

        for cid, ms in by_conv.items():
            ctype = conv_type(cid)
            name = convs.get(cid, [cid, 0])[0]
            if ctype == "单聊":
                peer = peer_of_single(cid, my_id)
                if peer in users:
                    name = users[peer][0]
            for msg in ms:
                kind, text = render(msg["content_type"], msg["content"])
                sender = users.get(msg["sender_id"], (f"用户{msg['sender_id']}",))[0] \
                    if msg["sender_id"] != my_id else "我"
                cur = con.execute(ins, (acc, cid, name, ctype, msg["sender_id"], sender,
                                        msg["send_time"] or 0, kind, text))
                con.execute("INSERT INTO fts(rowid,text,sender,conv_name) VALUES(?,?,?,?)",
                            (cur.lastrowid, text, sender, name))
                total += 1
            con.execute("INSERT OR REPLACE INTO convs VALUES(?,?,?,?,?,?)",
                        (acc, cid, name, ctype, len(ms), max((m["send_time"] or 0) for m in ms)))
            # 注：last 从实际消息取 max(send_time)，不用 session.db 的 last_message_time——
            # 那个字段只在用户点开过会话时才更新，会导致左侧列表时间落后。
        print(f"[index] {acc}: {len(msgs)} msgs")

    con.commit()
    # integrity + optimize
    con.execute("INSERT INTO fts(fts) VALUES('optimize')")
    n = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    con.close()
    sz = os.path.getsize(IDX) / 1e6
    print(f"index built: {n} msgs, {sz:.1f} MB -> {IDX}")

if __name__ == "__main__":
    main()
