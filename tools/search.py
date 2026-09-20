# -*- coding: utf-8 -*-
"""Instant FTS search over WeCom messages. Usage:
   python search.py 关键词 [--n 20] [--conv 名称子串] [--acc 账号ID] [--kind 文本] [--since 2026-08-01] [--until 2026-09-01]
"""
import sys, os, json, sqlite3, datetime, argparse

IDX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "wxwork_data", "search_index.db")

def ts(t):
    return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "?"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--conv", default=None)
    ap.add_argument("--acc", default=None)
    ap.add_argument("--kind", default=None)
    ap.add_argument("--since", default=None)
    ap.add_argument("--until", default=None)
    a = ap.parse_args()

    con = sqlite3.connect(IDX)
    con.row_factory = sqlite3.Row
    q = """
      SELECT m.rowid, m.acc, m.cid, m.conv_name, m.conv_type, m.sender, m.ts, m.kind, m.text,
             snippet(fts, 0, '《', '》', '…', 12) AS snip
      FROM fts JOIN messages m ON m.rowid = fts.rowid
      WHERE fts MATCH ?
    """
    params = [a.query]
    if a.conv:
        q += " AND m.conv_name LIKE ?"
        params.append(f"%{a.conv}%")
    if a.acc:
        q += " AND m.acc = ?"
        params.append(a.acc)
    if a.kind:
        q += " AND m.kind = ?"
        params.append(a.kind)
    if a.since:
        t = int(datetime.datetime.strptime(a.since, "%Y-%m-%d").timestamp())
        q += " AND m.ts >= ?"; params.append(t)
    if a.until:
        t = int(datetime.datetime.strptime(a.until, "%Y-%m-%d").timestamp())
        q += " AND m.ts < ?"; params.append(t)
    q += " ORDER BY m.ts DESC LIMIT ?"
    params.append(a.n)

    rows = con.execute(q, params).fetchall()
    total = con.execute("SELECT COUNT(*) FROM fts WHERE fts MATCH ?", [a.query]).fetchone()[0]
    out = []
    for r in rows:
        out.append({
            "time": ts(r["ts"]), "conv": r["conv_name"], "type": r["conv_type"],
            "sender": r["sender"], "kind": r["kind"], "acc": r["acc"], "cid": r["cid"],
            "snippet": r["snip"], "full": r["text"],
        })
    print(json.dumps({"query": a.query, "total_matches": total, "shown": len(out), "results": out},
                     ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()
