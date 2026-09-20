# -*- coding: utf-8 -*-
"""Dump schema + row counts + samples for all decrypted DBs."""
import sqlite3, os, json, sys

DEC = r"__BASE__\wxwork_data\decrypted"

def dump_db(path):
    name = os.path.basename(path)
    print(f"\n{'='*60}\n{name}\n{'='*60}")
    try:
        con = sqlite3.connect(path)
        cur = con.cursor()
        cur.execute("SELECT type, name, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
        objs = cur.fetchall()
        for typ, tname, sql in objs:
            if typ != "table":
                continue
            try:
                n = cur.execute(f'SELECT COUNT(*) FROM "{tname}"').fetchone()[0]
            except Exception as e:
                n = f"ERR {e}"
            print(f"\n-- {tname} ({n} rows)")
            print(f"   {sql}")
            if isinstance(n, int) and n > 0:
                try:
                    cols = [c[1] for c in cur.execute(f'PRAGMA table_info("{tname}")').fetchall()]
                    rows = cur.execute(f'SELECT * FROM "{tname}" LIMIT 3').fetchall()
                    for r in rows:
                        disp = []
                        for v in r:
                            if isinstance(v, bytes):
                                disp.append(f"<{len(v)}B:{v[:24].hex()}>")
                            else:
                                s = str(v).replace("\n", "\\n")
                                disp.append(s[:150])
                        print("   >", disp)
                except Exception as e:
                    print("   sample ERR", e)
        con.close()
    except Exception as e:
        print("DB ERROR:", e)

if __name__ == "__main__":
    targets = sys.argv[1:] or sorted(os.listdir(DEC))
    for t in targets:
        p = os.path.join(DEC, t) if not os.path.isabs(t) else t
        if os.path.exists(p) and p.endswith(".db"):
            dump_db(p)
