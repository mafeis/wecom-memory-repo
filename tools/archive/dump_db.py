# -*- coding: utf-8 -*-
import sqlite3, sys

db = sys.argv[1] if len(sys.argv) > 1 else r"__BASE__\wxwork_data\raw\global_config.db"
con = sqlite3.connect(db)
cur = con.cursor()
cur.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view')")
objs = cur.fetchall()
print("objects:", objs)
for name, typ in objs:
    if typ != "table":
        continue
    try:
        cur.execute(f'SELECT COUNT(*) FROM "{name}"')
        n = cur.fetchone()[0]
        cur.execute(f'PRAGMA table_info("{name}")')
        cols = [c[1] for c in cur.fetchall()]
        print(f'\n== {name} ({n} rows): {cols}')
        cur.execute(f'SELECT * FROM "{name}" LIMIT 12')
        for row in cur.fetchall():
            disp = []
            for v in row:
                if isinstance(v, bytes):
                    disp.append(v.hex()[:80] + ("..." if len(v) > 40 else ""))
                else:
                    s = str(v)
                    disp.append(s[:120])
            print("   ", disp)
    except Exception as e:
        print(name, "ERR", e)
