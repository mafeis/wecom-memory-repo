# -*- coding: utf-8 -*-
import sqlite3
print("sqlite:", sqlite3.sqlite_version)
con = sqlite3.connect(":memory:")
con.execute("CREATE VIRTUAL TABLE t USING fts5(x, tokenize='trigram')")
print("trigram OK")
