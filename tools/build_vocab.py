# -*- coding: utf-8 -*-
"""Build a CJK vocabulary from the index itself (message text 2-4 char n-grams
with frequency >= threshold). Output: tools/cjk_vocab.json (word -> freq).

⚠️ 该词典从本地聊天语料生成，含个人高频词——已 gitignore，不要提交到任何仓库。
"""
import sqlite3, os, re, json, collections

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(BASE, "wxwork_data", "search_index.db")

def main():
    if not os.path.exists(IDX):
        print("index not found, skip vocab build:", IDX)
        return
    con = sqlite3.connect(IDX)
    texts = [r[0] for r in con.execute("SELECT text FROM messages WHERE text != ''")]
    con.close()

    CJK = re.compile(r"[\u4e00-\u9fff]{2,6}")
    cnt = collections.Counter()
    for t in texts:
        for run in CJK.findall(t):
            for size in (2, 3, 4):
                for i in range(len(run) - size + 1):
                    cnt[run[i:i+size]] += 1

    vocab = {}
    for w, c in cnt.items():
        minf = {2: 4, 3: 3, 4: 2}.get(len(w), 99)
        if c >= minf:
            vocab[w] = c
    # 2-char words appearing >= 2 times also count for a small corpus
    for w, c in cnt.items():
        if len(w) == 2 and c >= 2 and w not in vocab:
            vocab[w] = c

    out = os.path.join(BASE, "tools", "cjk_vocab.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(vocab, f, ensure_ascii=False)
    print(f"vocab: {len(vocab)} words -> {out}")

if __name__ == "__main__":
    main()
