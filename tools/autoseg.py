# -*- coding: utf-8 -*-
"""Auto CJK segmentation for search queries.

Strategy (corpus-tuned, no external deps):
1. Load vocabulary (tools/cjk_vocab.json, word -> freq) built from the index itself.
2. Segment a CJK run by greedy longest-match; fall back to 2-char slide when a
   run is fully unknown (e.g. new names).
3. Latin/digit runs stay whole; punctuation splits.
"""
import json, os, re

_VOCAB = None
CJK_RUN = re.compile(r"[\u4e00-\u9fff]+")
SPLIT = re.compile(r"[\s,，。;；!？?！、\n\r\t]+")

def _load_vocab():
    global _VOCAB
    if _VOCAB is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cjk_vocab.json")
        if not os.path.exists(p):
            # 词典缺失（首次 clone / 数据重建后）：从本地索引自动生成
            try:
                import build_vocab
                build_vocab.main()
            except Exception:
                pass
        try:
            with open(p, encoding="utf-8") as f:
                _VOCAB = json.load(f)
        except Exception:
            _VOCAB = {}
    return _VOCAB

def _segment_run(run, vocab):
    """Greedy longest-match segmentation of one CJK run."""
    words, i = [], 0
    n = len(run)
    while i < n:
        matched = None
        for size in (4, 3, 2):
            if i + size <= n and run[i:i+size] in vocab:
                matched = run[i:i+size]
                break
        if matched:
            words.append(matched)
            i += len(matched)
        else:
            # unknown char: try 2-char slide; else emit single char (skipped by search)
            if i + 2 <= n and run[i:i+2] in vocab:
                words.append(run[i:i+2]); i += 2
            elif i + 3 <= n and run[i:i+3] in vocab:
                words.append(run[i:i+3]); i += 3
            else:
                i += 1  # skip unknown single char
    return words

def segment(q):
    """Split a raw query into search terms. Single CJK chars are dropped (unusable for search)."""
    vocab = _load_vocab()
    terms = []
    for part in SPLIT.split(q):
        if not part:
            continue
        if len(part) <= 6 and (part in vocab or not CJK_RUN.fullmatch(part)):
            # short latin/digit token or a known whole word: keep as-is
            terms.append(part)
            continue
        pos = 0
        for m in CJK_RUN.finditer(part):
            # latin/digit prefix
            if m.start() > pos:
                terms.append(part[pos:m.start()])
            run = m.group()
            if run in vocab and len(run) <= 4:
                terms.append(run)
            else:
                words = _segment_run(run, vocab)
                terms.extend(words or [run])
            pos = m.end()
        if pos < len(part):
            terms.append(part[pos:])
    # dedupe preserving order
    seen, out = set(), []
    for t in terms:
        if t and t not in seen:
            seen.add(t); out.append(t)
    return out
