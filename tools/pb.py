# -*- coding: utf-8 -*-
"""Precise protobuf text extraction for WeCom messages."""
import re

HEXRE = re.compile(r"^[0-9a-fA-F]{40,}$")

def _varint(buf, i):
    shift = 0; val = 0
    while i < len(buf):
        b = buf[i]; i += 1
        val |= (b & 0x7f) << shift
        if not b & 0x80:
            return val, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")

def parse_fields(buf):
    """Strictly parse one protobuf message. Returns [(field_no, wiretype, value)] or raises."""
    out = []
    i = 0
    n = len(buf)
    while i < n:
        tag, i = _varint(buf, i)
        fno, wt = tag >> 3, tag & 7
        if fno == 0:
            raise ValueError("field 0")
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            if i + 8 > n: raise ValueError("trunc fixed64")
            v = buf[i:i+8]; i += 8
        elif wt == 2:
            ln, i = _varint(buf, i)
            if i + ln > n: raise ValueError("trunc bytes")
            v = buf[i:i+ln]; i += ln
        elif wt == 5:
            if i + 4 > n: raise ValueError("trunc fixed32")
            v = buf[i:i+4]; i += 4
        else:
            raise ValueError(f"bad wiretype {wt}")
        out.append((fno, wt, v))
    return out

def _clean_text(s):
    # strip misaligned length-prefix artifact: single leading ASCII char before CJK/URL/dotted-number
    s = re.sub(r"^[\x21-\x7e](?=(?:https?://)|(?:\d+\.\d+\.\d+\.)|[\u4e00-\u9fff])", "", s)
    return s.strip()

def _is_printable_utf8(b):
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    for c in s:
        if c not in "\n\r\t" and ord(c) < 32:
            return None
        if 0xFFF0 <= ord(c) <= 0xFFFF:
            return None
    return s

def _strings_from_fields(fields, depth, out):
    if depth > 8:
        return
    for fno, wt, v in fields:
        if wt != 2:
            continue
        s = _is_printable_utf8(v)
        if s is not None:
            # could still be a nested message whose bytes happen to be valid UTF-8;
            # prefer nested parse when it fully parses AND contains >=1 wt2 field
            try:
                nested = parse_fields(v)
                has_nested = any(w == 2 for _, w, _ in nested)
                if has_nested and len(s) < 40 and not re.search(r"[\u4e00-\u9fff]", s):
                    _strings_from_fields(nested, depth + 1, out)
                    continue
            except ValueError:
                pass
            out.append(s)
        else:
            try:
                nested = parse_fields(v)
            except ValueError:
                continue
            _strings_from_fields(nested, depth + 1, out)

def extract_texts(content):
    """Extract readable strings from a message content blob, best-effort."""
    if content is None:
        return []
    if isinstance(content, str):
        return [content.strip()] if content.strip() else []
    if not isinstance(content, bytes):
        return [str(content)]
    try:
        fields = parse_fields(content)
    except ValueError:
        return []
    out = []
    _strings_from_fields(fields, 0, out)
    # drop hex blobs and pure-ascii single chars (artifacts)
    res = []
    for s in out:
        t = _clean_text(s)
        if not t or HEXRE.match(t):
            continue
        if len(t) == 1 and ord(t) < 128:
            continue
        res.append(t)
    # dedupe preserving order
    seen = set(); uniq = []
    for t in res:
        if t not in seen:
            seen.add(t); uniq.append(t)
    return uniq

def first_text(content):
    t = extract_texts(content)
    return t[0] if t else ""
