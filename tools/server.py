# -*- coding: utf-8 -*-
"""常驻本地搜索服务: http://127.0.0.1:8765"""
import os, re, sqlite3, datetime, json
from flask import Flask, request, jsonify, Response, send_file

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(BASE_DIR, "wxwork_data", "search_index.db")
app = Flask(__name__)

# ---------- 本地媒体缓存索引（文件按文件名、图片按 md5 前缀） ----------
WX_DOCS = os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "WXWork")
_MEDIA_LOCK = None  # built lazily in main thread; rebuild on demand

def _build_media_index():
    """Map cached media: images by md5-prefix -> abs path; files by name -> [abs paths]."""
    imgs, files = {}, {}
    for acc in os.listdir(WX_DOCS) if os.path.isdir(WX_DOCS) else []:
        if not acc.isdigit():
            continue
        for kind, store in (("Image", imgs), ("File", files)):
            root = os.path.join(WX_DOCS, acc, "Cache", kind)
            if not os.path.isdir(root):
                continue
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    m = re.match(r"([0-9a-f]{32})", fn) if kind == "Image" else None
                    if m:
                        imgs.setdefault((acc, m.group(1)), full)
                    else:
                        files.setdefault((acc, fn), full)
    return imgs, files

_MEDIA = {"imgs": {}, "files": {}, "built": 0}

def media_index():
    if not _MEDIA["built"]:
        _MEDIA["imgs"], _MEDIA["files"] = _build_media_index()
        _MEDIA["built"] = 1
    return _MEDIA["imgs"], _MEDIA["files"]

def ts_str(t, full=False):
    if not t:
        return ""
    f = "%Y-%m-%d %H:%M:%S" if full else "%Y-%m-%d %H:%M"
    return datetime.datetime.fromtimestamp(t).strftime(f)

def db():
    con = sqlite3.connect(f"file:{IDX}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con

def _esc_fts(s):
    """Quote a term for FTS5 MATCH (phrase query, avoids syntax errors)."""
    return '"' + s.replace('"', '""') + '"'

def _row_to_result(r, imgs, files):
    return {"acc": r["acc"], "cid": r["cid"], "conv": r["conv_name"], "ctype": r["conv_type"],
            "sender": r["sender"], "ts": r["ts"], "time": ts_str(r["ts"], True), "kind": r["kind"],
            "snippet": r["snip"] if "snip" in r.keys() and r["snip"] else r["text"],
            "text": r["text"], "local": _local_media(r["acc"], r["kind"], r["text"], imgs, files)}

@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"results": [], "total": 0})
    conv = request.args.get("conv", "").strip()
    acc = request.args.get("acc", "").strip()
    kind = request.args.get("kind", "").strip()
    since = request.args.get("since", "").strip()
    until = request.args.get("until", "").strip()
    n = min(int(request.args.get("n", 50)), 300)
    # ---- 自动分词：连写长查询按词典切词；空格拆词直接尊重；短词走 LIKE ----
    from autoseg import segment
    if re.search(r"[\s,，]", q):
        terms = [t for t in re.split(r"[\s,，]+", q) if t]      # 显式分词，直接尊重
    else:
        terms = segment(q) or [q]                               # 连写查询自动切词
    fts_terms = [t for t in terms if len(t) >= 3]
    like_terms = [t for t in terms if 0 < len(t) < 3]
    if not fts_terms and not like_terms:
        fts_terms = [q]

    filters, fparams = [], []
    if acc:
        filters.append("m.acc = ?"); fparams.append(acc)
    if conv:
        filters.append("m.conv_name LIKE ?"); fparams.append(f"%{conv}%")
    if kind:
        filters.append("m.kind = ?"); fparams.append(kind)
    if since:
        try:
            filters.append("m.ts >= ?"); fparams.append(int(datetime.datetime.strptime(since, "%Y-%m-%d").timestamp()))
        except ValueError:
            pass
    if until:
        try:
            filters.append("m.ts < ?"); fparams.append(int(datetime.datetime.strptime(until, "%Y-%m-%d").timestamp()))
        except ValueError:
            pass
    fsql = (" AND " + " AND ".join(filters)) if filters else ""

    con = db()
    rows = []
    if fts_terms:
        match = " AND ".join("fts MATCH ?" for _ in fts_terms)
        sql = f"""SELECT m.rowid, m.acc, m.cid, m.conv_name, m.conv_type, m.sender, m.ts, m.kind, m.text,
                         snippet(fts, 0, '「', '」', '…', 14) AS snip
                  FROM fts JOIN messages m ON m.rowid = fts.rowid WHERE {match}{fsql}
                  ORDER BY m.ts DESC LIMIT ?"""
        try:
            rows = con.execute(sql, [_esc_fts(t) for t in fts_terms] + fparams + [n]).fetchall()
        except Exception:
            fts_terms = []  # FTS 语法异常时整体退回 LIKE
    if like_terms or not fts_terms:
        use_terms = like_terms if like_terms else [t for t in terms if t]
        if use_terms:
            like_sql = " AND ".join("m.text LIKE ?" for _ in use_terms)
            likep = [f"%{t}%" for t in use_terms]
            sql2 = f"""SELECT m.rowid, m.acc, m.cid, m.conv_name, m.conv_type, m.sender, m.ts, m.kind, m.text,
                              NULL AS snip
                       FROM messages m WHERE {like_sql}{fsql}
                       ORDER BY m.ts DESC LIMIT ?"""
            rows2 = con.execute(sql2, likep + fparams + [n]).fetchall()
            seen = {(r["acc"], r["cid"], r["ts"], r["text"]) for r in rows}
            rows = rows + [r for r in rows2 if (r["acc"], r["cid"], r["ts"], r["text"]) not in seen]
    con.close()
    rows.sort(key=lambda r: r["ts"], reverse=True)
    rows = rows[:n]
    imgs, files = media_index()
    results = [_row_to_result(r, imgs, files) for r in rows]
    total = len(results)
    return jsonify({"total": total, "results": results,
                    "terms": terms})

@app.route("/api/convs")
def api_convs():
    con = db()
    rows = con.execute("SELECT acc,cid,name,ctype,n,last FROM convs WHERE n>0 ORDER BY last DESC").fetchall()
    users = {}
    for r in con.execute("SELECT acc,uid,name FROM users"):
        users.setdefault(r["acc"], {})[r["uid"]] = r["name"]
    con.close()
    return jsonify([{"acc": r["acc"], "cid": r["cid"], "name": r["name"], "type": r["ctype"],
                     "n": r["n"], "last": r["last"]} for r in rows])

def _local_media(acc, kind, text, imgs, files):
    """Find a local cached file for an image/file message. Returns abs path or ''."""
    if kind == "图片":
        m = re.search(r"([0-9a-f]{32})", text or "")
        if m:
            p = imgs.get((acc, m.group(1)))
            if p:
                return p
        fn = re.search(r"[\w.-]+\.(?:png|jpe?g|gif|bmp|webp)", text or "", re.I)
        if fn:
            p = files.get((acc, fn.group(0)))
            if p:
                return p
    elif kind == "文件":
        for t in re.split(r"\s+", text or ""):
            t = t.strip()
            if re.search(r"\.[A-Za-z0-9]{1,8}$", t) and not t.startswith("http"):
                p = files.get((acc, t))
                if p:
                    return p
    return ""

@app.route("/media")
def api_media():
    """Serve a local cached media file (read-only)."""
    p = request.args.get("p", "")
    real = os.path.realpath(p)
    if not real.startswith(os.path.realpath(WX_DOCS)):
        return jsonify({"error": "path outside WXWork profile"}), 403
    if not os.path.isfile(real):
        return jsonify({"error": "not found"}), 404
    return send_file(real)

@app.route("/api/conv")
def api_conv():
    acc = request.args.get("acc", "")
    cid = request.args.get("cid", "")
    around = request.args.get("around", type=int)
    limit = min(int(request.args.get("limit", 200)), 1000)
    span = request.args.get("span", type=int)  # 命中上下文模式：前后各 span 条消息
    con = db()
    if around and span is not None:
        # 取命中前后各 span 条（按条数而非秒数），合并后按时间升序
        sql_before = """SELECT sender,ts,kind,text FROM messages
                        WHERE acc=? AND cid=? AND ts<=? ORDER BY ts DESC LIMIT ?"""
        sql_after = """SELECT sender,ts,kind,text FROM messages
                       WHERE acc=? AND cid=? AND ts>? ORDER BY ts ASC LIMIT ?"""
        before = con.execute(sql_before, [acc, cid, around, span + 1]).fetchall()
        after = con.execute(sql_after, [acc, cid, around, span]).fetchall()
        con.close()
        rows = sorted(list(before) + list(after), key=lambda x: x["ts"] or 0)
        imgs, files = media_index()
        out = []
        for r in rows:
            out.append({"sender": r["sender"], "ts": r["ts"], "time": ts_str(r["ts"], True),
                        "kind": r["kind"], "text": r["text"],
                        "hit": (r["ts"] or 0) == around,
                        "local": _local_media(acc, r["kind"], r["text"], imgs, files)})
        return jsonify(out)
    sql = "SELECT sender,ts,kind,text FROM messages WHERE acc=? AND cid=?"
    params = [acc, cid]
    order = request.args.get("order", "desc")
    sql += " ORDER BY ts " + ("ASC" if order == "asc" else "DESC") + " LIMIT ?"
    params.append(limit)
    rows = con.execute(sql, params).fetchall()
    con.close()
    imgs, files = media_index()
    out = []
    for r in rows:
        out.append({"sender": r["sender"], "ts": r["ts"], "time": ts_str(r["ts"], True),
                    "kind": r["kind"], "text": r["text"],
                    "local": _local_media(acc, r["kind"], r["text"], imgs, files)})
    return jsonify(out)

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>企微速查</title>
<style>
:root{--bg:#f4f6fa;--card:#fff;--line:#e6eaf1;--txt:#1f2937;--dim:#6b7280;--dim2:#94a3b8;--accent:#2563eb;--hit:#fef3c7;--hdr:64px}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%;height:100%}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei","PingFang SC",sans-serif;background:var(--bg);color:var(--txt);font-size:14px;line-height:1.7;height:100vh;overflow:hidden;display:flex;flex-direction:column}
/* ---- 细滚动条：全站唯一滚动条风格 ---- */
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cdd5e0;border-radius:99px;border:2px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:#b3bfd0;border:2px solid transparent;background-clip:padding-box}
*{scrollbar-width:thin;scrollbar-color:#cdd5e0 transparent}
/* ---- 顶栏 ---- */
header{background:var(--card);border-bottom:1px solid var(--line);padding:10px 24px;display:flex;gap:16px;align-items:center;flex-wrap:wrap;flex-shrink:0;box-shadow:0 1px 2px rgba(0,0,0,.03)}
h1{font-size:17px;white-space:nowrap;letter-spacing:.01em}h1 b{color:var(--accent)}
.sw{flex:1;min-width:240px;display:flex;gap:8px}
#q{flex:1;padding:8px 14px;border:1px solid var(--line);border-radius:8px;font-size:14px;outline:none;transition:border-color .15s, box-shadow .15s;background:var(--bg)}
#q:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(37,99,235,.08);background:#fff}
button{padding:8px 18px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.9}
button[disabled]{opacity:.6;cursor:default}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filters input,.filters select{padding:6px 10px;border:1px solid var(--line);border-radius:7px;font-size:12.5px;background:#fff;color:var(--txt);outline:none}
.filters input:focus,.filters select:focus{border-color:var(--accent)}
/* ---- 主布局：sidebar 独立滚动 + main 独立滚动，页面本身不滚 ---- */
.layout{display:grid;grid-template-columns:272px 1fr;flex:1;min-height:0}
aside{background:var(--card);border-right:1px solid var(--line);overflow-y:auto;overflow-x:hidden}
.side-h{padding:12px 16px 6px;font-size:11.5px;color:var(--dim);font-weight:600;letter-spacing:.05em;text-transform:uppercase}
.conv{padding:9px 16px;cursor:pointer;border-left:3px solid transparent;display:flex;justify-content:space-between;gap:8px;font-size:13.5px;transition:background .12s}
.conv:hover{background:var(--bg)}.conv.act{border-left-color:var(--accent);background:#eff6ff}
.conv .n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conv .c{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap}
main{overflow-y:auto;overflow-x:hidden;padding:20px 32px 60px;max-width:1060px;width:100%;margin:0 auto;scroll-behavior:smooth}
.tip{color:var(--dim);font-size:12.5px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.05);transition:border-color .15s, box-shadow .15s}
.card .hd{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--dim);margin-bottom:5px;flex-wrap:wrap}
.card .hd b{color:var(--txt)}
.card .tx{white-space:pre-wrap;word-break:break-word}
.card.click{cursor:pointer}.card.click:hover{border-color:var(--accent);box-shadow:0 2px 8px rgba(37,99,235,.08)}
mark{background:var(--hit);border-radius:3px;padding:0 2px}
.msg{display:flex;align-items:baseline;gap:8px;padding:5px 10px;border-radius:6px;margin:1px 0}
.msg:hover{background:var(--bg)}
.msg .h{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap;flex-shrink:0}
.msg .who{font-weight:600;margin-right:2px;flex-shrink:0}
.msg .bd{min-width:0;word-break:break-word;white-space:pre-wrap}
/* ---- 聊天气泡视图 ---- */
.bwrap{display:flex;gap:10px;margin:6px 0;align-items:flex-start}
.bwrap.mine{flex-direction:row-reverse}
.avatar{width:38px;height:38px;border-radius:8px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#fff;user-select:none}
.bcol{display:flex;flex-direction:column;max-width:70%;min-width:0}
.bwrap.mine .bcol{align-items:flex-end}
.bwho{font-size:12px;color:var(--dim);margin:0 4px 2px}
.bubble{padding:8px 12px;border-radius:10px;background:var(--card);border:1px solid var(--line);box-shadow:0 1px 2px rgba(0,0,0,.04);word-break:break-word;white-space:pre-wrap;max-width:100%}
.bwrap.mine .bubble{background:#d6e4ff;border-color:#bcd0f7}
.bubble .thumb{max-width:240px;max-height:170px;display:block}
.bubble .flink{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom}
.bmeta{font-size:11.5px;color:var(--dim2);margin:2px 4px 0;font-variant-numeric:tabular-nums}
.bwrap.hit .bubble{border-color:var(--accent);box-shadow:0 0 0 3px rgba(37,99,235,.25);transition:box-shadow .3s}
.bwrap.hit .bmeta{color:var(--accent);font-weight:600}
.back-link{cursor:pointer;color:var(--accent);white-space:nowrap}
.back-link:hover{text-decoration:underline}
.thumb{display:inline-block;vertical-align:top;margin:2px 0;max-width:260px;max-height:180px;border-radius:8px;border:1px solid var(--line);cursor:zoom-in;transition:box-shadow .15s}
.thumb:hover{box-shadow:0 2px 10px rgba(0,0,0,.18)}
.flink{color:var(--accent);text-decoration:none;border-bottom:1px dashed rgba(37,99,235,.5);cursor:pointer}
.flink:hover{border-bottom-style:solid}
.flink.miss{color:var(--dim2);border-bottom-color:transparent;cursor:default}
.imgmiss{font-size:12px;color:var(--dim2);font-style:italic}
.lightbox{position:fixed;inset:0;background:rgba(15,23,42,.82);display:flex;align-items:center;justify-content:center;z-index:50;cursor:zoom-out}
.lightbox img{max-width:92vw;max-height:92vh;border-radius:8px;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.msg.mine .who{color:var(--accent)}
.kindtag{font-size:11.5px;color:var(--accent);background:rgba(37,99,235,.09);border-radius:99px;padding:0 8px;margin-right:2px;white-space:nowrap}
.day{margin:18px 0 8px;font-size:12.5px;color:var(--dim);font-weight:600;border-left:4px solid var(--accent);padding-left:10px;font-variant-numeric:tabular-nums}
.ctx-tip{font-size:12.5px;color:var(--dim);background:rgba(37,99,235,.07);border:1px dashed rgba(37,99,235,.35);border-radius:8px;padding:6px 12px;margin:12px 0}
.ctx-link{cursor:pointer;color:var(--accent);white-space:nowrap}
.ctx-link:hover{text-decoration:underline}
/* ---- 会话视图顶栏：粘在主区滚动容器顶部，不随消息滚走 ---- */
.conv-top{position:sticky;top:0;z-index:4;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.conv-top .hd{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--dim);flex-wrap:wrap}
.conv-top .hd b{color:var(--txt);font-size:14px}
.conv-top .hd-right{margin-left:auto;display:flex;gap:12px}
.conv-top .ctx-tip{margin:8px 0 0;padding:4px 10px}
@media (max-width:760px){body{overflow:auto}.layout{grid-template-columns:1fr}aside{max-height:200px;position:static;border-right:none;border-bottom:1px solid var(--line)}main{overflow:visible;padding:14px}header{padding:10px 14px}.msg{flex-wrap:wrap;gap:4px 8px}.msg .h{display:none}.bcol{max-width:82%}}
</style>
</head>
<body>
<header>
  <h1>企微<b>速查</b></h1>
  <div class="sw"><input id="q" placeholder="搜索聊天记录、邮件、文件名… 支持连写自动分词，空格分隔多词" autofocus><button onclick="dosearch()">搜索</button></div>
  <div class="filters">
    <select id="facc"><option value="">全部账号</option></select>
    <input id="fconv" placeholder="限定会话">
    <select id="fkind"><option value="">全部类型</option><option>文本</option><option>邮件</option><option>文件</option><option>图片</option><option>文档</option><option>引用回复</option><option>Markdown</option><option>卡片</option></select>
    <input id="fsince" placeholder="开始日期" size="8">
    <input id="funtil" placeholder="结束日期" size="8">
    <button style="background:#059669" onclick="doRefresh()" id="refreshBtn">↻ 刷新数据</button>
  </div>
</header>
<div class="layout">
  <aside id="side"></aside>
  <main id="main"><div class="tip">输入关键词回车搜索；点击左侧会话浏览完整记录；点击结果卡片查看上下文。</div></main>
</div>
<script>
let CONVS = [];
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function hl(s,q){
  const e = esc(s);
  if(!q) return e;
  try{ return e.split(new RegExp('('+q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi'))
    .map(p=>p.toLowerCase()===q.toLowerCase()?'<mark>'+p+'</mark>':p).join(''); }catch(_){return e}
}
const WD = ['日','一','二','三','四','五','六'];
function fmtT(t){ if(!t) return ''; const d=new Date(t*1000),p=n=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' 周'+WD[d.getDay()]+' '+p(d.getHours())+':'+p(d.getMinutes()); }
function fmtD(t){ if(!t) return ''; const d=new Date(t*1000),p=n=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' 周'+WD[d.getDay()]; }
function fmtSide(t){ if(!t) return ''; const d=new Date(t*1000),now=new Date(),p=n=>String(n).padStart(2,'0');
  const md = (d.getMonth()+1)+'/'+d.getDate();
  const sameDay = x => x.getFullYear()===d.getFullYear()&&x.getMonth()===d.getMonth()&&x.getDate()===d.getDate();
  if(sameDay(now)) return '今天 '+p(d.getHours())+':'+p(d.getMinutes());
  const yd = new Date(now); yd.setDate(now.getDate()-1);
  if(sameDay(yd)) return '昨天 '+p(d.getHours())+':'+p(d.getMinutes());
  if(d.getFullYear()===now.getFullYear()) return md;
  return d.getFullYear()+'/'+md; }
function mediaBody(x, q){
  // returns body HTML for a message, inlining images / linking files when local copy exists
  const txt = x.text || '';
  if(x.kind === '图片'){
    if(x.local){
      const u = '/media?p=' + encodeURIComponent(x.local);
      const cap = txt.replace(/[\w.-]*[0-9a-f]{32}[\w.-]*/g,'').trim();
      return (cap ? '<span class="bd">'+hl(cap, q)+'</span>' : '')
        + '<br><img class="thumb" loading="lazy" data-src="'+u+'" onclick="lightbox(this.dataset ? this.dataset.src : this.src)" onerror="this.outerHTML=\'<span class=imgmiss>[图片缓存已失效]</span>\'">';
    }
    const cap = txt.replace(/[\w.-]*[0-9a-f]{32}[\w.-]*/g,'').trim();
    return '<span class="bd">'+(cap ? hl(cap, q) : '[图片，本地缓存已清理]')+'</span>';
  }
  if(x.kind === '文件'){
    const m = txt.match(/[\w\u4e00-\u9fff\u3000-\u303f.-]+\.[A-Za-z0-9]{1,8}/);
    if(m && x.local){
      const rest = txt.replace(m[0], '').trim();
      return '<span class="bd">📄 <a class="flink" href="/media?p='+encodeURIComponent(x.local)+'" target="_blank">'+esc(m[0])+'</a>'
        + (rest ? ' · '+hl(rest, q) : '')+'</span>';
    }
    if(m){
      return '<span class="bd">📄 <span class="flink miss" title="本地缓存已被企业微信清理">'+esc(m[0])+'</span>'
        + (txt.replace(m[0],'').trim() ? ' · '+hl(txt.replace(m[0],'').trim(), q) : '')+'</span>';
    }
  }
  return '<span class="bd">'+hl(txt, q)+'</span>';
}
function lightbox(src){
  const d = document.createElement('div');
  d.className = 'lightbox';
  d.innerHTML = '<img src="'+src+'">';
  d.onclick = () => d.remove();
  document.body.appendChild(d);
}
// ---- 聊天气泡渲染（微信式：我=右侧蓝气泡，对方=左侧白气泡） ----
const AV_COLORS = ['#2563eb','#059669','#d97706','#7c3aed','#dc2626','#0891b2','#4f46e5','#b45309'];
function avColor(name){ let h=0; for(const ch of name) h=(h*31+ch.charCodeAt(0))>>>0; return AV_COLORS[h%AV_COLORS.length]; }
function bubbleHTML(x, qkw, peerName){
  const mine = x.sender === '我';
  const name = mine ? '我' : (x.sender || peerName || '对方');
  const hm = x.ts ? new Date(x.ts*1000).toTimeString().slice(0,5) : '--:--';
  const body = mediaBody(x, qkw);
  const tag = x.kind && x.kind !== '文本' ? '<span class="kindtag">'+esc(x.kind)+'</span>' : '';
  const hitCls = x.hit ? ' hit' : '';
  return '<div class="bwrap'+(mine?' mine':'')+hitCls+'" data-ts="'+(x.ts||0)+'">'
    + '<div class="avatar" style="background:'+avColor(name)+'">'+esc(name.slice(0,1))+'</div>'
    + '<div class="bcol">'
    + '<div class="bwho">'+esc(name)+'</div>'
    + '<div class="bubble">'+tag+body+'</div>'
    + '<div class="bmeta">'+esc(hm)+(x.hit?' · ⯐ 命中':'')+'</div>'
    + '</div></div>';
}
// ---- 增量渲染：先画 80 条，滚动接近底部再补，避免一次 400 条卡顿 ----
const BATCH = 80;
let IO = null;  // IntersectionObserver for batch sentinel + lazy images
function observeBatch(m, fn){
  // render next batch when sentinel visible
  IO = new IntersectionObserver(es => {
    if(es.some(e => e.isIntersecting)){ IO.disconnect(); IO = null; fn(); }
  }, {rootMargin: '600px'});
  const s = m.querySelector('#batch-sentinel');
  if(s) IO.observe(s);
}
function nextBatch(list, dayState, qkw, m, done){
  // append BATCH messages (grouped by day) and re-arm sentinel
  let h = '', n = 0;
  while(dayState.i < list.length && n < BATCH){
    const x = list[dayState.i];
    const d = fmtD(x.ts) || '未知';
    if(d !== dayState.day){ dayState.day = d; h += '<div class="day">'+d+'</div>'; }
    h += bubbleHTML(x, qkw, '');
    dayState.i++; n++;
  }
  m.querySelector('#batch-target').insertAdjacentHTML('beforeend', h);
  lazyImgs(m);
  if(dayState.i < list.length){
    if(!m.querySelector('#batch-sentinel')){
      m.querySelector('#batch-target').insertAdjacentHTML('afterend', '<div id="batch-sentinel" style="height:1px"></div>');
    }
    observeBatch(m, () => nextBatch(list, dayState, qkw, m, done));
  } else {
    const s = m.querySelector('#batch-sentinel'); if(s) s.remove();
    if(done) done();
  }
}
// ---- 图片懒加载：进入视口前 300px 才真正加载 ----
let IMGIO = null;
function lazyImgs(scope){
  if(!('IntersectionObserver' in window)){
    scope.querySelectorAll('img[data-src]').forEach(i => { i.src = i.dataset.src; });
    return;
  }
  if(!IMGIO){
    IMGIO = new IntersectionObserver(es => {
      es.forEach(e => {
        if(e.isIntersecting){
          e.target.src = e.target.dataset.src;
          e.target.removeAttribute('data-src');
          IMGIO.unobserve(e.target);
        }
      });
    }, {rootMargin: '300px'});
  }
  scope.querySelectorAll('img[data-src]').forEach(i => IMGIO.observe(i));
}
function renderConvPage(m, msgs, qkw){
  // msgs: desc or asc; display order = as given (desc=newest first, asc=oldest first)
  const asc = msgs.length > 1 && msgs[0].ts <= msgs[msgs.length-1].ts;
  const list = asc ? msgs : [...msgs].reverse(); // internal order oldest->newest
  m.querySelector('#batch-target').innerHTML = '';
  const dayState = {i: 0, day: ''};
  if(!asc){
    // newest-first view: reverse day separator order by rendering from the end
    // we render in display order: newest first. Reverse list so first batch = newest.
    list.reverse();
  }
  nextBatch(list, dayState, qkw, m);
}
function relTime(t){ if(!t) return ''; const s=Math.floor(Date.now()/1000-t);
  if(s<300) return '刚刚';
  if(s<3600) return Math.floor(s/60)+' 分钟前';
  if(s<86400) return Math.floor(s/3600)+' 小时前';
  if(s<86400*7) return Math.floor(s/86400)+' 天前';
  return fmtD(t); }
async function loadSide(sel){
  const r = await fetch('/api/convs'); CONVS = await r.json();
  fillAccSelect();
  renderSide(sel);
}
function fillAccSelect(){
  const sel = document.getElementById('facc');
  const cur = sel.value;
  const accs = [...new Set(CONVS.map(c => c.acc))].sort();
  sel.innerHTML = '<option value="">全部账号</option>' + accs.map(a => '<option value="'+esc(a)+'">'+esc(a)+'</option>').join('');
  if(accs.includes(cur)) sel.value = cur;
}
function renderSide(filter){
  const el = document.getElementById('side');
  const accSel = document.getElementById('facc').value;
  let h = '';
  const by = {};
  CONVS.forEach(c => {
    if(accSel && c.acc !== accSel) return;
    if(filter && !c.name.toLowerCase().includes(filter.toLowerCase())) return;
    (by[c.acc] = by[c.acc]||[]).push(c);
  });
  Object.keys(by).forEach(acc => {
    h += '<div class="side-h">'+esc(acc)+'</div>';
    by[acc].forEach(c => {
      h += '<div class="conv" data-acc="'+esc(c.acc)+'" data-cid="'+esc(c.cid)+'">'
        + '<span class="n">'+esc(c.name)+'</span><span class="c">'+esc(fmtSide(c.last))+' · '+c.n+'</span></div>';
    });
  });
  el.innerHTML = h || '<div class="conv">无会话</div>';
  el.querySelectorAll('.conv').forEach(e => e.onclick = () => showConvDesc(e.dataset.acc, e.dataset.cid, e));
}
async function dosearch(){
  const q = document.getElementById('q').value.trim();
  const acc = document.getElementById('facc').value;
  const conv = document.getElementById('fconv').value.trim();
  const kind = document.getElementById('fkind').value;
  const since = document.getElementById('fsince').value.trim();
  const until = document.getElementById('funtil').value.trim();
  if(!q){ return; }
  const p = new URLSearchParams({q, n:120});
  if(acc) p.set('acc', acc);
  if(conv) p.set('conv', conv); if(kind) p.set('kind', kind);
  if(since) p.set('since', since); if(until) p.set('until', until);
  const r = await fetch('/api/search?'+p); const d = await r.json();
  renderSide(conv);
  const m = document.getElementById('main');
  const termTags = (d.terms || []).map(t => '<span class="kindtag">'+esc(t)+'</span>').join(' ');
  let h = '<div class="tip">已分词：'+termTags+' — 共 <b>'+d.total+'</b> 条匹配，显示最近 '+d.results.length+' 条。点击卡片查看上下文。</div>';
  d.results.forEach(x => {
    h += '<div class="card click" data-acc="'+esc(x.acc)+'" data-cid="'+esc(x.cid)+'" data-ts="'+x.ts+'">'
      + '<div class="hd"><b>'+esc(x.conv)+'</b>'
      + '<span class="kindtag">'+esc(x.kind)+'</span>'
      + '<span>'+esc(x.ctype)+' · '+esc(x.sender)+'</span>'
      + '<span style="margin-left:auto;font-variant-numeric:tabular-nums" title="'+esc(x.time)+'">'+esc(relTime(x.ts))+' · '+esc(x.time)+'</span></div>'
      + '<div class="tx">'+hl(x.text, q)+(x.local && x.kind==='图片' ? ' <img class="thumb" loading="lazy" style="max-height:120px" src="/media?p='+encodeURIComponent(x.local)+'" onclick="event.stopPropagation();lightbox(this.src)" onerror="this.remove()">' : '')+'</div></div>';
  });
  if(!d.results.length) h += '<div class="tip" style="padding:40px;text-align:center">没有匹配结果</div>';
  m.innerHTML = h;
  m.querySelectorAll('.card.click').forEach(e => e.onclick = () => showConvFromSearch(e.dataset.acc, e.dataset.cid, parseInt(e.dataset.ts)));
  m.scrollTop = 0;
}
// 记住搜索上下文：从会话视图可以一键返回
let lastSearchHTML = null;
async function showConvFromSearch(acc, cid, ts){
  lastSearchHTML = document.getElementById('main').innerHTML;
  showConv(acc, cid, null, ts);
}
function backToSearch(){
  if(!lastSearchHTML) return;
  const m = document.getElementById('main');
  m.innerHTML = lastSearchHTML;
  lastSearchHTML = null;
  m.scrollTop = 0;
  // 重新绑定卡片点击
  m.querySelectorAll('.card.click').forEach(e => e.onclick = () => showConvFromSearch(e.dataset.acc, e.dataset.cid, parseInt(e.dataset.ts)));
}
async function showConv(acc, cid, el, around){
  renderSide(document.getElementById('fconv').value.trim());
  document.querySelectorAll('.conv').forEach(e => e.classList.toggle('act', e.dataset.acc===acc && e.dataset.cid===cid));
  const p = new URLSearchParams({acc, cid, limit: 400});
  if(around){
    // 命中上下文模式：后端直接返回命中前后各 10 条 + 命中标记
    p.set('around', around); p.set('span', 10);
  }
  const r = await fetch('/api/conv?'+p); const msgs = await r.json();
  const hitTs = around ? (msgs.find(x => x.hit)?.ts ?? around) : null;
  const info = CONVS.find(c => c.acc===acc && c.cid===cid) || {name: cid, n: '?', type: ''};
  const m = document.getElementById('main');
  // 顶栏固定：不随消息列表滚动
  let h = '<div class="conv-top">'
    + '<div class="hd"><b>'+esc(info.name)+'</b>'
    + '<span>'+esc(info.type||'')+'</span><span>'+msgs.length+' 条</span>'
    + '<span class="hd-right">'
    + (lastSearchHTML ? '<span class="back-link" onclick="backToSearch()">← 返回搜索结果</span>' : '')
    + '<span class="ctx-link" onclick="showConvFull(\''+esc(acc)+'\',\''+esc(cid)+'\')">↺ 查看完整记录</span>'
    + '</span></div>'
    + (around ? '<div class="ctx-tip">⌛ 命中消息的上下文（前后各 10 条）· 蓝圈为命中消息</div>' : '')
    + '</div>';
  h += '<div id="batch-target"></div>';
  m.innerHTML = h;
  m.scrollTop = 0;
  renderConvPage(m, msgs, document.getElementById('q').value.trim());
  if(hitTs){
    // 命中消息固定在首批中（最多 21 条），渲染后直接滚动定位
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const el = m.querySelector('.bwrap[data-ts="'+hitTs+'"]');
      if(el) m.scrollTop = Math.max(0, el.offsetTop - m.offsetTop - m.clientHeight/2 + el.offsetHeight/2);
    }));
  }
}
// 完整记录视图（从命中上下文一键切换；清除返回搜索状态）
function showConvFull(acc, cid){
  lastSearchHTML = null;
  showConvDesc(acc, cid);
}
// 最新在上的会话视图（默认；点击左侧会话进入）
async function showConvDesc(acc, cid, el){
  renderSide(document.getElementById('fconv').value.trim());
  document.querySelectorAll('.conv').forEach(e => e.classList.toggle('act', e.dataset.acc===acc && e.dataset.cid===cid));
  const r = await fetch('/api/conv?acc='+encodeURIComponent(acc)+'&cid='+encodeURIComponent(cid)+'&limit=400');
  const msgs = await r.json();
  const info = CONVS.find(c => c.acc===acc && c.cid===cid) || {name: cid, n: '?', type: '', last: 0};
  const m = document.getElementById('main');
  let h = '<div class="conv-top"><div class="hd"><b>'+esc(info.name)+'</b>'
    + '<span>'+esc(info.type||'')+'</span><span>'+msgs.length+' 条</span>'
    + '<span class="hd-right"><span class="ctx-link" onclick="showConvAsc(\''+esc(acc)+'\',\''+esc(cid)+'\')">⬆ 从旧到新看</span></span></div>'
    + '<div class="ctx-tip">最新在上 · 顶部是最新消息</div></div>';
  h += '<div id="batch-target"></div>';
  m.innerHTML = h;
  m.scrollTop = 0;
  renderConvPage(m, msgs, document.getElementById('q').value.trim());
}
// 从旧到新（升序取最近 400 条）
async function showConvAsc(acc, cid){
  renderSide(document.getElementById('fconv').value.trim());
  document.querySelectorAll('.conv').forEach(e => e.classList.toggle('act', e.dataset.acc===acc && e.dataset.cid===cid));
  const r = await fetch('/api/conv?acc='+encodeURIComponent(acc)+'&cid='+encodeURIComponent(cid)+'&limit=400&order=asc');
  const msgs = await r.json();
  const info = CONVS.find(c => c.acc===acc && c.cid===cid) || {name: cid, n: '?', type: ''};
  const m = document.getElementById('main');
  let h = '<div class="conv-top"><div class="hd"><b>'+esc(info.name)+'</b>'
    + '<span>'+esc(info.type||'')+'</span><span>'+msgs.length+' 条</span>'
    + '<span class="hd-right"><span class="ctx-link" onclick="showConvDesc(\''+esc(acc)+'\',\''+esc(cid)+'\')">⬇ 最新在上</span></span></div></div>';
  h += '<div id="batch-target"></div>';
  m.innerHTML = h;
  m.scrollTop = 0;
  renderConvPage(m, msgs, document.getElementById('q').value.trim());
}
document.getElementById('q').addEventListener('keydown', e => { if(e.key==='Enter') dosearch(); });
document.getElementById('facc').addEventListener('change', () => renderSide(document.getElementById('fconv').value.trim()));
async function doRefresh(){
  const btn = document.getElementById('refreshBtn');
  btn.textContent = '刷新中…'; btn.disabled = true;
  let base = 0;
  try{
    const s = await (await fetch('/api/status')).json();
    base = s.index_mtime || 0;
    await fetch('/api/refresh', {method:'POST'});
  }catch(e){}
  const poll = setInterval(async () => {
    try{
      const s = await (await fetch('/api/status')).json();
      if(s.index_mtime && s.index_mtime !== base){
        clearInterval(poll);
        btn.textContent = '↻ 刷新数据'; btn.disabled = false;
        await loadSide(document.getElementById('fconv').value.trim());
        alert('刷新完成，现在搜索到的就是最新聊天记录');
      }
    }catch(e){}
  }, 5000);
}
loadSide();
</script>
</body>
</html>"""

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Re-snapshot, re-extract keys, re-decrypt, rebuild index (community web.py idea)."""
    import threading
    def _work():
        try:
            import refresh_all
            refresh_all.main()
        except Exception as e:
            print("refresh error:", e, flush=True)
    t = threading.Thread(target=_work, daemon=True)
    t.start()
    return jsonify({"started": True, "hint": "刷新约需 30-60 秒，稍后重新搜索即可看到最新消息"})

@app.route("/api/status")
def api_status():
    st = {"index_mtime": os.path.getmtime(IDX) if os.path.exists(IDX) else 0,
          "now": datetime.datetime.now().timestamp()}
    if st["index_mtime"]:
        st["index_age_min"] = round((st["now"] - st["index_mtime"]) / 60, 1)
    return jsonify(st)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
