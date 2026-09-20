# -*- coding: utf-8 -*-
"""Generate the single-file HTML wiki with client-side full-text search."""
import os, json, sqlite3, datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIKI = os.path.join(BASE, "wiki")
DEC = os.path.join(BASE, "wxwork_data", "decrypted")

data = json.load(open(os.path.join(WIKI, "_data.json"), encoding="utf-8"))

# attach contacts per account
for acc_obj in data["accounts"]:
    acc = acc_obj["acc"]
    users = []
    try:
        con = sqlite3.connect(os.path.join(DEC, acc, "user.db"))
        con.row_factory = sqlite3.Row
        for r in con.execute("SELECT id, name, position, mobile, email FROM user_table"):
            users.append(dict(r))
        con.close()
    except Exception:
        pass
    acc_obj["users"] = users

payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")

TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>企业微信记忆仓库</title>
<style>
:root{--bg:#f4f6fa;--card:#fff;--line:#e6eaf1;--txt:#1f2937;--dim:#6b7280;--accent:#2563eb;--ok:#059669;--code-bg:#0f172a}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei","PingFang SC",sans-serif;background:var(--bg);color:var(--txt);font-size:14px;line-height:1.7}
header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 32px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
header h1{font-size:18px;font-weight:700;white-space:nowrap}
header h1 span{color:var(--accent)}
.searchwrap{flex:1;min-width:260px;position:relative}
#q{width:100%;padding:9px 14px;border:1px solid var(--line);border-radius:8px;font-size:14px;outline:none;background:var(--bg)}
#q:focus{border-color:var(--accent);background:#fff}
.meta{font-size:12px;color:var(--dim);white-space:nowrap}
.layout{display:grid;grid-template-columns:300px 1fr;gap:0;min-height:calc(100vh - 61px)}
aside{background:var(--card);border-right:1px solid var(--line);overflow-y:auto;max-height:calc(100vh - 61px);position:sticky;top:0}
.grp{padding:10px 16px 4px;font-size:12px;color:var(--dim);font-weight:600}
.conv{padding:9px 16px;cursor:pointer;border-left:3px solid transparent;display:flex;justify-content:space-between;gap:8px}
.conv:hover{background:var(--bg)}
.conv.act{border-left-color:var(--accent);background:#eff6ff}
.conv .n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conv .c{font-size:12px;color:var(--dim);font-variant-numeric:tabular-nums}
main{padding:24px 32px 60px;max-width:980px}
.day{margin:22px 0 10px;font-size:12.5px;color:var(--dim);font-weight:600;border-left:4px solid var(--accent);padding-left:10px}
.msg{padding:6px 10px;border-radius:8px;margin:2px 0}
.msg:hover{background:var(--bg)}
.msg .h{font-size:12px;color:var(--dim);margin-right:8px;font-variant-numeric:tabular-nums}
.msg .who{font-weight:600;margin-right:6px}
.msg.me .who{color:var(--accent)}
.badge{display:inline-block;font-size:11.5px;border-radius:99px;padding:0 8px;margin-right:6px;background:rgba(37,99,235,.1);color:var(--accent)}
.hit{background:#fef3c7;border-radius:3px;padding:0 2px}
.empty{color:var(--dim);padding:40px;text-align:center}
.statcard{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 20px;margin-bottom:18px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.statcard b{font-size:16px}
.statcard .row{display:flex;gap:28px;flex-wrap:wrap;font-size:13px}
@media print{aside,header{display:none}}
@media (max-width:760px){.layout{grid-template-columns:1fr}aside{position:static;max-height:220px;border-right:none;border-bottom:1px solid var(--line)}main{padding:16px}}
</style>
</head>
<body>
<header>
  <h1>企业微信<span>记忆仓库</span></h1>
  <div class="searchwrap"><input id="q" type="search" placeholder="搜索全部聊天记录…（输入关键词，回车定位）" autofocus></div>
  <div class="meta" id="meta"></div>
</header>
<div class="layout">
  <aside id="side"></aside>
  <main id="main"></main>
</div>
<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
const DATA = JSON.parse(document.getElementById('payload').textContent);
const allConvs = [];
DATA.accounts.forEach(a => a.convs.forEach(c => allConvs.push({a: a, c: c})));
allConvs.sort((x, y) => y.c.last - x.c.last);
document.getElementById('meta').textContent = DATA.generated + ' 生成 · ' + allConvs.reduce((s, x) => s + x.c.count, 0) + ' 条消息 · ' + allConvs.length + ' 个会话';

function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function hl(s, q){
  if(!q) return esc(s);
  const parts = esc(s).split(new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')','gi'));
  return parts.map(p => p.toLowerCase() === q.toLowerCase() ? '<span class="hit">' + p + '</span>' : p).join('');
}
function fmtT(t){
  if(!t) return '';
  const d = new Date(t * 1000);
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth()+1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function fmtClock(t){
  if(!t) return '--:--';
  const d = new Date(t * 1000);
  const p = n => String(n).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
const KINDICON = {'图片':'📷','语音':'🎙️','文件':'📎','邮件':'✉️','文档':'📄','卡片':'🃏','通话':'📞','会议':'📅','Markdown':'📝','引用回复':'↩️','应用消息':'🤖'};

function renderSide(filter){
  const side = document.getElementById('side');
  let html = '';
  DATA.accounts.forEach(a => {
    const convs = a.convs.filter(c => c.count > 0 && (!filter || c.name.toLowerCase().includes(filter.toLowerCase())));
    if(!convs.length) return;
    html += '<div class="grp">' + esc(a.my_name || a.acc) + '（' + convs.length + '）</div>';
    convs.forEach(c => {
      html += '<div class="conv" data-cid="' + esc(c.cid) + '" data-acc="' + a.acc + '"><span class="n">' + esc(c.name) + '</span><span class="c">' + c.count + '</span></div>';
    });
  });
  side.innerHTML = html || '<div class="empty">无匹配会话</div>';
  side.querySelectorAll('.conv').forEach(el => el.onclick = () => showConv(el.dataset.acc, el.dataset.cid));
}
function showConv(acc, cid, q){
  renderSide(document.getElementById('q').value.trim());
  const item = allConvs.find(x => x.a.acc === acc && x.c.cid === cid);
  document.querySelectorAll('.conv').forEach(el => {
    el.classList.toggle('act', el.dataset.cid === cid && el.dataset.acc === acc);
  });
  const main = document.getElementById('main');
  if(!item){ main.innerHTML = '<div class="empty">会话不存在</div>'; return; }
  const a = item.a, c = item.c;
  let html = '<div class="statcard"><div class="row"><span><b>' + esc(c.name) + '</b></span><span>' + esc(c.type) + '</span><span>' + c.count + ' 条消息</span><span>' + fmtT(c.last) + ' 最新</span><span style="color:var(--dim)">' + esc(c.cid) + '</span></div></div>';
  let day = '';
  c.msgs.forEach(m => {
    const d = m.t ? fmtT(m.t).slice(0, 10) : '未知日期';
    if(d !== day){ day = d; html += '<div class="day">' + d + '</div>'; }
    const icon = KINDICON[m.k] ? '<span class="badge">' + KINDICON[m.k] + '</span>' : (m.k !== '文本' ? '<span class="badge">' + esc(m.k) + '</span>' : '');
    const isMe = m.s === (a.my_name || '我');
    html += '<div class="msg' + (isMe ? ' me' : '') + '"><span class="h">' + fmtClock(m.t) + '</span><span class="who">' + esc(m.s) + '</span>' + icon + hl(m.x, q) + '</div>';
  });
  main.innerHTML = html;
  window.scrollTo(0, 0);
}
function searchAll(q){
  renderSide(q);
  const main = document.getElementById('main');
  const hits = [];
  const ql = q.toLowerCase();
  allConvs.forEach(({a, c}) => {
    c.msgs.forEach(m => {
      if((m.x || '').toLowerCase().includes(ql) || (m.s || '').toLowerCase().includes(ql)){
        hits.push({a, c, m});
      }
    });
  });
  hits.sort((x, y) => y.m.t - x.m.t);
  let html = '<div class="statcard"><div class="row"><span><b>“' + esc(q) + '”</b> 的搜索结果</span><span>' + hits.length + ' 条匹配</span><span style="color:var(--dim)">点击任意结果查看上下文</span></div></div>';
  hits.slice(0, 300).forEach(h => {
    const icon = KINDICON[h.m.k] ? '<span class="badge">' + KINDICON[h.m.k] + '</span>' : '';
    html += '<div class="msg" style="cursor:pointer" onclick="showConv(\'' + h.a.acc + '\',\'' + esc(h.c.cid) + '\',\'' + esc(q).replace(/'/g,'') + '\')"><span class="h">' + fmtT(h.m.t) + '</span><span class="who">' + esc(h.c.name) + ' · ' + esc(h.m.s) + '</span>' + icon + hl(h.m.x, q) + '</div>';
  });
  if(!hits.length) html += '<div class="empty">没有找到包含 “' + esc(q) + '” 的消息</div>';
  main.innerHTML = html;
  window.scrollTo(0, 0);
}
let deb;
document.getElementById('q').addEventListener('input', e => {
  clearTimeout(deb);
  const v = e.target.value.trim();
  deb = setTimeout(() => {
    if(v.length >= 2) searchAll(v);
    else { renderSide(v); showLatest(); }
  }, 200);
});
function showLatest(){
  const first = allConvs.find(x => x.c.count > 0);
  if(first) showConv(first.a.acc, first.c.cid);
}
renderSide('');
showLatest();
</script>
</body>
</html>
"""

html_out = TEMPLATE.replace("__PAYLOAD__", payload)
out_path = os.path.join(WIKI, "企业微信记忆仓库.html")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html_out)
print(f"written: {out_path}  ({os.path.getsize(out_path)/1e6:.1f} MB)")
