"""Web UI for browsing WeCom chat data.

Usage: python -m wecom_reader.web --db-dir E:/WXWork/1688851235369380/Data
"""

import json
import os
import sqlite3
import sys
import time
from datetime import datetime

from flask import Flask, Response, render_template_string, request

from .reader import WeComReader

app = Flask(__name__)
reader: WeComReader = None


def safe_jsonify(data):
    """JSON response that handles bytes, datetime, etc."""

    def _default(obj):
        if isinstance(obj, bytes):
            try:
                return obj.decode("utf-8", errors="replace")
            except Exception:
                return obj.hex()
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return str(obj)
        return str(obj)

    return Response(
        json.dumps(data, ensure_ascii=False, default=_default),
        mimetype="application/json",
    )

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>企微聊天记录查看器</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; background: #f0f2f5; height: 100vh; overflow: hidden; }
.app { display: flex; height: 100vh; }

/* Left sidebar - session list */
.sidebar { width: 320px; background: #fff; border-right: 1px solid #e8e8e8; display: flex; flex-direction: column; }
.sidebar-header { padding: 16px; border-bottom: 1px solid #e8e8e8; }
.sidebar-header h2 { font-size: 16px; color: #333; margin-bottom: 8px; }
.sidebar-header input { width: 100%; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 14px; outline: none; }
.sidebar-header input:focus { border-color: #1890ff; }
.session-count { padding: 4px 16px; font-size: 12px; color: #999; background: #fafafa; border-bottom: 1px solid #f0f0f0; }
.session-list { flex: 1; overflow-y: auto; }
.session-item { padding: 12px 16px; border-bottom: 1px solid #f0f0f0; cursor: pointer; transition: background 0.15s; }
.session-item:hover { background: #f5f5f5; }
.session-item.active { background: #e6f7ff; border-left: 3px solid #1890ff; }
.session-name { font-size: 14px; color: #333; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.session-meta { display: flex; justify-content: space-between; margin-top: 4px; }
.session-type { font-size: 11px; color: #999; background: #f0f0f0; padding: 1px 6px; border-radius: 3px; }
.session-time { font-size: 11px; color: #bbb; }

/* Right panel - messages */
.main { flex: 1; display: flex; flex-direction: column; background: #f0f2f5; }
.chat-header { padding: 16px 20px; background: #fff; border-bottom: 1px solid #e8e8e8; display: flex; align-items: center; gap: 12px; }
.chat-header h3 { font-size: 15px; color: #333; }
.chat-header .badge { font-size: 11px; color: #999; background: #f0f0f0; padding: 2px 8px; border-radius: 4px; }
.message-area { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }
.msg { max-width: 70%; display: flex; flex-direction: column; }
.msg.sent { align-self: flex-end; }
.msg.received { align-self: flex-start; }
.msg-sender { font-size: 12px; color: #999; margin-bottom: 4px; }
.msg-bubble { padding: 10px 14px; border-radius: 8px; font-size: 14px; line-height: 1.5; word-break: break-word; white-space: pre-wrap; }
.msg.sent .msg-bubble { background: #95ec69; color: #333; border-bottom-right-radius: 2px; }
.msg.received .msg-bubble { background: #fff; color: #333; border-bottom-left-radius: 2px; box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
.msg-time { font-size: 11px; color: #bbb; margin-top: 4px; }
.msg.sent .msg-time { text-align: right; }
.msg-type-tag { font-size: 10px; color: #fff; background: #1890ff; padding: 1px 5px; border-radius: 3px; margin-left: 6px; }
.msg-type-tag.image { background: #722ed1; }
.msg-type-tag.voice { background: #fa8c16; }
.msg-type-tag.file { background: #13c2c2; }
.msg-type-tag.system { background: #999; }

/* Empty state */
.empty-state { display: flex; align-items: center; justify-content: center; height: 100%; color: #999; font-size: 15px; }
.loading { text-align: center; padding: 20px; color: #999; }
.load-more { text-align: center; padding: 12px; }
.load-more button { padding: 6px 20px; background: #fff; border: 1px solid #d9d9d9; border-radius: 4px; cursor: pointer; font-size: 13px; color: #666; }
.load-more button:hover { border-color: #1890ff; color: #1890ff; }
</style>
</head>
<body>
<div class="app">
  <div class="sidebar">
    <div class="sidebar-header">
      <h2>企微聊天记录</h2>
      <input type="text" id="searchInput" placeholder="搜索会话..." oninput="debounceSearch()">
      <button onclick="refreshData()" style="margin-top:8px;padding:6px 12px;background:#1890ff;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:12px;width:100%">刷新数据</button>
    </div>
    <div class="session-count" id="sessionCount">加载中...</div>
    <div class="session-list" id="sessionList"></div>
  </div>
  <div class="main">
    <div class="empty-state" id="emptyState">← 选择一个会话查看消息</div>
    <div id="chatView" style="display:none; flex:1; flex-direction:column; height:100%;">
      <div class="chat-header">
        <h3 id="chatTitle">-</h3>
        <span class="badge" id="chatBadge">-</span>
      </div>
      <div class="message-area" id="messageArea"></div>
    </div>
  </div>
</div>
<script>
let currentSession = null;
let currentOffset = 0;
let searchTimer = null;

function debounceSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadSessions(document.getElementById('searchInput').value), 300);
}

async function loadSessions(keyword = '') {
    const params = new URLSearchParams({limit: 500});
  if (keyword) params.set('keyword', keyword);
  const resp = await fetch('/api/sessions?' + params);
  const data = await resp.json();
  const list = document.getElementById('sessionList');
  const count = document.getElementById('sessionCount');
  count.textContent = `${data.count} 个会话`;
  list.innerHTML = data.sessions.map(s => `
    <div class="session-item" data-id="${s.id}" onclick="selectSession('${s.id}', '${escapeHtml(s.name)}', '${s.type}')">
      <div class="session-name">${escapeHtml(s.name) || s.id}</div>
      <div class="session-meta">
        <span class="session-type">${typeLabel(s.type)}</span>
        <span class="session-time">${s.last_message_time ? formatTime(s.last_message_time) : ''}</span>
      </div>
    </div>
  `).join('');
}

function typeLabel(t) {
  return {group:'群聊',single:'单聊',wechat_contact:'微信',app:'应用',system:'系统',other:'其他'}[t]||t;
}

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
  return d.toLocaleDateString('zh-CN',{month:'2-digit',day:'2-digit'})+' '+d.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
}

function escapeHtml(s) { const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }

async function selectSession(id, name, type) {
  currentSession = id;
  currentOffset = 0;
  document.querySelectorAll('.session-item').forEach(el => el.classList.toggle('active', el.dataset.id===id));
  document.getElementById('emptyState').style.display = 'none';
  const cv = document.getElementById('chatView');
  cv.style.display = 'flex';
  document.getElementById('chatTitle').textContent = name || id;
  document.getElementById('chatBadge').textContent = typeLabel(type) + ' · ' + id;
  const area = document.getElementById('messageArea');
  area.innerHTML = '<div class="loading">加载中...</div>';
  await loadMessages(id, true);
}

async function loadMessages(sessionId, reset=false) {
  if (reset) currentOffset = 0;
  const params = new URLSearchParams({session_id: sessionId, limit: 50, offset: currentOffset});
  const resp = await fetch('/api/messages?' + params);
  const data = await resp.json();
  const area = document.getElementById('messageArea');
  if (reset) area.innerHTML = '';
  const html = data.messages.map(m => {
    const isSend = false; // WeCom doesn't expose self_id easily, treat all as received
    const sender = m.sender_name || (m.sender_id != null ? String(m.sender_id) : '');
    const content = m.content || '';
    const tname = m.type_name || '';
    const typeClass = {image:'image',voice:'voice','image/file':'file',status:'system',meeting:'system',call:'system',app_message:'file'}[tname]||'';
    const tag = tname && tname!=='text' && !tname.startsWith('type_') ? `<span class="msg-type-tag ${typeClass}">${escapeHtml(tname)}</span>` : '';
    return `<div class="msg ${isSend?'sent':'received'}">
      ${!isSend && sender ? `<div class="msg-sender">${escapeHtml(sender)}</div>` : ''}
      <div class="msg-bubble">${escapeHtml(content) || '<i style="color:#bbb">[空消息]</i>'}${tag}</div>
      <div class="msg-time">${formatTime(m.send_time)}</div>
    </div>`;
  }).join('');
  if (data.messages.length === 0 && currentOffset === 0) {
    area.innerHTML = '<div class="loading">暂无消息</div>';
  } else {
    if (currentOffset === 0) area.innerHTML = html;
    else area.insertAdjacentHTML('afterbegin', html);
    if (data.messages.length >= 50) {
      let lb = area.querySelector('.load-more');
      if (!lb) { area.insertAdjacentHTML('afterbegin','<div class="load-more"><button onclick="loadMore()">加载更多</button></div>'); }
    }
  }
  if (reset) area.scrollTop = area.scrollHeight;
  currentOffset += data.messages.length;
}

function loadMore() {
  if (currentSession) loadMessages(currentSession, false);
}

async function refreshData() {
  const btn = event.target;
  btn.textContent = '解密中...';
  btn.disabled = true;
  try {
    const resp = await fetch('/api/refresh', {method: 'POST'});
    const data = await resp.json();
    if (data.success) {
      btn.textContent = '刷新成功';
      await loadSessions();
      if (currentSession) await selectSession(currentSession, document.getElementById('chatTitle').textContent, '');
    } else {
      btn.textContent = '刷新失败: ' + (data.error || '');
    }
  } catch(e) {
    btn.textContent = '刷新失败';
  }
  setTimeout(() => { btn.textContent = '刷新数据'; btn.disabled = false; }, 2000);
}

loadSessions();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/sessions")
def api_sessions():
    keyword = request.args.get("keyword")
    limit = int(request.args.get("limit", 200))
    sessions = reader.list_sessions(limit=limit, keyword=keyword)
    return safe_jsonify({"count": len(sessions), "sessions": sessions})


@app.route("/api/messages")
def api_messages():
    session_id = request.args.get("session_id")
    if not session_id:
        return safe_jsonify({"error": "session_id required"}), 400
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    messages = reader.get_messages(session_id, limit=limit, offset=offset)
    return safe_jsonify({"count": len(messages), "messages": messages})


@app.route("/api/search")
def api_search():
    keyword = request.args.get("q", "")
    session_id = request.args.get("session_id")
    limit = int(request.args.get("limit", 50))
    results = reader.search_messages(keyword, conversation_id=session_id, limit=limit)
    return safe_jsonify({"count": len(results), "results": results})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Re-decrypt databases to get latest data."""
    try:
        result = reader.init(verbose=False)
        return safe_jsonify(result)
    except Exception as e:
        return safe_jsonify({"success": False, "error": str(e)})


def main():
    import argparse
    parser = argparse.ArgumentParser(description="WeCom chat web viewer")
    parser.add_argument("--db-dir", required=True, help="WeCom data directory")
    parser.add_argument("--decrypted-dir", default="wxwork_decrypted", help="Decrypted DB directory")
    parser.add_argument("--port", type=int, default=8765, help="Web server port")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    args = parser.parse_args()

    global reader
    reader = WeComReader(db_dir=args.db_dir, decrypted_dir=args.decrypted_dir)
    print(f"[*] Decrypted data: {args.decrypted_dir}")
    print(f"[*] Starting web UI on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
