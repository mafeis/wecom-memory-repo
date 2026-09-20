# wecom-memory-repo · 企业微信记忆仓库

从本地**企业微信（WeCom）**数据库解密生成个人"记忆仓库"：把所有聊天记录、邮件、文件名变成可全文搜索的本地知识库。

> **隐私第一**：本仓库只包含代码。所有数据（`wxwork_data/`、`wiki/`、密钥、聊天语料衍生的分词词典）已在 `.gitignore` 中排除，**不会上传任何聊天记录、密钥或由其衍生的文件**。

## 功能特性

- 🔍 **毫秒级全文搜索** —— FTS5 索引覆盖全部文本、邮件、文件名，命中高亮、按时间排序
- ✂️ **智能分词** —— 连写查询自动切词（自建语料词典），1-2 字短词自动降级 LIKE；多词 AND 组合
- 💬 **微信式气泡对话** —— 我=右侧蓝气泡、对方=左侧白气泡；图片内联预览（点击看原图）、文件可点击打开
- 🎯 **命中定位** —— 点搜索结果直接跳到命中消息（前后各 10 条上下文，蓝圈高亮），可一键返回搜索列表
- 🖥️ **Web 速查台** —— Flask 常驻服务（`http://127.0.0.1:8765`），账号筛选、增量渲染、图片懒加载
- 📄 **单文件离线 Wiki** —— 生成 `wiki/企业微信记忆仓库.html`，拷走即用
- 📝 **Markdown 记忆仓库** —— 按会话生成 `wiki/conversations/*.md`，可直接喂给 AI/笔记工具
- 🔄 **一键刷新** —— 快照 → 提取密钥 → 解密（含 WAL 合并）→ 重建索引，全程只读源文件

## 工作原理

1. **快照**：对企业微信 `Documents\WXWork\<账号>\Data` 下的 `.db` 做共享只读复制（**源文件从不修改**）
2. **提取密钥**：企业微信 5.x 本地库为 wxSQLite3 AES-128-CBC 加密，密钥（16 字节）运行时存在于 `WXWork.exe` 进程内存，通过 Windows API 只读提取；按 WXWork 会话缓存，避免重复提取
3. **解密**：每页独立派生密钥 `page_key = MD5(raw_key + 页号 + "sAlT")`，`IV = MD5(LCG(页号+1))`；WAL 帧单独解密合并，保证最新消息不遗漏
4. **建索引**：汇总全部解密库到统一 `search_index.db`（SQLite FTS5，trigram 分词）

## 目录结构

```
├── tools/                  # 核心脚本
│   ├── wxwork_crypto.py    # wxSQLite3 AES-128-CBC 加解密核心
│   ├── pb.py               # 消息体 protobuf 文本精确提取
│   ├── build_wiki.py       # 解密 + WAL 合并 + 生成 Markdown wiki
│   ├── build_fts.py        # 构建统一 FTS5 搜索索引
│   ├── build_vocab.py      # 从语料生成分词词典（本地生成，gitignore）
│   ├── autoseg.py          # 连写查询自动分词（贪心最长匹配）
│   ├── gen_html.py         # 生成单文件离线 HTML wiki
│   ├── refresh_all.py      # 一键全量刷新流水线（快照→密钥→解密→索引）
│   ├── server.py           # Flask Web 速查服务 (127.0.0.1:8765)
│   ├── search.py           # 命令行搜索
│   ├── save_keys.py        # 提取并持久化密钥 keys.json
│   ├── decrypt_db.py       # 手动解密单个库的调试工具
│   └── archive/            # 早期密钥扫描实验脚本（存档备查）
├── vendors/
│   └── wecom-reader/       # 内置的密钥提取/消息读取库（MIT，见 vendors/wecom-reader/LICENSE）
├── wxwork_data/            # 数据目录（运行时生成，gitignore）
│   ├── raw/                #   源库只读快照（加密）
│   ├── decrypted/          #   解密后的 SQLite 库
│   ├── keys.json           #   数据库密钥（⚠️ 勿外传）
│   └── search_index.db     #   FTS 搜索索引
├── wiki/                   # 生成的 wiki（gitignore）
└── update_wiki.ps1         # 一键更新入口
```

> 依赖已内置：`vendors/wecom-reader`（MIT 协议）随本仓库分发，clone 后无需额外下载。

## 快速开始

### 1. 环境准备

- Windows + 企业微信（WXWork）已登录
- Python 3.10+

```powershell
pip install -r requirements.txt
```

### 2. 生成记忆仓库

保持企业微信运行，然后：

```powershell
powershell -File .\update_wiki.ps1
```

约 1 分钟后 `wiki/` 即生成完毕。

### 3. 启动 Web 速查台

```powershell
python tools\server.py        # 打开 http://127.0.0.1:8765
```

右上角「↻ 刷新数据」可就地重新提取密钥 + 解密 + 重建索引。

### 4. 命令行搜索

```powershell
python tools\search.py "关键词" --n 20
# 可选: --conv 会话名 --kind 文本/邮件/文件 --since 2026-08-01 --until 2026-09-01
```

## 安全提醒

- `wxwork_data/keys.json` 和 `wxwork_data/decrypted/` 含全部明文聊天记录与密钥，**请勿提交到任何仓库或外发**
- `tools/cjk_vocab.json` 由本地聊天语料自动生成（含个人高频词），已在 `.gitignore` 排除；缺失时 `autoseg` 会自动重建
- 本项目仅用于个人本地数据备份/检索，请遵守公司数据合规要求

## 致谢

本项目依赖以下社区项目：

- [wangk-ask/wecom-reader](https://github.com/wangk-ask/wecom-reader)（**MIT 协议**）—— 密钥提取 / 消息读取 / CLI，源码已内置在 `vendors/wecom-reader/`，原始许可文件见 [vendors/wecom-reader/LICENSE](vendors/wecom-reader/LICENSE)
- [jiebao776/wxwork-decrypt](https://github.com/jiebao776/wxwork-decrypt)（仓库未附带许可证）—— wxSQLite3 AES-128-CBC 加解密**算法出处**；`tools/wxwork_crypto.py` 为参考其公开算法文档的独立实现，未分发其源码

如果您是上述项目作者且对引用方式有异议，请提 issue 联系。
