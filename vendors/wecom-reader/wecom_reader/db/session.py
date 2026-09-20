"""Session (会话) queries for decrypted WeCom databases."""

import sqlite3
from typing import Optional


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def list_sessions(
    db_path: str,
    limit: int = 50,
    offset: int = 0,
    keyword: Optional[str] = None,
    session_type: Optional[str] = None,
) -> list[dict]:
    """List sessions from session.db conversation_table.

    Args:
        db_path: Path to decrypted session.db.
        limit: Max results.
        offset: Pagination offset.
        keyword: Filter by name/remark keyword.
        session_type: Filter by prefix (R/S/M/O/Y).

    Returns:
        List of session dicts with id, name, type, last_message_time, etc.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        if not _table_exists(conn, "conversation_table"):
            return []

        query = "SELECT id, name, roomname_remark, last_message_time, last_message_id FROM conversation_table"
        conditions = []
        params = []

        if keyword:
            conditions.append("(name LIKE ? OR roomname_remark LIKE ? OR id LIKE ?)")
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw])

        if session_type:
            prefix = session_type.upper()
            if not prefix.endswith(":"):
                prefix = prefix + ":"
            conditions.append("id LIKE ?")
            params.append(f"{prefix}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY last_message_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        sessions = []
        for row in rows:
            cid = row["id"]
            name = row["roomname_remark"] or row["name"] or ""
            stype = _classify_session(cid)
            sessions.append({
                "id": cid,
                "name": name,
                "type": stype,
                "last_message_time": row["last_message_time"],
                "last_message_id": row["last_message_id"],
            })
        return sessions
    finally:
        conn.close()


def _classify_session(cid: str) -> str:
    """Classify session by ID prefix."""
    if not cid:
        return "unknown"
    if cid.startswith("R:"):
        return "group"
    if cid.startswith("S:"):
        return "single"
    if cid.startswith("M:"):
        return "wechat_contact"
    if cid.startswith("O:"):
        return "app"
    if cid.startswith("Y:"):
        return "system"
    return "other"


def get_session_count(db_path: str) -> int:
    """Get total number of sessions."""
    conn = sqlite3.connect(db_path)
    try:
        if not _table_exists(conn, "conversation_table"):
            return 0
        row = conn.execute("SELECT COUNT(*) FROM conversation_table").fetchone()
        return row[0] if row else 0
    finally:
        conn.close()
