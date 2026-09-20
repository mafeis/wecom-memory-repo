"""Contact (联系人) queries for decrypted WeCom databases."""

import sqlite3
from typing import Optional


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def list_contacts(
    db_path: str,
    keyword: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """List contacts from user.db.

    Args:
        db_path: Path to decrypted user.db.
        keyword: Filter by name/account/corp.
        limit: Max results.
        offset: Pagination offset.

    Returns:
        List of contact dicts.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        contacts = []

        if _table_exists(conn, "user_table"):
            query = "SELECT id, name, real_name, account, external_corp_name, external_job FROM user_table"
            params = []

            if keyword:
                query += " WHERE (name LIKE ? OR real_name LIKE ? OR account LIKE ? OR external_corp_name LIKE ?)"
                kw = f"%{keyword}%"
                params.extend([kw, kw, kw, kw])

            query += " ORDER BY id LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            for row in conn.execute(query, params):
                display_name = row["real_name"] or row["name"] or row["account"] or ""
                corp = row["external_corp_name"] or ""
                if corp and corp not in display_name:
                    display_name = f"{display_name} ({corp})" if display_name else corp

                contacts.append({
                    "id": row["id"],
                    "name": display_name,
                    "raw_name": row["name"],
                    "real_name": row["real_name"],
                    "account": row["account"],
                    "corp_name": corp,
                    "job": row["external_job"],
                })

        # Also check external_user_relation_v3 for external contacts
        if _table_exists(conn, "external_user_relation_v3"):
            existing_ids = {c["id"] for c in contacts}
            query = "SELECT user_id, remarks, real_remarks, corp_remark FROM external_user_relation_v3"
            params = []
            if keyword:
                query += " WHERE (remarks LIKE ? OR real_remarks LIKE ? OR corp_remark LIKE ?)"
                kw = f"%{keyword}%"
                params.extend([kw, kw, kw])
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            for row in conn.execute(query, params):
                uid = row["user_id"]
                if uid in existing_ids:
                    continue
                name = row["real_remarks"] or row["remarks"] or row["corp_remark"] or ""
                if name:
                    contacts.append({
                        "id": uid,
                        "name": name,
                        "raw_name": None,
                        "real_name": None,
                        "account": None,
                        "corp_name": None,
                        "job": None,
                    })

        return contacts
    finally:
        conn.close()


def build_user_map(db_path: str) -> dict[int, str]:
    """Build user_id -> display_name mapping for message sender resolution."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        users = {}
        if _table_exists(conn, "user_table"):
            for row in conn.execute(
                "SELECT id, name, real_name, account, external_corp_name FROM user_table"
            ):
                name = row["real_name"] or row["name"] or row["account"] or ""
                corp = row["external_corp_name"] or ""
                if corp and corp not in name:
                    name = f"{name} ({corp})" if name else corp
                if name:
                    users[int(row["id"])] = name

        if _table_exists(conn, "external_user_relation_v3"):
            for row in conn.execute(
                "SELECT user_id, remarks, real_remarks, corp_remark FROM external_user_relation_v3"
            ):
                uid = int(row["user_id"])
                if uid not in users:
                    name = row["real_remarks"] or row["remarks"] or row["corp_remark"] or ""
                    if name:
                        users[uid] = name

        return users
    finally:
        conn.close()


def get_group_members(session_db_path: str, conversation_id: str) -> dict[int, str]:
    """Get group members with nicknames for a conversation."""
    conn = sqlite3.connect(session_db_path)
    conn.row_factory = sqlite3.Row
    try:
        members = {}
        if _table_exists(conn, "conversation_user_table"):
            for row in conn.execute(
                "SELECT user_id, nick_name FROM conversation_user_table WHERE conversation_id = ?",
                (conversation_id,),
            ):
                if row["nick_name"]:
                    members[int(row["user_id"])] = row["nick_name"]
        return members
    finally:
        conn.close()
