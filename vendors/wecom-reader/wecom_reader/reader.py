"""Main WeComReader class — unified interface for WeCom chat data access."""

import os
import shutil
import sqlite3
from typing import Optional

from .crypto.decrypt import decrypt_database, is_plain_sqlite, is_wxsqlite3_aes128_page1, verify_key
from .crypto.key_extract import extract_key
from .db.contact import build_user_map, get_group_members, list_contacts
from .db.message import get_message_count, get_messages, search_messages
from .db.session import get_session_count, list_sessions


class WeComReader:
    """Agent-reusable WeCom (企业微信) local chat reader.

    Usage:
        reader = WeComReader()           # auto-detect
        reader = WeComReader(db_dir=...) # explicit path

        # One-step init + decrypt
        reader.init()

        # Query
        sessions = reader.list_sessions()
        msgs = reader.get_messages("R:12345")
        results = reader.search_messages("keyword")
        contacts = reader.contacts()
    """

    def __init__(
        self,
        db_dir: Optional[str] = None,
        decrypted_dir: Optional[str] = None,
        key_map: Optional[dict] = None,
    ):
        """Initialize reader.

        Args:
            db_dir: Path to WeCom Data directory (auto-detected if None).
            decrypted_dir: Path for decrypted DB output (default: ./wxwork_decrypted).
            key_map: Pre-extracted key map from extract_key(). If None, init() will extract.
        """
        self._db_dir = db_dir
        self._decrypted_dir = decrypted_dir or os.path.join(os.getcwd(), "wxwork_decrypted")
        self._key_map = key_map
        self._user_map: Optional[dict] = None

    @property
    def db_dir(self) -> Optional[str]:
        return self._db_dir

    @property
    def decrypted_dir(self) -> str:
        return self._decrypted_dir

    def status(self) -> dict:
        """Check current status of decrypted data."""
        result = {
            "db_dir": self._db_dir,
            "decrypted_dir": self._decrypted_dir,
            "decrypted": os.path.isdir(self._decrypted_dir),
            "databases": {},
        }

        if os.path.isdir(self._decrypted_dir):
            for name in os.listdir(self._decrypted_dir):
                path = os.path.join(self._decrypted_dir, name)
                if name.endswith(".db") and os.path.isfile(path):
                    sz = os.path.getsize(path)
                    try:
                        conn = sqlite3.connect(path)
                        tables = [
                            r[0]
                            for r in conn.execute(
                                "SELECT name FROM sqlite_master WHERE type='table'"
                            ).fetchall()
                        ]
                        conn.close()
                    except Exception:
                        tables = []
                    result["databases"][name] = {
                        "size_mb": round(sz / 1024 / 1024, 1),
                        "tables": tables,
                    }

        return result

    def init(
        self,
        timeout: int = 120,
        verbose: bool = False,
    ) -> dict:
        """Extract keys from WXWork.exe and decrypt all databases.

        Args:
            timeout: Max seconds for memory scan per process.
            verbose: Print progress.

        Returns:
            Dict with success status, key count, db count, etc.
        """
        # Extract keys
        if self._key_map is None:
            if verbose:
                print("[*] Extracting keys from WXWork.exe memory...")
            self._key_map = extract_key(
                db_dir=self._db_dir, timeout=timeout, verbose=verbose
            )

        self._db_dir = self._key_map.get("_db_dir", self._db_dir)
        if not self._db_dir:
            raise RuntimeError("No db_dir found in key map")

        # Decrypt databases
        os.makedirs(self._decrypted_dir, exist_ok=True)
        success = 0
        copied = 0
        failed = 0

        for root, dirs, files in os.walk(self._db_dir):
            dirs[:] = [d for d in dirs if d not in ("-journal",)]
            for name in files:
                if not name.endswith(".db") or name.endswith("-wal") or name.endswith("-shm"):
                    continue
                path = os.path.join(root, name)
                rel = os.path.relpath(path, self._db_dir)
                out_path = os.path.join(self._decrypted_dir, rel)

                with open(path, "rb") as f:
                    page1 = f.read(4096)

                if is_plain_sqlite(page1):
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    shutil.copy2(path, out_path)
                    copied += 1
                    continue

                if not is_wxsqlite3_aes128_page1(page1):
                    failed += 1
                    continue

                # Find key for this DB
                salt_hex = page1[:16].hex()
                key_hex = self._key_map.get(salt_hex)
                if not key_hex:
                    # Try all keys
                    for k, v in self._key_map.items():
                        if k.startswith("_"):
                            continue
                        if verify_key(bytes.fromhex(v), page1):
                            key_hex = v
                            break

                if not key_hex:
                    failed += 1
                    continue

                try:
                    decrypt_database(path, out_path, bytes.fromhex(key_hex))
                    success += 1
                except Exception:
                    failed += 1

        return {
            "success": success > 0,
            "decrypted": success,
            "copied": copied,
            "failed": failed,
            "decrypted_dir": self._decrypted_dir,
        }

    def _get_db_path(self, name: str) -> Optional[str]:
        """Get path to a decrypted database file."""
        if not os.path.isdir(self._decrypted_dir):
            return None
        path = os.path.join(self._decrypted_dir, name)
        return path if os.path.isfile(path) else None

    def _ensure_user_map(self):
        """Lazy-load user map for sender name resolution."""
        if self._user_map is not None:
            return
        user_db = self._get_db_path("user.db")
        if user_db:
            self._user_map = build_user_map(user_db)
        else:
            self._user_map = {}

    def list_sessions(
        self,
        limit: int = 50,
        offset: int = 0,
        keyword: Optional[str] = None,
        session_type: Optional[str] = None,
    ) -> list[dict]:
        """List WeCom sessions/conversations."""
        session_db = self._get_db_path("session.db")
        if not session_db:
            return []
        return list_sessions(session_db, limit=limit, offset=offset, keyword=keyword, session_type=session_type)

    def get_messages(
        self,
        conversation_id: str,
        limit: int = 50,
        offset: int = 0,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> list[dict]:
        """Get messages for a conversation."""
        msg_db = self._get_db_path("message.db")
        if not msg_db:
            return []

        self._ensure_user_map()
        messages = get_messages(
            msg_db, conversation_id, limit=limit, offset=offset, since=since, until=until
        )

        # Enrich with sender names
        for msg in messages:
            sender_id = msg.get("sender_id")
            if sender_id and isinstance(sender_id, int) and sender_id in self._user_map:
                msg["sender_name"] = self._user_map[sender_id]

        return messages

    def search_messages(
        self,
        keyword: str,
        conversation_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Search messages by keyword."""
        msg_db = self._get_db_path("message.db")
        if not msg_db:
            return []

        self._ensure_user_map()
        results = search_messages(msg_db, keyword, conversation_id=conversation_id, limit=limit)

        for msg in results:
            sender_id = msg.get("sender_id")
            if sender_id and isinstance(sender_id, int) and sender_id in self._user_map:
                msg["sender_name"] = self._user_map[sender_id]

        return results

    def contacts(
        self,
        keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List contacts."""
        user_db = self._get_db_path("user.db")
        if not user_db:
            return []
        return list_contacts(user_db, keyword=keyword, limit=limit, offset=offset)

    def group_members(self, conversation_id: str) -> dict[int, str]:
        """Get group members with nicknames."""
        session_db = self._get_db_path("session.db")
        if not session_db:
            return {}
        return get_group_members(session_db, conversation_id)

    def session_count(self) -> int:
        """Get total session count."""
        session_db = self._get_db_path("session.db")
        if not session_db:
            return 0
        return get_session_count(session_db)

    def message_count(self, conversation_id: str) -> int:
        """Get message count for a conversation."""
        msg_db = self._get_db_path("message.db")
        if not msg_db:
            return 0
        return get_message_count(msg_db, conversation_id)
