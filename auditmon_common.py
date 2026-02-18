# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import json
import time
import gzip
import shutil
import sqlite3
import stat
import hashlib
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

def real_home() -> Path:
    # если запущено через sudo, берём домашнюю папку исходного пользователя
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            pass
    return Path.home()

APP_NAME = "auditmon"
HOME = real_home()

DEFAULT_CONFIG: Dict[str, Any] = {
    "db_path": str(HOME / ".local" / "share" / "auditmon" / "events.sqlite"), # директория с бд
    "archive_dir": str(HOME / ".local" / "share" / "auditmon" / "archives"),  # директория с архивами бд
    "rotate_max_mb": 64,                                                             # количество Мб, при котором база ротируется
    "proc_scan_interval_sec": 1.0,                                                   # интервал сканирования /proc
    "journal": {
        "enabled": True,
        "unit": "",  # optional: e.g. "sshd.service"
        "max_lines_per_min": 600
    },
    "inotify_paths": ["/etc", "/tmp", str(HOME)],
    "security": {
        "drop_privileges": True,
        "run_user": "",
        "keep_caps": ["SYS_PTRACE", "DAC_READ_SEARCH"]
    },
    "privacy": {
        "hash_paths": False,
        "hash_salt_b64": "",  # auto-generated if hash_paths enabled
    },
    "alerts": {
        "enabled": True,
        "rules": [
            {
                "name": "ALL_INTERNAL",
                "enabled": True,
                "when": {
                    "event_type":["FILE_DELETE", "NET_CONNECT_ATTEMPT", "NET_CONNECT_RESULT"]
                },
                "action": {"internal": True},
                "message": "{event_type} user={user} pid={pid} comm={comm}"
            }
        ]
    },
    "gui_auth": {
        "enabled": False,
        "password_hash_b64": "",
        "salt_b64": "",
        "iterations": 200_000
    }
}

def now_ms() -> int:
    return int(time.time() * 1000)


def ensure_private_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Ensure parent perms are not too open (best effort)
    try:
        path.parent.chmod(0o700)
    except Exception:
        pass

# Загружаем конфигурацию, мерджим с дефолтной. Если не найдена, берем дефолтную.
def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(Path.home() / ".config" / "auditmon" / "config.json")
    p = Path(config_path)
    if not p.exists():
        ensure_private_path(p)
        save_config(DEFAULT_CONFIG, config_path)
        return json.loads(json.dumps(DEFAULT_CONFIG))
    cfg = json.loads(p.read_text(encoding="utf-8"))
    # Shallow merge defaults
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    deep_update(merged, cfg)
    # auto-generate salt if needed
    if merged.get("privacy", {}).get("hash_paths") and not merged["privacy"].get("hash_salt_b64"):
        merged["privacy"]["hash_salt_b64"] = base64.b64encode(os.urandom(16)).decode()
        save_config(merged, config_path)
    return merged

# сохранение конфига с правами
def save_config(cfg: Dict[str, Any], config_path: Optional[str] = None) -> None:
    if config_path is None:
        config_path = str(Path.home() / ".config" / "auditmon" / "config.json")
    p = Path(config_path)
    ensure_private_path(p)
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        p.chmod(0o600)
    except Exception:
        pass

# рекурсивное слияние существующего конфига с дефолтным
def deep_update(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_update(dst[k], v)
        else:
            dst[k] = v

# хеширование пароля с солью
def pbkdf2_sha256(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def set_gui_password(cfg: Dict[str, Any], password: str) -> None:
    salt = os.urandom(16)
    iters = int(cfg.get("gui_auth", {}).get("iterations", 200_000))
    digest = pbkdf2_sha256(password, salt, iters)
    cfg.setdefault("gui_auth", {})
    cfg["gui_auth"]["enabled"] = True
    cfg["gui_auth"]["salt_b64"] = base64.b64encode(salt).decode()
    cfg["gui_auth"]["password_hash_b64"] = base64.b64encode(digest).decode()
    cfg["gui_auth"]["iterations"] = iters


def verify_gui_password(cfg: Dict[str, Any], password: str) -> bool:
    auth = cfg.get("gui_auth", {})
    if not auth.get("enabled"):
        return True
    try:
        salt = base64.b64decode(auth.get("salt_b64", ""))
        expected = base64.b64decode(auth.get("password_hash_b64", ""))
        iters = int(auth.get("iterations", 200_000))
    except Exception:
        return False
    got = pbkdf2_sha256(password, salt, iters)
    return got == expected


def _connect_db(db_path: str) -> sqlite3.Connection:
    ensure_private_path(Path(db_path))
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(db_path: str) -> None:
    conn = _connect_db(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ms INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            user TEXT,
            uid INTEGER,
            pid INTEGER,
            ppid INTEGER,
            comm TEXT,
            details_json TEXT
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ms);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ms INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            event_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(event_id) REFERENCES events(id)
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_ms);")
    conn.close()
    # lock down permissions best-effort
    try:
        os.chmod(db_path, 0o600)
    except Exception:
        pass


def rotate_db_if_needed(db_path: str, archive_dir: str, rotate_max_mb: int) -> Optional[str]:
    """
    If DB file exceeds rotate_max_mb, archive it to archive_dir as .sqlite.gz and recreate DB.
    Returns archive path if rotated.
    """
    try:
        size = os.path.getsize(db_path)
    except FileNotFoundError:
        return None
    max_bytes = int(rotate_max_mb) * 1024 * 1024
    if size <= max_bytes:
        return None

    ts = time.strftime("%Y%m%d-%H%M%S")
    archive_dir_p = Path(archive_dir)
    archive_dir_p.mkdir(parents=True, exist_ok=True)
    try:
        archive_dir_p.chmod(0o700)
    except Exception:
        pass
    tmp_copy = archive_dir_p / f"events-{ts}.sqlite"
    archive_gz = archive_dir_p / f"events-{ts}.sqlite.gz"

    # Make a consistent copy by forcing a checkpoint and using SQLite backup API
    conn = _connect_db(db_path)
    try:
        conn.execute("PRAGMA wal_checkpoint(FULL);")
        dest = sqlite3.connect(str(tmp_copy))
        with dest:
            conn.backup(dest)
        dest.close()
    finally:
        conn.close()

    # Compress and remove uncompressed copy
    with open(tmp_copy, "rb") as f_in, gzip.open(archive_gz, "wb", compresslevel=6) as f_out:
        shutil.copyfileobj(f_in, f_out)
    try:
        tmp_copy.unlink()
    except Exception:
        pass

    # Replace DB with new empty one
    try:
        os.remove(db_path)
    except Exception:
        pass
    init_db(db_path)

    try:
        os.chmod(str(archive_gz), 0o600)
    except Exception:
        pass

    return str(archive_gz)


def hash_if_needed(cfg: Dict[str, Any], value: str) -> str:
    priv = cfg.get("privacy", {})
    if not priv.get("hash_paths"):
        return value
    salt_b64 = priv.get("hash_salt_b64", "")
    if not salt_b64:
        return value
    salt = base64.b64decode(salt_b64)
    h = hashlib.sha256(salt + value.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


@dataclass
class Event:
    ts_ms: int
    event_type: str
    user: Optional[str]
    uid: Optional[int]
    pid: Optional[int]
    ppid: Optional[int]
    comm: Optional[str]
    details_json: str


def insert_event(conn: sqlite3.Connection, ev: Event) -> int:
    cur = conn.execute(
        "INSERT INTO events(ts_ms,event_type,user,uid,pid,ppid,comm,details_json) VALUES(?,?,?,?,?,?,?,?);",
        (ev.ts_ms, ev.event_type, ev.user, ev.uid, ev.pid, ev.ppid, ev.comm, ev.details_json)
    )
    return int(cur.lastrowid)


def insert_alert(conn: sqlite3.Connection, ts_ms: int, rule_name: str, event_id: Optional[int], message: str) -> int:
    cur = conn.execute(
        "INSERT INTO alerts(ts_ms,rule_name,event_id,message) VALUES(?,?,?,?);",
        (ts_ms, rule_name, event_id, message)
    )
    return int(cur.lastrowid)
