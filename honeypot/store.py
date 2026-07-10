"""Persistência de eventos do honeypot em SQLite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    service TEXT NOT NULL,        -- ssh | http
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    username TEXT,
    password TEXT,
    user_agent TEXT,
    method TEXT,
    path TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
"""


class EventStore:
    def __init__(self, path: str = "honeypot.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(_SCHEMA)

    def log(self, service: str, src_ip: str, src_port: int = 0, *,
            username: str = "", password: str = "", user_agent: str = "",
            method: str = "", path: str = "", raw: str = "") -> None:
        self.conn.execute(
            "INSERT INTO events (ts, service, src_ip, src_port, username, password,"
            " user_agent, method, path, raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), service, src_ip, src_port,
             username, password, user_agent, method, path, raw),
        )
        self.conn.commit()

    def stats(self) -> dict:
        cur = self.conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_service = dict(cur.execute(
            "SELECT service, COUNT(*) FROM events GROUP BY service").fetchall())
        top_ips = cur.execute(
            "SELECT src_ip, COUNT(*) c FROM events GROUP BY src_ip "
            "ORDER BY c DESC LIMIT 10").fetchall()
        top_users = cur.execute(
            "SELECT username, COUNT(*) c FROM events WHERE username != '' "
            "GROUP BY username ORDER BY c DESC LIMIT 10").fetchall()
        top_pass = cur.execute(
            "SELECT password, COUNT(*) c FROM events WHERE password != '' "
            "GROUP BY password ORDER BY c DESC LIMIT 10").fetchall()
        return {
            "total": total,
            "by_service": by_service,
            "top_ips": top_ips,
            "top_usernames": top_users,
            "top_passwords": top_pass,
        }

    def close(self) -> None:
        self.conn.close()
