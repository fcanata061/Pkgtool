# pkgtool/db.py
\"\"\"Simple SQLite wrapper for pkgtool persistent state.

Provides:
 - init_db(path)
 - ToolDB class with methods to register packages/toolchains, query installed, mark built_with, list updates, etc.
Keep it small and transactional.
\"\"\"

from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
import time

from .config import get_config

DEFAULT_DB_PATH = Path(get_config().get("db_path", "/var/lib/pkgtool/pkgtool.db"))

SCHEMA = [
    # packages: general installed packages (not toolchains)
    \"\"\"\nCREATE TABLE IF NOT EXISTS packages (\n  id INTEGER PRIMARY KEY,\n  name TEXT NOT NULL,\n  version TEXT NOT NULL,\n  install_prefix TEXT NOT NULL,\n  meta_path TEXT,\n  installed_at REAL\n);\n\"\"\",
    # toolchains table
    \"\"\"\nCREATE TABLE IF NOT EXISTS toolchains (\n  id INTEGER PRIMARY KEY,\n  component TEXT NOT NULL,\n  version TEXT NOT NULL,\n  path TEXT NOT NULL,\n  meta_path TEXT,\n  installed_at REAL,\n  active INTEGER DEFAULT 0\n);\n\"\"\",
    # built metadata
    \"\"\"\nCREATE TABLE IF NOT EXISTS built_info (\n  id INTEGER PRIMARY KEY,\n  package_id INTEGER,\n  built_with TEXT,\n  FOREIGN KEY(package_id) REFERENCES packages(id)\n);\n\"\"\"
]

def init_db(path: Optional[str] = None) -> None:
    p = Path(path) if path else DEFAULT_DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    cur = conn.cursor()
    for sql in SCHEMA:
        cur.executescript(sql)
    conn.commit()
    conn.close()

class ToolDB:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else DEFAULT_DB_PATH
        init_db(str(self.path))

    def _conn(self):
        return sqlite3.connect(str(self.path))

    # packages
    def register_package(self, name: str, version: str, prefix: str, meta_path: Optional[str] = None) -> int:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO packages (name,version,install_prefix,meta_path,installed_at) VALUES (?,?,?,?,?)",
                    (name, version, prefix, meta_path, time.time()))
        pkg_id = cur.lastrowid
        conn.commit()
        conn.close()
        return pkg_id

    def list_packages(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT id,name,version,install_prefix,meta_path,installed_at FROM packages")
        rows = cur.fetchall()
        conn.close()
        return [{"id": r[0], "name": r[1], "version": r[2], "prefix": r[3], "meta": r[4], "installed_at": r[5]} for r in rows]

    # toolchains
    def register_toolchain(self, component: str, version: str, path: str, meta_path: Optional[str] = None, active: bool = False) -> int:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO toolchains (component,version,path,meta_path,installed_at,active) VALUES (?,?,?,?,?,?)",
                    (component, version, path, meta_path, time.time(), 1 if active else 0))
        iid = cur.lastrowid
        conn.commit()
        conn.close()
        return iid

    def set_active_toolchain(self, component: str, version: str):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("UPDATE toolchains SET active=0 WHERE component=?", (component,))
        cur.execute("UPDATE toolchains SET active=1 WHERE component=? AND version=?", (component, version))
        conn.commit()
        conn.close()

    def list_toolchains(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT id,component,version,path,meta_path,installed_at,active FROM toolchains")
        rows = cur.fetchall()
        conn.close()
        return [{"id": r[0], "component": r[1], "version": r[2], "path": r[3], "meta": r[4], "installed_at": r[5], "active": bool(r[6])} for r in rows]
