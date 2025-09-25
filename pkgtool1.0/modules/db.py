# Pkgtool/pkgtool1.0/modules/db.py
# -*- coding: utf-8 -*-
"""
PackageDB - banco local de pacotes instalados para pkgtool

Funcionalidades:
- Backends: file (JSON/YAML) e SQLite
- Persistência atômica com .tmp + rename, backups rotativos
- Lock de arquivo (portalocker ou fcntl fallback)
- Snapshots versionadas
- Histórico de transações (transactions.log)
- Índice invertido de arquivos (file_index)
- API: add/remove/update/get/list/exists/file_owner/search/deps/required_by
- CLI: pkgtool-db (list, info, add, remove, update, owns, search, export, check, history, snapshot, restore, sign, verify, migrate, stats, gc)
- Integração com modules.config (cfg) e modules.log (logger) se disponíveis
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Try to import optional libs
try:
    import yaml  # type: ignore
    _have_yaml = True
except Exception:
    _have_yaml = False

try:
    import portalocker  # type: ignore
    _have_portalocker = True
except Exception:
    _have_portalocker = False

# Try to import config/log modules (compatibility)
try:
    from modules.config import cfg  # type: ignore
except Exception:
    cfg = None

try:
    from modules import log as _logmod  # type: ignore
    logger = _logmod.get_logger("pkgtool.db")
except Exception:
    import logging as _logging
    logger = _logging.getLogger("pkgtool.db")
    if not logger.handlers:
        h = _logging.StreamHandler()
        logger.addHandler(h)
    logger.setLevel(_logging.INFO)

# ---------------- Utilities ----------------

def _now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _sha256_of_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _sha256_of_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def _atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    tmp = path.with_suffix(path.suffix + f".{int(time.time()*1000)}.tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(content, encoding="utf-8")
    try:
        tmp.chmod(mode)
    except Exception:
        pass
    tmp.replace(path)

def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    tmp = path.with_suffix(path.suffix + f".{int(time.time()*1000)}.tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(data)
    try:
        tmp.chmod(mode)
    except Exception:
        pass
    tmp.replace(path)

# File lock context manager
@contextlib.contextmanager
def _file_lock(path: Path, exclusive: bool = True, timeout: Optional[float] = 30.0):
    """
    Context manager for locking a file. Uses portalocker if available; else fcntl (Unix).
    Acquires a lock on (path or path.with_suffix('.lock')).
    """
    lock_path = path.with_suffix(path.suffix + ".lock") if path.suffix else Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+b")
    locked = False
    start = time.time()
    try:
        if _have_portalocker:
            mode = portalocker.LockFlags.EXCLUSIVE if exclusive else portalocker.LockFlags.SHARED
            portalocker.lock(fh, mode)
            locked = True
        else:
            # fallback to fcntl (POSIX)
            try:
                import fcntl  # type: ignore
                flag = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                while True:
                    try:
                        fcntl.flock(fh.fileno(), flag | fcntl.LOCK_NB)
                        locked = True
                        break
                    except BlockingIOError:
                        if timeout is not None and (time.time() - start) > timeout:
                            raise TimeoutError("Timeout acquiring file lock for %s" % lock_path)
                        time.sleep(0.05)
            except Exception:
                # No portalocker and not POSIX - best effort: use file open as advisory
                locked = True
        yield
    finally:
        try:
            if _have_portalocker and locked:
                portalocker.unlock(fh)
            else:
                try:
                    import fcntl  # type: ignore
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass

# ---------------- Data types / schema helpers ----------------

@dataclasses.dataclass
class PackageRecord:
    name: str
    version: str
    release: Optional[str] = None
    arch: Optional[str] = None
    installed_at: str = dataclasses.field(default_factory=_now_iso)
    source: Optional[str] = None
    files: List[str] = dataclasses.field(default_factory=list)
    dependencies: List[str] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "release": self.release,
            "arch": self.arch,
            "installed_at": self.installed_at,
            "source": self.source,
            "files": list(self.files),
            "dependencies": list(self.dependencies),
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PackageRecord":
        return PackageRecord(
            name=d["name"],
            version=d.get("version", ""),
            release=d.get("release"),
            arch=d.get("arch"),
            installed_at=d.get("installed_at", _now_iso()),
            source=d.get("source"),
            files=list(d.get("files", [])),
            dependencies=list(d.get("dependencies", [])),
            metadata=dict(d.get("metadata", {})),
        )

# ---------------- PackageDB class ----------------

class PackageDB:
    """
    PackageDB manages the local package database.

    Usage:
        db = PackageDB.from_config(cfg)  # or PackageDB(path=..., backend="file", format="json")
        db.load()
        db.add_package({...})
        db.save()
    """

    def __init__(self,
                 path: Union[str, Path],
                 backend: str = "file",
                 fmt: str = "json",
                 snapshot_dir: Optional[Union[str, Path]] = None,
                 backups: int = 5,
                 transactions_log: Optional[Union[str, Path]] = None,
                 signatures: bool = False):
        self.path = Path(path)
        self.backend = backend.lower()
        self.format = fmt.lower()
        self.backups = int(backups)
        self.transactions_log = Path(transactions_log) if transactions_log else (self.path.parent / "transactions.log")
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else (self.path.parent / "snapshots")
        self.signatures = bool(signatures)
        self._data: Dict[str, Dict[str, Any]] = {}  # key: name -> package dict
        self._file_index: Dict[str, List[str]] = defaultdict(list)  # file path -> list of package names
        self._lock = threading.RLock()
        self._loaded = False
        self._sqlite_conn: Optional[sqlite3.Connection] = None
        if self.backend == "sqlite":
            self._sqlite_path = self.path.with_suffix(".sqlite") if self.path.suffix else self.path.with_suffix(".sqlite")
        else:
            self._sqlite_path = None

    # ------ construction helpers ------
    @classmethod
    def from_config(cls, cfg_obj: Optional[Any]) -> "PackageDB":
        """
        Build PackageDB from cfg object (modules.config.cfg) or None.
        Config keys (under 'database'):
            path: file path (default: ./Pkgtool/pkgtool1.0/db.json)
            backend: file|sqlite
            format: json|yaml
            backups: int
            snapshot_dir: path
            transactions_log: path
            signatures: bool
        """
        if cfg_obj is None:
            # defaults: repo-local db.json
            base = Path.cwd() / "Pkgtool" / "pkgtool1.0"
            default_path = base / "db.json"
            return cls(path=default_path, backend="file", fmt="json")
        dbconf = cfg_obj.get("database", {}) or {}
        p = dbconf.get("path") or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "db.json")
        backend = dbconf.get("backend", "file")
        fmt = dbconf.get("format", "json")
        backups = dbconf.get("backups", 5)
        snapshots = dbconf.get("snapshot_dir") or (Path(p).parent / "snapshots")
        txn = dbconf.get("transactions_log") or (Path(p).parent / "transactions.log")
        signatures = dbconf.get("signatures", False)
        return cls(path=p, backend=backend, fmt=fmt, snapshot_dir=snapshots, backups=backups, transactions_log=txn, sign

atures=signatures)

    # ------ low-level IO ------
    def load(self, strict: bool = False) -> None:
        """
        Load DB from configured backend.
        strict: if True, raise exceptions on problems; else attempt recovery from backups.
        """
        with self._lock:
            logger.debug("Loading PackageDB from %s (backend=%s, format=%s)", self.path, self.backend, self.format)
            if self.backend == "sqlite":
                self._ensure_sqlite()
                self._load_from_sqlite()
            else:
                # file backend
                if not self.path.exists():
                    logger.info("DB file not found at %s; initializing empty DB.", self.path)
                    self._data = {}
                    self._file_index = defaultdict(list)
                    self._loaded = True
                    return
                try:
                    with _file_lock(self.path, exclusive=False):
                        text = self.path.read_text(encoding="utf-8")
                        if self.format == "json":
                            data = json.loads(text)
                        elif self.format == "yaml" or self.format == "yml":
                            if _have_yaml:
                                data = yaml.safe_load(text) or {}
                            else:
                                # attempt simple parse fallback (not recommended)
                                data = json.loads(text)
                        else:
                            raise ValueError("Unsupported format: " + self.format)
                        if not isinstance(data, dict):
                            raise ValueError("DB root is not a mapping")
                        # Data normalization: top-level keys are package names
                        self._data = {}
                        for name, rec in data.items():
                            if isinstance(rec, dict):
                                rec["name"] = name
                                self._data[name] = rec
                        # rebuild index
                        self._rebuild_index()
                        self._loaded = True
                        logger.info("DB loaded with %d packages", len(self._data))
                except Exception as e:
                    logger.exception("Failed to load DB: %s", e)
                    # try backup recovery
                    if not strict and self._try_recover_from_backup():
                        logger.info("Recovered db from backup.")
                    else:
                        raise

    def save(self, *, snapshot: bool = False) -> None:
        """
        Persist DB to backend. Creates backups rotating.
        If snapshot=True -> write snapshot copy with timestamp.
        """
        with self._lock:
            logger.debug("Saving PackageDB to %s (backend=%s, format=%s)", self.path, self.backend, self.format)
            if self.backend == "sqlite":
                self._ensure_sqlite()
                self._save_to_sqlite()
                return
            # prepare data structure
            out = {name: rec for name, rec in self._data.items()}
            # write atomically
            if not self.path.parent.exists():
                self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with _file_lock(self.path, exclusive=True):
                    # backup current
                    if self.path.exists():
                        self._rotate_backups()
                    # write new
                    if self.format == "json":
                        content = json.dumps(out, indent=2, ensure_ascii=False)
                        _atomic_write_text(self.path, content)
                    elif self.format in ("yaml", "yml"):
                        if _have_yaml:
                            content = yaml.safe_dump(out, sort_keys=False)
                            _atomic_write_text(self.path, content)
                        else:
                            # fallback: write json but with .yaml extension
                            content = json.dumps(out, indent=2, ensure_ascii=False)
                            _atomic_write_text(self.path, content)
                    else:
                        raise ValueError("Unsupported format: " + self.format)
                    logger.info("DB saved to %s", self.path)
                    # snapshot
                    if snapshot:
                        self._write_snapshot()
            except Exception as e:
                logger.exception("Failed to save DB: %s", e)
                raise

    def backup(self) -> Path:
        """
        Create a timestamped backup copy of current DB and return path to backup.
        """
        with self._lock:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            bak = self.path.with_name(self.path.name + f".bak-{ts}")
            if self.path.exists():
                shutil.copy2(self.path, bak)
                logger.info("Backup written to %s", bak)
            else:
                # write empty snapshot
                bak.write_text(json.dumps({}, indent=2), encoding="utf-8")
                logger.info("Backup (empty) written to %s", bak)
            return bak

    # ------ sqlite helpers ------
    def _ensure_sqlite(self) -> None:
        if self._sqlite_conn:
            return
        if not self._sqlite_path:
            raise RuntimeError("SQLite path not configured")
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._sqlite_path), isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at TEXT
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_index (
                file TEXT,
                pkg_name TEXT,
                PRIMARY KEY(file, pkg_name)
            );
        """)
        conn.commit()
        self._sqlite_conn = conn

    def _load_from_sqlite(self) -> None:
        conn = self._sqlite_conn
        if conn is None:
            self._ensure_sqlite()
            conn = self._sqlite_conn
        cur = conn.cursor()
        cur.execute("SELECT name, data FROM packages")
        rows = cur.fetchall()
        data = {}
        for name, s in rows:
            try:
                rec = json.loads(s)
                rec["name"] = name
                data[name] = rec
            except Exception:
                logger.warning("Skipping invalid row for package %s", name)
        self._data = data
        # rebuild file_index
        self._file_index = defaultdict(list)
        cur.execute("SELECT file, pkg_name FROM file_index")
        for f, p in cur.fetchall():
            self._file_index[f].append(p)
        self._loaded = True
        logger.info("Loaded %d packages from sqlite DB", len(self._data))

    def _save_to_sqlite(self) -> None:
        conn = self._sqlite_conn
        if conn is None:
            self._ensure_sqlite()
            conn = self._sqlite_conn
        cur = conn.cursor()
        # upsert packages
        for name, rec in self._data.items():
            s = json.dumps(rec, ensure_ascii=False)
            cur.execute("INSERT INTO packages (name, data, updated_at) VALUES (?, ?, ?) "
                        "ON CONFLICT(name) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                        (name, s, _now_iso()))
        # rebuild file_index table
        cur.execute("DELETE FROM file_index")
        pairs = []
        for f, pkgs in self._file_index.items():
            for p in pkgs:
                pairs.append((f, p))
        cur.executemany("INSERT OR IGNORE INTO file_index (file, pkg_name) VALUES (?, ?)", pairs)
        conn.commit()
        logger.info("SQLite DB saved (%d packages)", len(self._data))

    # ------ rotation / recover ------
    def _rotate_backups(self) -> None:
        # rotate backups like db.json.bak1 ... bakN
        try:
            for i in range(self.backups - 1, 0, -1):
                src = self.path.with_name(self.path.name + f".bak{i}")
                dst = self.path.with_name(self.path.name + f".bak{i+1}")
                if src.exists():
                    if dst.exists():
                        dst.unlink()
                    src.replace(dst)
            # current to bak1
            first = self.path.with_name(self.path.name + ".bak1")
            if self.path.exists():
                shutil.copy2(self.path, first)
        except Exception as e:
            logger.warning("Backup rotation failed: %s", e)

    def _try_recover_from_backup(self) -> bool:
        # attempt last backup
        for i in range(1, self.backups + 1):
            cand = self.path.with_name(self.path.name + f".bak{i}")
            if cand.exists():
                try:
                    logger.info("Attempting recover from %s", cand)
                    shutil.copy2(cand, self.path)
                    return True
                except Exception:
                    continue
        return False

    # ------ snapshot ------
    def _write_snapshot(self) -> Path:
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        snap_name = f"db-snapshot-{ts}.json"
        snap_path = self.snapshot_dir / snap_name
        data = {n: rec for n, rec in self._data.items()}
        _atomic_write_text(snap_path, json.dumps(data, indent=2, ensure_ascii=False))
        logger.info("Snapshot written to %s", snap_path)
        return snap_path

    def list_snapshots(self) -> List[Path]:
        if not self.snapshot_dir.exists():
            return []
        return sorted([p for p in self.snapshot_dir.iterdir() if p.is_file()], key=lambda p: p.name, reverse=True)

    def restore_snapshot(self, snapshot_path: Union[str, Path]) -> None:
        sp = Path(snapshot_path)
        if not sp.exists():
            raise FileNotFoundError("Snapshot not found: " + str(sp))
        with self._lock:
            with _file_lock(self.path, exclusive=True):
                shutil.copy2(sp, self.path)
            self.load()
            logger.info("Snapshot %s restored", sp)

    # ------ index / internal helpers ------
    def _rebuild_index(self) -> None:
        self._file_index = defaultdict(list)
        for name, rec in self._data.items():
            files = rec.get("files", [])
            for f in files:
                self._file_index[str(f)].append(name)
        logger.debug("File index rebuilt (%d entries)", len(self._file_index))

    def _index_package_files(self, pkg_name: str, files: Iterable[str]) -> None:
        for f in files:
            lst = self._file_index.get(str(f))
            if not lst:
                self._file_index[str(f)] = [pkg_name]
            else:
                if pkg_name not in lst:
                    lst.append(pkg_name)

    def _deindex_package_files(self, pkg_name: str, files: Iterable[str]) -> None:
        for f in files:
            lst = self._file_index.get(str(f))
            if lst and pkg_name in lst:
                lst.remove(pkg_name)
                if not lst:
                    del self._file_index[str(f)]

    # ------ transactions / history ------
    def _log_transaction(self, action: str, pkg: Dict[str, Any]) -> None:
        rec = {
            "timestamp": _now_iso(),
            "action": action,
            "package": pkg.get("name"),
            "data": pkg,
            "user": os.environ.get("USER", ""),
            "host": os.uname().nodename if hasattr(os, "uname") else "",
        }
        try:
            self.transactions_log.parent.mkdir(parents=True, exist_ok=True)
            with _file_lock(self.transactions_log, exclusive=True):
                with self.transactions_log.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            logger.exception("Failed to write transaction log")

    def history(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.transactions_log.exists():
            return []
        out = []
        with self.transactions_log.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out[-limit:]

    # ------ CRUD API ------
    def add_package(self, pkg: Union[PackageRecord, Dict[str, Any]], *, overwrite: bool = False, persist: bool = True) -> None:
        """
        Add a package record. pkg can be dict or PackageRecord.
        If overwrite=False and package exists -> raises.
        If persist=True -> save to disk.
        """
        with self._lock:
            if isinstance(pkg, PackageRecord):
                rec = pkg.to_dict()
            else:
                rec = dict(pkg)
            name = rec.get("name")
            if not name:
                raise ValueError("Package must have a name")
            if name in self._data and not overwrite:
                raise ValueError(f"Package {name} already exists")
            # ensure installed_at
            rec.setdefault("installed_at", _now_iso())
            # ensure files is list
            rec["files"] = list(rec.get("files", []))
            rec["dependencies"] = list(rec.get("dependencies", []))
            self._data[name] = rec
            # update index
            self._index_package_files(name, rec["files"])
            # log transaction
            try:
                self._log_transaction("install", rec)
            except Exception:
                pass
            if persist:
                self.save()

    def remove_package(self, name: str, *, persist: bool = True, remove_files_from_index: bool = True) -> None:
        """
        Remove package by name. Does not touch filesystem files; only DB and index.
        """
        with self._lock:
            rec = self._data.get(name)
            if not rec:
                raise KeyError("Package not found: " + name)
            # remove from index
            if remove_files_from_index:
                self._deindex_package_files(name, rec.get("files", []))
            del self._data[name]
            # transaction
            try:
                self._log_transaction("remove", rec)
            except Exception:
                pass
            if persist:
                self.save()

    def update_package(self, name: str, updates: Dict[str, Any], *, persist: bool = True) -> None:
        """
        Partially update package fields. For files list, replacement is complete unless you use special ops.
        """
        with self._lock:
            rec = self._data.get(name)
            if not rec:
                raise KeyError("Package not found: " + name)
            # if files are replaced, update index
            if "files" in updates:
                old_files = set(rec.get("files", []))
                new_files = set(updates.get("files", []))
                to_add = new_files - old_files
                to_remove = old_files - new_files
                self._index_package_files(name, to_add)
                self._deindex_package_files(name, to_remove)
            # merge updates
            rec.update(updates)
            rec["installed_at"] = rec.get("installed_at", rec.get("installed_at", _now_iso()))
            self._data[name] = rec
            try:
                self._log_transaction("update", rec)
            except Exception:
                pass
            if persist:
                self.save()

    def get_package(self, name: str) -> Dict[str, Any]:
        with self._lock:
            rec = self._data.get(name)
            if not rec:
                raise KeyError("Package not found: " + name)
            return dict(rec)

    def list_packages(self, *, regex: Optional[str] = None, depends_on: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List packages, optionally filter by regex on name, or packages that depend on 'depends_on'.
        """
        with self._lock:
            out = []
            import re as _re
            pat = _re.compile(regex) if regex else None
            for name, rec in self._data.items():
                if pat and not pat.search(name):
                    continue
                if depends_on:
                    deps = rec.get("dependencies", [])
                    if depends_on not in deps:
                        continue
                out.append(dict(rec))
            if limit:
                return out[:limit]
            return out

    def exists(self, name: str) -> bool:
        with self._lock:
            return name in self._data

    # ------ file ownership / search ------
    def file_owner(self, filepath: Union[str, Path]) -> List[str]:
        """
        Return list of package names that own the provided filepath.
        """
        f = str(filepath)
        with self._lock:
            return list(self._file_index.get(f, []))

    def search(self, pattern: str, *, in_metadata: bool = True, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Search packages by regex against name, version, or metadata (if enabled).
        """
        import re as _re
        pat = _re.compile(pattern)
        out = []
        with self._lock:
            for name, rec in self._data.items():
                if pat.search(name) or pat.search(str(rec.get("version", ""))):
                    out.append(dict(rec))
                    continue
                if in_metadata:
                    meta_json = json.dumps(rec.get("metadata", {}))
                    if pat.search(meta_json):
                        out.append(dict(rec))
                if limit and len(out) >= limit:
                    break
        return out

    # ------ dependency utilities ------
    def dependencies(self, name: str) -> List[str]:
        """
        Return direct dependencies of a package.
        """
        with self._lock:
            rec = self._data.get(name)
            if not rec:
                raise KeyError("Package not found: " + name)
            return list(rec.get("dependencies", []))

    def required_by(self, name: str) -> List[str]:
        """
        Return list of packages that depend on the given package (direct).
        """
        with self._lock:
            out = []
            for pname, rec in self._data.items():
                deps = rec.get("dependencies", [])
                if name in deps:
                    out.append(pname)
            return out

    # ------ integrity checks ------
    def check_integrity(self, *, check_files_exist: bool = False) -> Dict[str, Any]:
        """
        Validate DB structure, duplicates, index correctness, optional file presence.
        Returns a dict with results and lists of problems.
        """
        issues = {"missing_files": [], "index_mismatches": [], "duplicates": [], "invalid_records": []}
        with self._lock:
            # duplicates (same name) shouldn't happen in dict
            # check that index matches data
            for fname, owners in list(self._file_index.items()):
                for owner in owners:
                    if owner not in self._data:
                        issues["index_mismatches"].append({"file": fname, "owner": owner})
            # check each package
            for name, rec in self._data.items():
                if not isinstance(rec, dict):
                    issues["invalid_records"].append({"name": name, "reason": "not a mapping"})
                    continue
                files = rec.get("files", [])
                for f in files:
                    if check_files_exist:
                        if not Path(f).exists():
                            issues["missing_files"].append({"pkg": name, "file": f})
            # no serious exception -> return results
            ok = not any(issues[k] for k in issues)
            return {"ok": ok, "issues": issues}

    # ------ stats / gc / migrate ------
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total_pkgs = len(self._data)
            total_files = len(self._file_index)
            biggest_pkgs = sorted(self._data.items(), key=lambda kv: len(kv[1].get("files", [])), reverse=True)[:10]
            return {
                "total_packages": total_pkgs,
                "total_files_indexed": total_files,
                "top_packages_by_filecount": [{ "name": n, "files": len(r.get("files", [])) } for n, r in biggest_pkgs],
            }

    def gc(self) -> Dict[str, Any]:
        """
        Garbage collect index: remove stale index entries, compact snapshots older than backups.
        """
        with self._lock:
            # rebuild index from packages
            self._rebuild_index()
            # prune snapshots beyond some number (keep latest self.backups)
            snaps = self.list_snapshots()
            removed = []
            if len(snaps) > self.backups:
                for s in snaps[self.backups:]:
                    try:
                        s.unlink()
                        removed.append(str(s))
                    except Exception:
                        continue
            return {"reindexed": True, "removed_snapshots": removed}

    def migrate_backend(self, new_backend: str, new_format: Optional[str] = None) -> None:
        """
        Migrate DB to new backend (file|sqlite). If migrating file->sqlite, create sqlite and import.
        """
        with self._lock:
            new_backend = new_backend.lower()
            if new_backend == self.backend and (new_format is None or new_format == self.format):
                logger.info("No migration needed (same backend/format)")
                return
            if new_backend == "sqlite":
                # ensure sqlite path
                sqlite_path = self.path.with_suffix(".sqlite") if self.path.suffix else self.path.with_suffix(".sqlite")
                conn = sqlite3.connect(str(sqlite_path))
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("CREATE TABLE IF NOT EXISTS packages (name TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT);")
                conn.execute("CREATE TABLE IF NOT EXISTS file_index (file TEXT, pkg_name TEXT, PRIMARY KEY(file,pkg_name));")
                cur = conn.cursor()
                # insert existing records
                for name, rec in self._data.items():
                    cur.execute("INSERT OR REPLACE INTO packages (name, data, updated_at) VALUES (?, ?, ?)",
                                (name, json.dumps(rec, ensure_ascii=False), _now_iso()))
                for f, pkgs in self._file_index.items():
                    for p in pkgs:
                        cur.execute("INSERT OR IGNORE INTO file_index (file, pkg_name) VALUES (?, ?)", (f, p))
                conn.commit()
                conn.close()
                logger.info("Migrated DB to sqlite at %s", sqlite_path)
                # update self to sqlite
                self.backend = "sqlite"
                self._sqlite_path = sqlite_path
                self._sqlite_conn = None
                return
            elif new_backend == "file":
                # export current content into a file at path
                fmt = new_format or self.format
                if fmt not in ("json", "yaml", "yml"):
                    fmt = "json"
                out = {n: rec for n, rec in self._data.items()}
                if not self.path.parent.exists():
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                if fmt == "json":
                    _atomic_write_text(self.path, json.dumps(out, indent=2, ensure_ascii=False))
                else:
                    if _have_yaml:
                        _atomic_write_text(self.path, yaml.safe_dump(out, sort_keys=False))
                    else:
                        _atomic_write_text(self.path, json.dumps(out, indent=2, ensure_ascii=False))
                self.backend = "file"
                self.format = fmt
                self._sqlite_conn = None
                logger.info("Migrated DB to file at %s (format=%s)", self.path, self.format)
                return
            else:
                raise ValueError("Unsupported backend: " + new_backend)

    # ------ signing / verify (GPG CLI) ------
    def sign_db(self, key: Optional[str] = None, gpg_cmd: str = "gpg") -> Path:
        """
        Sign the DB file using GPG command-line. Writes detached signature at path + .sig
        Returns signature path.
        Requires gpg installed.
        """
        if self.backend != "file":
            raise RuntimeError("Signing currently supported only for file backend")
        sig_path = self.path.with_suffix(self.path.suffix + ".sig")
        cmd = [gpg_cmd, "--batch", "--yes", "--output", str(sig_path), "--detach-sign"]
        if key:
            cmd.extend(["--local-user", key])
        cmd.append(str(self.path))
        logger.debug("Signing DB using: %s", " ".join(cmd))
        try:
            res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("DB signed -> %s", sig_path)
            return sig_path
        except subprocess.CalledProcessError as e:
            logger.error("GPG sign failed: %s", e.stderr.decode() if e.stderr else e)
            raise

    def verify_signature(self, gpg_cmd: str = "gpg") -> bool:
        if self.backend != "file":
            raise RuntimeError("Verify supported only for file backend")
        sig_path = self.path.with_suffix(self.path.suffix + ".sig")
        if not sig_path.exists():
            logger.warning("Signature file not found: %s", sig_path)
            return False
        cmd = [gpg_cmd, "--verify", str(sig_path), str(self.path)]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("Signature OK")
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Signature verification failed: %s", e.stderr.decode() if e.stderr else e)
            return False

# ---------------- CLI ----------------

def _build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkgtool-db", description="Database tool for pkgtool (pkgtool-db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List installed packages").add_argument("--regex", help="Filter by regex", default=None)

    p_info = sub.add_parser("info", help="Show package info")
    p_info.add_argument("name", help="Package name")

    p_add = sub.add_parser("add", help="Add package record (JSON string or @file)")
    p_add.add_argument("pkg", help="Package JSON or @path")
    p_add.add_argument("--persist", action="store_true", help="Persist immediately")

    p_rm = sub.add_parser("remove", help="Remove package")
    p_rm.add_argument("name", help="Package name")
    p_rm.add_argument("--persist", action="store_true")

    p_up = sub.add_parser("update", help="Update package")
    p_up.add_argument("name", help="Package name")
    p_up.add_argument("updates", help="JSON dict or @file")
    p_up.add_argument("--persist", action="store_true")

    p_owns = sub.add_parser("owns", help="Show which package owns a file")
    p_owns.add_argument("file", help="File path")

    p_search = sub.add_parser("search", help="Search packages")
    p_search.add_argument("pattern", help="Regex pattern")

    p_export = sub.add_parser("export", help="Export DB")
    p_export.add_argument("--out", "-o", help="Output file (stdout if omitted)")
    p_export.add_argument("--format", "-f", choices=["json", "yaml"], default=None)

    p_check = sub.add_parser("check", help="Check integrity")
    p_check.add_argument("--check-files", action="store_true", help="Verify files exist on FS")

    p_hist = sub.add_parser("history", help="Show transaction history")
    p_hist.add_argument("--limit", type=int, default=100)

    p_snap = sub.add_parser("snapshot", help="Create snapshot of current DB")
    p_snap.add_argument("--name", help="Optional name", default=None)

    p_list_snaps = sub.add_parser("snapshots", help="List snapshots")

    p_restore = sub.add_parser("restore", help="Restore snapshot")
    p_restore.add_argument("snapshot", help="Snapshot filename or path")

    p_sign = sub.add_parser("sign", help="Sign DB with GPG")
    p_sign.add_argument("--key", help="GPG key id", default=None)

    p_verify = sub.add_parser("verify", help="Verify DB signature")

    p_migrate = sub.add_parser("migrate", help="Migrate backend")
    p_migrate.add_argument("backend", choices=["file", "sqlite"])
    p_migrate.add_argument("--format", choices=["json", "yaml"], help="Format (for file)")

    p_stats = sub.add_parser("stats", help="Show DB stats")

    p_gc = sub.add_parser("gc", help="Run garbage collection (reindex, prune snapshots)")

    return p

def _read_json_or_file(arg: str) -> Dict[str, Any]:
    if arg.startswith("@"):
        p = Path(arg[1:])
        if not p.exists():
            raise FileNotFoundError("File not found: " + str(p))
        s = p.read_text(encoding="utf-8")
    else:
        s = arg
    return json.loads(s)

def cli_main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    # build db from config if possible
    try:
        db = PackageDB.from_config(cfg) if cfg is not None else PackageDB(Path.cwd() / "Pkgtool" / "pkgtool1.0" / "db.json")
    except Exception:
        db = PackageDB(Path.cwd() / "Pkgtool" / "pkgtool1.0" / "db.json")
    try:
        db.load()
    except Exception as e:
        logger.warning("DB load warning: %s", e)

    try:
        if args.cmd == "list":
            res = db.list_packages(regex=getattr(args, "regex", None))
            for r in res:
                print(f"{r['name']} {r.get('version','')}")
            return 0

        if args.cmd == "info":
            name = args.name
            rec = db.get_package(name)
            print(json.dumps(rec, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "add":
            payload = _read_json_or_file(args.pkg)
            db.add_package(payload, overwrite=False, persist=bool(args.persist))
            print("Added package", payload.get("name"))
            return 0

        if args.cmd == "remove":
            db.remove_package(args.name, persist=bool(args.persist))
            print("Removed", args.name)
            return 0

        if args.cmd == "update":
            updates = _read_json_or_file(args.updates)
            db.update_package(args.name, updates, persist=bool(args.persist))
            print("Updated", args.name)
            return 0

        if args.cmd == "owns":
            owners = db.file_owner(args.file)
            if not owners:
                print("No owner found")
            else:
                for o in owners:
                    print(o)
            return 0

        if args.cmd == "search":
            res = db.search(args.pattern)
            for r in res:
                print(f"{r['name']} {r.get('version','')}")
            return 0

        if args.cmd == "export":
            out = getattr(args, "out", None)
            fmt = getattr(args, "format", None) or db.format
            data = {n: rec for n, rec in db._data.items()}
            s = json.dumps(data, indent=2, ensure_ascii=False) if fmt == "json" else (yaml.safe_dump(data, sort_keys=False) if _have_yaml else json.dumps(data, indent=2, ensure_ascii=False))
            if out:
                Path(out).write_text(s, encoding="utf-8")
                print("Exported to", out)
            else:
                print(s)
            return 0

        if args.cmd == "check":
            res = db.check_integrity(check_files_exist=bool(args.check_files))
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "history":
            h = db.history(limit=args.limit)
            print(json.dumps(h, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "snapshot":
            snap = db._write_snapshot()
            print("Snapshot:", snap)
            return 0

        if args.cmd == "snapshots":
            snaps = db.list_snapshots()
            for s in snaps:
                print(s)
            return 0

        if args.cmd == "restore":
            db.restore_snapshot(args.snapshot)
            print("Restored snapshot")
            return 0

        if args.cmd == "sign":
            db.sign_db(key=getattr(args, "key", None))
            print("Signed DB")
            return 0

        if args.cmd == "verify":
            ok = db.verify_signature()
            print("Signature OK" if ok else "Signature invalid")
            return 0

        if args.cmd == "migrate":
            db.migrate_backend(args.backend, new_format=getattr(args, "format", None))
            print("Migration complete")
            return 0

        if args.cmd == "stats":
            s = db.stats()
            print(json.dumps(s, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "gc":
            res = db.gc()
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        logger.exception("Error in pkgtool-db CLI: %s", e)
        print("Error:", e, file=sys.stderr)
        return 2

    return 0

# ---------------- Auto-run when executed ----------------

if __name__ == "__main__":
    sys.exit(cli_main())
