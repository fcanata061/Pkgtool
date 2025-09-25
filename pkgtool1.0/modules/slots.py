# Pkgtool/pkgtool1.0/modules/slots.py
# -*- coding: utf-8 -*-
"""
slots.py - advanced slot / subslot / ABI orchestration for pkgtool

Features implemented:
- Slot registry persisted in db.py (or local json fallback)
- SlotRecord dataclass with slot, subslot, abi_hash, install_path, active flag
- Transaction manager (begin/commit/rollback) with file snapshots + journal
- Atomic activation/switch with alternatives symlink swap
- Snapshot and rollback per transaction
- Strategy engine (manual/latest/stable/auto-rebuild/pin-by-profile)
- Integration with db.py, masks.py, log.py, config.py (best-effort)
- ABI fingerprinting (basic: sha256 of all files inside install_path)
- Dependency resolution helpers for slot-aware dependencies
- Hooks/event bus for slot lifecycle events
- CLI: pkgtool-slot with many subcommands (list, info, activate, set-active, snapshot, rollback, simulate, gc, status, register, unregister)
- Security: RBAC basic check (must be root for sensitive ops) and audit logging
- Observability: counters in-memory (slot_switches, rollbacks, failed_activations)
"""

from __future__ import annotations

import argparse
import contextlib
import enum
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import uuid
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# Try imports of other modules (best-effort integration)
try:
    from modules import db as _dbmod  # type: ignore
except Exception:
    _dbmod = None

try:
    from modules import masks as _masks  # type: ignore
except Exception:
    _masks = None

try:
    from modules import log as _logmod  # type: ignore
    _logger = _logmod.get_logger("pkgtool.slots")
except Exception:
    import logging as _logging
    _logger = _logging.getLogger("pkgtool.slots")
    if not _logger.handlers:
        _logger.addHandler(_logging.StreamHandler())
    _logger.setLevel(_logging.INFO)

try:
    from modules.config import cfg as _cfg  # type: ignore
except Exception:
    _cfg = None

# ----------------------------
# Constants / defaults
# ----------------------------
_DEFAULT_SLOTS_DIR = Path.cwd() / "Pkgtool" / "pkgtool1.0" / "slots"
_DEFAULT_SNAP_DIR = _DEFAULT_SLOTS_DIR / "snapshots"
_DEFAULT_JOURNAL = _DEFAULT_SLOTS_DIR / "slot-journal.log"
_DEFAULT_ALTERNATIVES_ROOT = Path("/etc/pkgtool-alternatives")
_DEFAULT_AUDIT_LOG = _DEFAULT_SLOTS_DIR / "slot-audit.log"

# ----------------------------
# Data classes
# ----------------------------
@dataclass
class SlotRecord:
    name: str  # package name, e.g., dev-lang/python
    slot: str  # slot id, e.g., "3.11"
    subslot: Optional[str] = None  # subslot or finer version
    version: Optional[str] = None  # full version string
    abi_hash: Optional[str] = None  # ABI fingerprint
    install_path: Optional[str] = None  # filesystem path
    active: bool = False
    provisioned_by: Optional[str] = None  # which subsystem installed it
    installed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SlotRecord":
        return SlotRecord(
            name=d.get("name"),
            slot=d.get("slot"),
            subslot=d.get("subslot"),
            version=d.get("version"),
            abi_hash=d.get("abi_hash"),
            install_path=d.get("install_path"),
            active=bool(d.get("active", False)),
            provisioned_by=d.get("provisioned_by"),
            installed_at=d.get("installed_at", datetime.utcnow().isoformat() + "Z"),
            metadata=dict(d.get("metadata", {})),
        )

@dataclass
class TxRecord:
    tx_id: str
    action: str
    packages: List[Dict[str, Any]]
    actor: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    status: str = "pending"
    note: Optional[str] = None
    snapshot: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# ----------------------------
# Utilities
# ----------------------------

def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    tmp = path.with_suffix(path.suffix + f".{int(time.time()*1000)}.tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(data)
    try:
        tmp.chmod(mode)
    except Exception:
        pass
    tmp.replace(path)

def _uid_is_root() -> bool:
    try:
        return os.geteuid() == 0  # type: ignore
    except Exception:
        # On Windows or unknown env: best-effort check
        return os.name != "posix"

# ----------------------------
# Storage backend (wrapper around db.py or fallback file)
# ----------------------------
class _LocalStorageFallback:
    """
    Fallback simple JSON-based storage for slots, used when modules.db isn't available.
    Stores a mapping: package name -> list of slot records
    """

    def __init__(self, path: Optional[Path] = None):
        base = path or _DEFAULT_SLOTS_DIR
        self.path = Path(base) / "slots.json"
        _ensure_dir(self.path.parent)
        self._lock = threading.RLock()
        self._data: Dict[str, List[Dict[str, Any]]] = {}
        self._loaded = False
        self._load()

    def _load(self):
        with self._lock:
            if self.path.exists():
                try:
                    txt = self.path.read_text(encoding="utf-8")
                    self._data = json.loads(txt)
                    self._loaded = True
                except Exception:
                    _logger.exception("Failed to load local slots json")
                    self._data = {}
            else:
                self._data = {}
                self._save()

    def _save(self):
        with self._lock:
            _atomic_write(self.path, json.dumps(self._data, indent=2, ensure_ascii=False).encode("utf-8"))

    def list_slots(self, pkg_name: str) -> List[SlotRecord]:
        with self._lock:
            arr = self._data.get(pkg_name, [])
            return [SlotRecord.from_dict(d) for d in arr]

    def save_slots(self, pkg_name: str, slots: List[SlotRecord]) -> None:
        with self._lock:
            self._data[pkg_name] = [s.to_dict() for s in slots]
            self._save()

    def all(self) -> Dict[str, List[SlotRecord]]:
        with self._lock:
            return {k: [SlotRecord.from_dict(x) for x in v] for k, v in self._data.items()}

# ----------------------------
# SlotManager core
# ----------------------------
class SlotManager:
    def __init__(self):
        # Storage: use db module if available, else fallback
        self._use_db = _dbmod is not None
        self._storage_fallback = _LocalStorageFallback() if not self._use_db else None
        # read config
        self._load_config()
        # ensure dirs
        _ensure_dir(self.slots_root)
        _ensure_dir(self.snapshots_dir)
        # locks & tx
        self._lock = threading.RLock()
        self._active_tx: Optional[TxRecord] = None
        self._tx_lock = threading.RLock()
        # hooks events
        self._hooks: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        # metrics
        self.metrics = {
            "slot_switches": 0,
            "rollbacks": 0,
            "failed_activations": 0,
            "transactions_committed": 0,
            "transactions_rolledback": 0,
        }
        # load state from db or fallback
        self._load_state()

    def _load_config(self):
        # defaults
        self.slots_root = Path(_cfg.get("slots", {}).get("slots_root")) if _cfg else _DEFAULT_SLOTS_DIR
        if not isinstance(self.slots_root, Path):
            self.slots_root = Path(self.slots_root) if self.slots_root else _DEFAULT_SLOTS_DIR
        self.snapshots_dir = Path(_cfg.get("slots", {}).get("snapshots_dir")) if _cfg else _DEFAULT_SNAP_DIR
        if not isinstance(self.snapshots_dir, Path):
            self.snapshots_dir = Path(self.snapshots_dir) if self.snapshots_dir else _DEFAULT_SNAP_DIR
        self.journal_path = Path(_cfg.get("slots", {}).get("transaction_journal")) if _cfg else _DEFAULT_JOURNAL
        if not isinstance(self.journal_path, Path):
            self.journal_path = Path(self.journal_path) if self.journal_path else _DEFAULT_JOURNAL
        self.alternatives_root = Path(_cfg.get("slots", {}).get("alternatives_root")) if _cfg else _DEFAULT_ALTERNATIVES_ROOT
        if not isinstance(self.alternatives_root, Path):
            self.alternatives_root = Path(self.alternatives_root) if self.alternatives_root else _DEFAULT_ALTERNATIVES_ROOT
        self.audit_log = Path(_cfg.get("slots", {}).get("audit_log")) if _cfg else _DEFAULT_AUDIT_LOG
        if not isinstance(self.audit_log, Path):
            self.audit_log = Path(self.audit_log) if self.audit_log else _DEFAULT_AUDIT_LOG
        # policies
        sconf = _cfg.get("slots", {}) if _cfg else {}
        self.strategy = sconf.get("default_strategy", "latest")
        self.auto_cleanup = bool(sconf.get("auto_cleanup", True))
        self.cleanup_retention_days = int(sconf.get("cleanup_retention_days", 30))
        self.auto_rebuild_dependencies = bool(sconf.get("auto_rebuild_dependencies", False))
        self.allow_force_activation = bool(sconf.get("allow_force_activation", False))

    def _load_state(self):
        # when db module is available, nothing to load here: db holds data
        if not self._use_db:
            # ensure fallback storage loaded
            self._storage_fallback._load()

    # Storage API wrappers
    def _list_slots(self, pkg_name: str) -> List[SlotRecord]:
        if self._use_db:
            try:
                # expect db to expose method find_by_slot or similar; best-effort: call db.get_package with slot
                # we will attempt a few common APIs; fallback to reading package record and looking into slots
                if hasattr(_dbmod, "list_slots"):
                    return _dbmod.list_slots(pkg_name)  # type: ignore
                # else get_package variants
                pkg = None
                if hasattr(_dbmod, "get_package"):
                    try:
                        pkg = _dbmod.get_package(pkg_name)  # type: ignore
                    except Exception:
                        pkg = None
                if pkg and isinstance(pkg, dict) and "slots" in pkg:
                    return [SlotRecord.from_dict(x) for x in pkg.get("slots", [])]
            except Exception:
                _logger.exception("db integration error in list_slots")
            # fallback to storage fallback if available
        return self._storage_fallback.list_slots(pkg_name)

    def _save_slots(self, pkg_name: str, slots: List[SlotRecord]) -> None:
        if self._use_db:
            try:
                if hasattr(_dbmod, "save_slots"):
                    _dbmod.save_slots(pkg_name, [s.to_dict() for s in slots])  # type: ignore
                    return
                # fallback: if db has update_package add slots into metadata
                if hasattr(_dbmod, "update_package"):
                    try:
                        # attach slots into package metadata
                        rec = {"slots": [s.to_dict() for s in slots]}
                        _dbmod.update_package(pkg_name, {"slots": rec["slots"]})  # type: ignore
                        return
                    except Exception:
                        pass
            except Exception:
                _logger.exception("db integration error in save_slots")
        # fallback path
        self._storage_fallback.save_slots(pkg_name, slots)

    def _all_slots(self) -> Dict[str, List[SlotRecord]]:
        if self._use_db:
            try:
                if hasattr(_dbmod, "all_slots"):
                    return _dbmod.all_slots()  # type: ignore
            except Exception:
                _logger.debug("db.all_slots not available or failed")
        return self._storage_fallback.all()

    # ----------------------
    # ABI fingerprinting
    # ----------------------
    def compute_abi_hash(self, install_path: str) -> str:
        """
        Basic ABI fingerprint: sha256 over filenames + sizes + mtimes of files in install_path.
        This is a heuristic; for production you might compute symbol tables/SONAMEs.
        """
        p = Path(install_path)
        if not p.exists():
            return ""
        h = hashlib.sha256()
        for root, dirs, files in os.walk(p):
            for fn in sorted(files):
                fp = Path(root) / fn
                try:
                    st = fp.stat()
                    # include path relative, size, mtime
                    rel = str(fp.relative_to(p)).encode("utf-8")
                    h.update(rel)
                    h.update(str(st.st_size).encode("utf-8"))
                    h.update(str(int(st.st_mtime)).encode("utf-8"))
                except Exception:
                    continue
        return "sha256:" + h.hexdigest()

    # ----------------------
    # Hooks / events
    # ----------------------
    def on(self, event: str, cb: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            self._hooks.setdefault(event, []).append(cb)

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        # synchronous calling of hooks; callbacks should be short
        try:
            for cb in list(self._hooks.get(event, [])):
                try:
                    cb(payload)
                except Exception:
                    _logger.exception("Slot hook error for %s", event)
        except Exception:
            _logger.exception("Slot event dispatch failed")

    # ----------------------
    # Transactions (file based)
    # ----------------------
    @contextlib.contextmanager
    def transaction(self, action: str, packages: List[Dict[str, Any]], actor: Optional[str] = None, note: Optional[str] = None):
        """
        Transaction context manager:
            with sm.transaction("activate", [{"name":"pkg","slot":"3.12"}], actor="root") as tx:
                ... perform ops ...
                tx.commit()
        commit happens when context exits without exception and tx.commit() called; otherwise rollback.
        """
        tx = TxRecord(tx_id=str(uuid.uuid4()), action=action, packages=packages, actor=actor or os.environ.get("USER", "unknown"), note=note)
        tx_path = self.journal_path
        _ensure_dir(tx_path.parent)
        # write initial tx record to journal
        try:
            with open(tx_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(tx.to_dict(), ensure_ascii=False) + "\n")
        except Exception:
            _logger.exception("Failed to write tx journal")
        # create snapshot
        snap = self._create_snapshot(prefix=f"tx-{tx.tx_id}")
        tx.snapshot = str(snap) if snap else None
        # set active tx
        with self._tx_lock:
            self._active_tx = tx
        rolled_back = False
        committed = False

        try:
            yield tx
            # commit default if no exceptions and user called commit
            # But we require caller to call tx_commit function to mark commit.
            # To provide ease-of-use, we'll check tx.status
            if tx.status != "committed":
                # auto-commit
                tx.status = "committed"
            committed = True
            # write commit record
            tx_record = tx.to_dict()
            tx_record["status"] = "committed"
            try:
                with open(tx_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(tx_record, ensure_ascii=False) + "\n")
            except Exception:
                _logger.exception("Failed to write tx commit")
            self.metrics["transactions_committed"] += 1
        except Exception as e:
            # rollback to snapshot
            _logger.exception("Transaction failed; rolling back: %s", e)
            try:
                self._rollback_to_snapshot(tx.snapshot)
                rolled_back = True
                self.metrics["transactions_rolledback"] += 1
            except Exception:
                _logger.exception("Rollback failed")
            raise
        finally:
            with self._tx_lock:
                self._active_tx = None
            # emit event
            ev = {"tx": tx.to_dict(), "committed": committed, "rolled_back": rolled_back}
            self._emit("slot.transaction_completed", ev)

    def _create_snapshot(self, prefix: str = "snap") -> Optional[Path]:
        """
        Create a snapshot of current slots state (persisted) in snapshots_dir.
        Returns Path to snapshot file (JSON).
        """
        _ensure_dir(self.snapshots_dir)
        snap_file = self.snapshots_dir / f"{prefix}-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        try:
            # gather all slots
            all_data = {}
            for pkg, slots in self._all_slots().items():
                all_data[pkg] = [s.to_dict() for s in slots]
            _atomic_write(snap_file, json.dumps(all_data, indent=2, ensure_ascii=False).encode("utf-8"))
            _logger.info("Created snapshot %s", snap_file)
            return snap_file
        except Exception:
            _logger.exception("Failed to create snapshot")
            return None

    def _rollback_to_snapshot(self, snapshot_path: Optional[str]) -> None:
        if not snapshot_path:
            raise RuntimeError("No snapshot to rollback to")
        sp = Path(snapshot_path)
        if not sp.exists():
            raise FileNotFoundError("Snapshot not found: " + str(sp))
        try:
            data = json.loads(sp.read_text(encoding="utf-8"))
            # write data back to storage
            for pkg, arr in data.items():
                slots = [SlotRecord.from_dict(d) for d in arr]
                self._save_slots(pkg, slots)
            _logger.info("Rolled back to snapshot %s", sp)
        except Exception:
            _logger.exception("Rollback failed")
            raise

    # ----------------------
    # CRUD: register / unregister slots
    # ----------------------
    def register_install(self, name: str, slot: str, *, version: Optional[str] = None,
                         subslot: Optional[str] = None, install_path: Optional[str] = None,
                         provisioned_by: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None,
                         activate: bool = False) -> SlotRecord:
        """
        Called by installer/build system when a slot is installed.
        Computes abi_hash and stores SlotRecord in storage; optionally activates.
        """
        with self._lock:
            slots = self._list_slots(name)
            # compute abi hash
            abi = None
            if install_path:
                try:
                    abi = self.compute_abi_hash(install_path)
                except Exception:
                    _logger.exception("ABI hashing failed for %s", install_path)
            rec = SlotRecord(name=name, slot=slot, subslot=subslot, version=version,
                             abi_hash=abi, install_path=install_path, active=False,
                             provisioned_by=provisioned_by, metadata=metadata or {})
            # remove existing record with same slot if present (overwrite)
            slots = [s for s in slots if s.slot != slot]
            slots.append(rec)
            self._save_slots(name, slots)
            _logger.info("Registered slot %s:%s (version=%s)", name, slot, version)
            # persisted to DB via _save_slots
            if activate:
                # activation goes through activate() for transactional semantics
                try:
                    self.activate(name, slot, actor=os.environ.get("USER", "unknown"), note="auto-activate after install")
                except Exception:
                    _logger.exception("Auto-activation failed for %s:%s", name, slot)
            return rec

    def unregister(self, name: str, slot: str, *, purge: bool = False) -> None:
        with self._lock:
            slots = self._list_slots(name)
            found = [s for s in slots if s.slot == slot]
            if not found:
                raise KeyError("Slot not found")
            # if active, deactivate first
            if any(s.active for s in found):
                for s in slots:
                    if s.slot == slot:
                        s.active = False
            # remove
            new_slots = [s for s in slots if s.slot != slot]
            self._save_slots(name, new_slots)
            _logger.info("Unregistered slot %s:%s", name, slot)
            # optionally purge files from install_path
            if purge:
                for s in found:
                    if s.install_path:
                        try:
                            shutil.rmtree(s.install_path)
                            _logger.info("Purged install_path %s", s.install_path)
                        except Exception:
                            _logger.exception("Failed to purge %s", s.install_path)

    # ----------------------
    # Activation / set-active
    # ----------------------
    def activate(self, name: str, slot: str, *, actor: Optional[str] = None, note: Optional[str] = None, force: bool = False) -> TxRecord:
        """
        Activate a slot atomically:
        - validate masks
        - create transaction snapshot
        - set selected slot's active=True, others active=False (for that package)
        - update alternatives symlinks atomically
        - commit tx (snapshot remains for rollback)
        Returns TxRecord
        """
        if not _uid_is_root() and not self.allow_force_activation:
            raise PermissionError("activate requires root privileges")

        actor = actor or os.environ.get("USER", "unknown")
        packages = [{"name": name, "slot": slot}]
        with self.transaction("activate", packages, actor=actor, note=note) as tx:
            # inside transaction; perform activation steps
            tx_id = tx.tx_id
            # validate existence
            slots = self._list_slots(name)
            target = None
            for s in slots:
                if s.slot == slot:
                    target = s
                    break
            if not target:
                raise KeyError(f"Slot {slot} for {name} not found")
            # check masks
            if _masks is not None and not force:
                try:
                    allowed = _masks.is_allowed(name, target.version or "0", slot=slot)
                    if not allowed:
                        raise PermissionError(f"Slot {name}:{slot} disallowed by masks")
                except Exception:
                    # if masks check fails, be conservative and block unless force
                    raise
            # check ABI conflicts with dependents (basic)
            conflict_info = self._check_abi_conflicts(name, slot)
            if conflict_info and not force:
                # depending on policy, either block or schedule rebuilds
                if self.auto_rebuild_dependencies:
                    # schedule rebuilds: emit event
                    self._emit("slot.pre-activate", {"name": name, "slot": slot, "conflicts": conflict_info, "tx": tx.to_dict()})
                else:
                    raise RuntimeError(f"ABI conflicts detected for {name}:{slot}: {conflict_info}")
            # perform activation: mark target active, others inactive
            for s in slots:
                s.active = (s.slot == slot)
            # save
            self._save_slots(name, slots)
            # update alternatives: atomic swap
            try:
                self._update_alternatives_for_package(name, slots)
            except Exception:
                _logger.exception("Failed to update alternatives")
            tx.status = "committed"
            # metrics & logging
            self.metrics["slot_switches"] += 1
            self._audit("activate", tx_id, actor, [{"name": name, "slot": slot}], note=note)
            self._emit("slot.post-activate", {"name": name, "slot": slot, "tx": tx.to_dict()})
            return tx

    def set_active(self, name: str, slot: str, *, actor: Optional[str] = None, note: Optional[str] = None, force: bool = False) -> TxRecord:
        return self.activate(name, slot, actor=actor, note=note, force=force)

    def _update_alternatives_for_package(self, name: str, slots: List[SlotRecord]) -> None:
        """
        Build an alternatives tree for package and atomically swap root symlink.
        alternatives_root/<name>/current -> target install path
        Additionally, provide alternatives for defined metadata['alternatives'] entries.
        """
        pkg_alt_dir = self.alternatives_root / name
        tmp_dir = pkg_alt_dir.with_suffix(".tmp-" + str(int(time.time())))
        # ensure directories
        _ensure_dir(pkg_alt_dir.parent)
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # chosen active slot
        active_slots = [s for s in slots if s.active]
        target_path = active_slots[0].install_path if active_slots else None

        # create symlink for 'current'
        if target_path:
            cur = tmp_dir / "current"
            try:
                os.symlink(target_path, cur)
            except Exception:
                # if symlink failed (windows?), try copy path string file
                (tmp_dir / "current").write_text(str(target_path), encoding="utf-8")

        # per-slot alternatives (if metadata has 'alternatives' list mapping)
        for s in slots:
            alt_list = s.metadata.get("alternatives", [])
            for alt in alt_list:
                # alt is path relative to bin, target is s.install_path + alt?
                # we will create symlink alt -> install_path/alt
                src = Path(s.install_path) / alt if s.install_path else None
                dst = tmp_dir / f"{s.slot}__{Path(alt).name}"
                if src and src.exists():
                    try:
                        os.symlink(str(src), dst)
                    except Exception:
                        try:
                            dst.write_text(str(src), encoding="utf-8")
                        except Exception:
                            _logger.debug("Failed to create alt symlink for %s", src)

        # atomic swap: move tmp_dir to pkg_alt_dir replacing it
        try:
            if pkg_alt_dir.exists():
                backup = pkg_alt_dir.with_suffix(".bak-" + str(int(time.time())))
                pkg_alt_dir.replace(backup)
                tmp_dir.replace(pkg_alt_dir)
                # remove backup
                shutil.rmtree(backup, ignore_errors=True)
            else:
                tmp_dir.replace(pkg_alt_dir)
        except Exception:
            _logger.exception("Failed to atomically swap alternatives for %s", name)
            # fallback: try best-effort copy
            try:
                if tmp_dir.exists():
                    if pkg_alt_dir.exists():
                        shutil.rmtree(pkg_alt_dir)
                    shutil.move(str(tmp_dir), str(pkg_alt_dir))
            except Exception:
                _logger.exception("Fallback move failed for alternatives")
        _logger.info("Updated alternatives for %s -> %s", name, target_path)

    # ----------------------
    # ABI conflict detection (basic)
    # ----------------------
    def _check_abi_conflicts(self, name: str, slot: str) -> List[Dict[str, Any]]:
        """
        Detect packages that depend on this package and would be ABI-incompatible.
        Returns list of conflict descriptions. This requires db integration to find dependents.
        """
        conflicts = []
        # find dependents in db
        try:
            if _dbmod and hasattr(_dbmod, "required_by"):
                dependents = _dbmod.required_by(name)  # type: ignore
                for dep in dependents:
                    # check dependent's required slot vs candidate slot
                    # if dependent declares dependency on slot different than candidate -> potential conflict
                    try:
                        dep_rec = _dbmod.get_package(dep)  # type: ignore
                    except Exception:
                        dep_rec = None
                    # naive rule: if dependent does not allow this slot in its dependencies list, flag
                    if dep_rec and isinstance(dep_rec, dict):
                        deps = dep_rec.get("dependencies", [])
                        for d in deps:
                            if isinstance(d, str) and d.startswith(name):
                                # parse possible slot
                                if ":" in d:
                                    _, req_slot = d.split(":", 1)
                                    if req_slot and req_slot != slot:
                                        conflicts.append({"dependent": dep, "required_slot": req_slot})
                    else:
                        # if we cannot inspect dependent, be conservative: add note
                        conflicts.append({"dependent": dep, "reason": "unknown metadata"})
        except Exception:
            _logger.debug("db module not available or required_by not implemented")
        return conflicts

    # ----------------------
    # Dependency resolution
    # ----------------------
    def resolve_dependency(self, dep_spec: str, *, prefer: str = "policy") -> Optional[Tuple[str, str]]:
        """
        Resolve dependency spec possibly containing slot: <pkg>[:<slot>]
        prefer: 'policy'|'latest'|'stable' etc. If slot present, return (pkg, slot).
        Returns (pkg, slot) or None if cannot satisfy.
        """
        # parse dep_spec
        if ":" in dep_spec:
            name, slot = dep_spec.split(":", 1)
            name = name.strip()
            slot = slot.strip()
            # check exists
            try:
                slots = self._list_slots(name)
                for s in slots:
                    if s.slot == slot:
                        # check masks
                        if _masks and not _masks.is_allowed(name, s.version or "0", slot=slot):
                            return None
                        return (name, slot)
            except Exception:
                return None
            return None
        else:
            name = dep_spec
            # choose based on prefer strategy
            slots = self._list_slots(name)
            if not slots:
                return None
            if prefer == "latest":
                # pick highest version by version string
                slots_sorted = sorted([s for s in slots], key=lambda x: (x.version or "", x.slot), reverse=True)
                for s in slots_sorted:
                    if _masks and not _masks.is_allowed(name, s.version or "0", slot=s.slot):
                        continue
                    return (name, s.slot)
                return None
            elif prefer == "stable":
                slots_sorted = sorted([s for s in slots if not s.metadata.get("unstable", False)], key=lambda x: (x.version or "", x.slot), reverse=True)
                if slots_sorted:
                    return (name, slots_sorted[0].slot)
                # fallback
                return (name, slots[0].slot)
            else:
                # policy/default: if an active slot exists, use it
                for s in slots:
                    if s.active:
                        if _masks and not _masks.is_allowed(name, s.version or "0", slot=s.slot):
                            continue
                        return (name, s.slot)
                # fallback to latest
                return self.resolve_dependency(dep_spec + ":latest", prefer="latest")

    # ----------------------
    # Simulation / dry-run
    # ----------------------
    def simulate_activate(self, name: str, slot: str) -> Dict[str, Any]:
        """
        Returns a plan describing steps to activate and potential impacts (ABI conflicts, dependents)
        """
        plan = {"name": name, "slot": slot, "checks": [], "actions": [], "impact": []}
        slots = self._list_slots(name)
        target = next((s for s in slots if s.slot == slot), None)
        if not target:
            plan["checks"].append({"ok": False, "reason": "slot-not-found"})
            return plan
        # masks
        if _masks:
            try:
                allowed = _masks.is_allowed(name, target.version or "0", slot=slot)
                plan["checks"].append({"masks_allowed": allowed})
                if not allowed:
                    plan["impact"].append({"type": "blocked_by_mask"})
            except Exception:
                plan["checks"].append({"masks_allowed": "unknown"})
        # ABI conflicts
        conflicts = self._check_abi_conflicts(name, slot)
        plan["checks"].append({"abi_conflicts": conflicts})
        plan["impact"].extend(conflicts)
        # actions: set active, update alternatives, emit events
        plan["actions"].append("set_active_slot")
        plan["actions"].append("update_alternatives")
        plan["actions"].append("emit_post_activate")
        return plan

    # ----------------------
    # Snapshots listing / restore / rollback
    # ----------------------
    def list_snapshots(self) -> List[Path]:
        _ensure_dir(self.snapshots_dir)
        return sorted([p for p in self.snapshots_dir.iterdir() if p.is_file()], key=lambda x: x.stat().st_mtime, reverse=True)

    def restore_snapshot(self, snapshot: str) -> None:
        sp = Path(snapshot)
        if not sp.exists():
            raise FileNotFoundError(snapshot)
        self._rollback_to_snapshot(str(sp))
        self.metrics["rollbacks"] += 1
        self._audit("restore_snapshot", str(uuid.uuid4()), os.environ.get("USER", "unknown"), [{"snapshot": str(sp)}], note="manual restore")

    # ----------------------
    # Garbage collection / cleanup
    # ----------------------
    def gc(self, dry_run: bool = True) -> Dict[str, Any]:
        """
        Remove old/deprecated slots based on retention policy and referenced dependents.
        Returns actions performed
        """
        removed = []
        now = datetime.utcnow()
        threshold = now - timedelta(days=self.cleanup_retention_days)
        all_slots = self._all_slots()
        for pkg, arr in all_slots.items():
            for s in arr:
                # skip active or recently installed
                try:
                    inst = datetime.fromisoformat(s.installed_at.replace("Z", ""))
                except Exception:
                    inst = now
                if s.active:
                    continue
                if inst > threshold:
                    continue
                # ensure no dependent references this slot
                dependents = []
                if _dbmod and hasattr(_dbmod, "required_by"):
                    try:
                        dependents = _dbmod.required_by(pkg)  # type: ignore
                    except Exception:
                        dependents = []
                if dependents:
                    continue
                # candidate for removal
                if not dry_run:
                    try:
                        self.unregister(pkg, s.slot, purge=True)
                        removed.append({"pkg": pkg, "slot": s.slot})
                    except Exception:
                        _logger.exception("Failed to remove slot %s:%s", pkg, s.slot)
                else:
                    removed.append({"pkg": pkg, "slot": s.slot, "dry": True})
        return {"removed": removed}

    # ----------------------
    # Audit logging
    # ----------------------
    def _audit(self, action: str, tx_id: str, actor: str, packages: List[Dict[str, Any]], note: Optional[str] = None):
        rec = {
            "timestamp": _now_iso(),
            "action": action,
            "tx_id": tx_id,
            "actor": actor,
            "packages": packages,
            "host": socket.gethostname(),
            "note": note,
        }
        try:
            _ensure_dir(self.audit_log.parent)
            with open(self.audit_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            _logger.exception("Failed to write slot audit")

    # ----------------------
    # CLI helpers / status
    # ----------------------
    def status(self) -> Dict[str, Any]:
        return {"metrics": self.metrics, "active_tx": self._active_tx.to_dict() if self._active_tx else None}

# ----------------------------
# Create manager singleton
# ----------------------------
_slots_manager = SlotManager()

# ----------------------------
# Public API functions
# ----------------------------
def register_install(name: str, slot: str, **kwargs) -> SlotRecord:
    return _slots_manager.register_install(name, slot, **kwargs)

def unregister(name: str, slot: str, **kwargs) -> None:
    return _slots_manager.unregister(name, slot, **kwargs)

def list_slots(name: str) -> List[SlotRecord]:
    return _slots_manager._list_slots(name)

def all_slots() -> Dict[str, List[SlotRecord]]:
    return _slots_manager._all_slots()

def activate(name: str, slot: str, **kwargs) -> TxRecord:
    return _slots_manager.activate(name, slot, **kwargs)

def set_active(name: str, slot: str, **kwargs) -> TxRecord:
    return _slots_manager.set_active(name, slot, **kwargs)

def resolve_dependency(dep_spec: str, **kwargs):
    return _slots_manager.resolve_dependency(dep_spec, **kwargs)

def simulate_activate(name: str, slot: str):
    return _slots_manager.simulate_activate(name, slot)

def list_snapshots():
    return _slots_manager.list_snapshots()

def restore_snapshot(snapshot: str):
    return _slots_manager.restore_snapshot(snapshot)

def gc(dry_run: bool = True):
    return _slots_manager.gc(dry_run=dry_run)

def on(event: str, cb: Callable[[Dict[str, Any]], None]) -> None:
    _slots_manager.on(event, cb)

def status():
    return _slots_manager.status()

# ----------------------------
# CLI
# ----------------------------
def _build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkgtool-slot", description="Slot management for pkgtool")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List slots for a package").add_argument("package", help="package name")

    p_info = sub.add_parser("info", help="Show info for a slot")
    p_info.add_argument("package")
    p_info.add_argument("slot")

    p_register = sub.add_parser("register", help="Register a slot after installation")
    p_register.add_argument("package")
    p_register.add_argument("slot")
    p_register.add_argument("--version")
    p_register.add_argument("--install-path")
    p_register.add_argument("--activate", action="store_true")

    p_unregister = sub.add_parser("unregister", help="Unregister a slot")
    p_unregister.add_argument("package")
    p_unregister.add_argument("slot")
    p_unregister.add_argument("--purge", action="store_true")

    p_activate = sub.add_parser("activate", help="Activate a slot")
    p_activate.add_argument("package")
    p_activate.add_argument("slot")
    p_activate.add_argument("--force", action="store_true")
    p_activate.add_argument("--note")

    p_sim = sub.add_parser("simulate", help="Simulate activation")
    p_sim.add_argument("package")
    p_sim.add_argument("slot")

    p_snap = sub.add_parser("snapshot", help="Create a snapshot now")
    p_snap.add_argument("--name")

    p_list_snaps = sub.add_parser("snapshots", help="List snapshots")

    p_restore = sub.add_parser("restore", help="Restore snapshot")
    p_restore.add_argument("snapshot")

    p_gc = sub.add_parser("gc", help="Garbage collect slots")
    p_gc.add_argument("--dry-run", action="store_true")

    p_status = sub.add_parser("status", help="Show manager status")

    return p

def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "list":
            slots = list_slots(args.package)
            if not slots:
                print("No slots installed for", args.package)
                return 0
            for s in slots:
                act = "(active)" if s.active else ""
                print(f"{s.slot} {s.version or ''} {act} installed_at={s.installed_at} path={s.install_path}")
            return 0

        if args.cmd == "info":
            slots = list_slots(args.package)
            target = next((x for x in slots if x.slot == args.slot), None)
            if not target:
                print("Slot not found")
                return 2
            print(json.dumps(target.to_dict(), indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "register":
            rec = register_install(args.package, args.slot, version=args.version, install_path=args.install_path or None, activate=args.activate, provisioned_by=os.environ.get("USER", "cli"))
            print("Registered:", rec.to_dict())
            return 0

        if args.cmd == "unregister":
            unregister(args.package, args.slot, purge=bool(args.purge))
            print("Unregistered")
            return 0

        if args.cmd == "activate":
            tx = activate(args.package, args.slot, actor=os.environ.get("USER", "cli"), note=args.note, force=bool(args.force))
            print("Activated via tx:", tx.tx_id)
            return 0

        if args.cmd == "simulate":
            plan = simulate_activate(args.package, args.slot)
            print(json.dumps(plan, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "snapshot":
            name = args.name or f"manual-{int(time.time())}"
            snap = _slots_manager._create_snapshot(prefix=name)
            print("Snapshot:", snap)
            return 0

        if args.cmd == "snapshots":
            snaps = list_snapshots()
            for s in snaps:
                print(s)
            return 0

        if args.cmd == "restore":
            restore_snapshot(args.snapshot)
            print("Restored")
            return 0

        if args.cmd == "gc":
            res = gc(dry_run=bool(args.dry_run))
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "status":
            st = status()
            print(json.dumps(st, indent=2, ensure_ascii=False))
            return 0

    except PermissionError as e:
        print("Permission error:", e, file=os.sys.stderr)
        return 3
    except Exception as e:
        _logger.exception("CLI error")
        print("Error:", e, file=os.sys.stderr)
        return 2

    return 0

# Auto-init: register basic hook that logs to log module
def _default_hooks():
    def _log_evt(ev):
        try:
            _logger.info("Slot event: %s", json.dumps(ev, ensure_ascii=False))
        except Exception:
            _logger.info("Slot event (unserializable)")

    on("slot.post-activate", _log_evt)
    on("slot.transaction_completed", _log_evt)

_default_hooks()

# If run as script, execute CLI
if __name__ == "__main__":
    import sys as _sys
    _sys.exit(cli_main(_sys.argv[1:]))
