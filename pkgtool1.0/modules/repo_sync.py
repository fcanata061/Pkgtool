# Pkgtool/pkgtool1.0/modules/repo_sync.py
# -*- coding: utf-8 -*-
"""
repo_sync.py - repository synchronization subsystem for pkgtool

Features:
- Multi-backend sync: git, rsync, tarball (http/https), local copy
- Multiple mirrors per repo with benchmark and fallback
- Incremental sync (git fetch, rsync incremental, tarball snapshots)
- Hooks: pre-sync, post-sync (commands), and event callbacks
- Snapshots and rollback (snapshot per successful sync, rollback on failure)
- Verification: checksum (sha256/sha512), GPG signature verification
- History and status per repo persisted to status files
- Daemon mode for periodic sync (simple threaded scheduler)
- Parallel sync support (thread pool)
- CLI: pkgtool-repo (sync, list, status, add, remove, rollback, test-mirrors, daemon)
- Integration with modules.config, modules.log, modules.db, modules.masks (best-effort)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Try optional imports / integratations
try:
    from modules import log as _logmod  # type: ignore
    logger = _logmod.get_logger("pkgtool.repo_sync")
except Exception:
    import logging as _logging
    logger = _logging.getLogger("pkgtool.repo_sync")
    if not logger.handlers:
        logger.addHandler(_logging.StreamHandler())
    logger.setLevel(_logging.INFO)

try:
    from modules.config import cfg as _cfg  # type: ignore
except Exception:
    _cfg = None

try:
    from modules import db as _dbmod  # type: ignore
except Exception:
    _dbmod = None

try:
    from modules import masks as _masks  # type: ignore
except Exception:
    _masks = None

# ---------------------------
# Defaults and paths
# ---------------------------
_DEFAULT_REPOS_DIR = Path.cwd() / "Pkgtool" / "pkgtool1.0" / "repos"
_DEFAULT_SNAP_DIR = _DEFAULT_REPOS_DIR / ".snapshots"
_DEFAULT_HISTORY_DIR = _DEFAULT_REPOS_DIR / ".history"
_DEFAULT_LOCK_DIR = _DEFAULT_REPOS_DIR / ".locks"
_DEFAULT_STATUS_FILE = _DEFAULT_REPOS_DIR / ".repo_status.json"
_DEFAULT_MAX_WORKERS = 4
_DEFAULT_SNAPSHOT_RETENTION = 7  # keep 7 snapshots by default

# ---------------------------
# Utilities
# ---------------------------

def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _atomic_write_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp.{int(time.time()*1000)}")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)

def _run_cmd(cmd: List[str], cwd: Optional[Path] = None, capture: bool = False, check: bool = True) -> Tuple[int, str, str]:
    logger.debug("Running command: %s (cwd=%s)", " ".join(cmd), cwd)
    try:
        p = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)
        out, err = p.communicate()
        ret = p.returncode
        sout = out.decode("utf-8", errors="replace") if out else ""
        serr = err.decode("utf-8", errors="replace") if err else ""
        if check and ret != 0:
            raise subprocess.CalledProcessError(ret, cmd, output=sout, stderr=serr)
        return ret, sout, serr
    except subprocess.CalledProcessError as e:
        logger.debug("Command error stdout: %s stderr: %s", e.output, e.stderr)
        raise

def _copytree(src: Path, dst: Path, ignore=None) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=ignore)

def _now_timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

# ---------------------------
# Repo data structures
# ---------------------------
@dataclass
class RepoConfig:
    name: str
    type: str  # git | rsync | tarball | local
    urls: List[str]  # mirrors (url or path)
    path: Path  # local path to store repository
    branch: Optional[str] = None  # for git
    auto_sync: bool = False
    priority: int = 0
    hooks: Dict[str, List[str]] = field(default_factory=dict)  # pre_sync, post_sync
    verify: Dict[str, Any] = field(default_factory=dict)  # e.g. {"gpg": True, "checksum": "sha256"}
    snapshot_retention: int = _DEFAULT_SNAPSHOT_RETENTION

    def to_dict(self):
        d = asdict(self)
        d["path"] = str(self.path)
        return d

@dataclass
class RepoStatus:
    name: str
    last_sync: Optional[str] = None
    status: str = "unknown"  # ok | failed | syncing | unknown
    detail: Optional[str] = None
    current_ref: Optional[str] = None  # git commit or snapshot id
    mirror_used: Optional[str] = None
    last_duration_s: Optional[float] = None
    last_files: Optional[int] = None

    def to_dict(self):
        return asdict(self)

# ---------------------------
# RepoManager core
# ---------------------------
class RepoManager:
    def __init__(self):
        # load config
        self.repos_dir = Path(_cfg.get("repos", {}).get("repos_root")) if _cfg else _DEFAULT_REPOS_DIR
        if not isinstance(self.repos_dir, Path):
            self.repos_dir = Path(self.repos_dir) if self.repos_dir else _DEFAULT_REPOS_DIR
        self.snapshots_dir = Path(_cfg.get("repos", {}).get("snapshots_dir")) if _cfg else _DEFAULT_SNAP_DIR
        if not isinstance(self.snapshots_dir, Path):
            self.snapshots_dir = Path(self.snapshots_dir) if self.snapshots_dir else _DEFAULT_SNAP_DIR
        self.history_dir = Path(_cfg.get("repos", {}).get("history_dir")) if _cfg else _DEFAULT_HISTORY_DIR
        if not isinstance(self.history_dir, Path):
            self.history_dir = Path(self.history_dir) if self.history_dir else _DEFAULT_HISTORY_DIR
        self.lock_dir = Path(_cfg.get("repos", {}).get("lock_dir")) if _cfg else _DEFAULT_LOCK_DIR
        if not isinstance(self.lock_dir, Path):
            self.lock_dir = Path(self.lock_dir) if self.lock_dir else _DEFAULT_LOCK_DIR
        self.max_workers = int(_cfg.get("repos", {}).get("max_workers", _DEFAULT_MAX_WORKERS)) if _cfg else _DEFAULT_MAX_WORKERS
        # state
        self.repo_configs: Dict[str, RepoConfig] = {}
        self.repo_status: Dict[str, RepoStatus] = {}
        _ensure_dir(self.repos_dir)
        _ensure_dir(self.snapshots_dir)
        _ensure_dir(self.history_dir)
        _ensure_dir(self.lock_dir)
        # load persisted configs from config file if present
        self._load_from_config()
        self._status_file = self.repos_dir / ".repo_manager_status.json"
        self._status_lock = threading.RLock()
        # event hooks (in-process)
        self._hooks: Dict[str, List[callable]] = {}
        # daemon state
        self._daemon_thread: Optional[threading.Thread] = None
        self._daemon_stop = threading.Event()

    def _load_from_config(self):
        """
        Loads repo list from configuration (cfg) under 'repos' key.
        Expected structure:
        repos:
          main:
            type: git
            url: ...
            urls: [...]
            branch: main
            path: /var/lib/pkgtool/repos/main
            auto_sync: true
            priority: 10
            hooks:
              pre_sync: [...]
              post_sync: [...]
            verify:
              gpg: true
              checksum: sha256
        """
        repos_conf = {}
        try:
            if _cfg is not None:
                repos_conf = _cfg.get("repos") or {}
        except Exception:
            repos_conf = {}
        # if repo conf is a mapping of named repos, consume them
        for name, conf in (repos_conf.items() if isinstance(repos_conf, dict) else []):
            try:
                typ = conf.get("type", "git")
                urls = []
                if "urls" in conf and conf.get("urls"):
                    urls = list(conf.get("urls"))
                elif "url" in conf and conf.get("url"):
                    url = conf.get("url")
                    if isinstance(url, (list, tuple)):
                        urls = list(url)
                    else:
                        urls = [url]
                path = conf.get("path") or str(self.repos_dir / name)
                branch = conf.get("branch")
                auto_sync = bool(conf.get("auto_sync", False))
                priority = int(conf.get("priority", 0) or 0)
                hooks = conf.get("hooks", {}) or {}
                verify = conf.get("verify", {}) or {}
                retention = int(conf.get("snapshot_retention", _DEFAULT_SNAPSHOT_RETENTION) or _DEFAULT_SNAPSHOT_RETENTION)
                rc = RepoConfig(name=name, type=typ, urls=urls, path=Path(path), branch=branch, auto_sync=auto_sync, priority=priority, hooks=hooks, verify=verify, snapshot_retention=retention)
                self.repo_configs[name] = rc
                # ensure status entry exists
                if name not in self.repo_status:
                    self.repo_status[name] = RepoStatus(name=name, status="unknown")
            except Exception:
                logger.exception("Failed to parse repo config for %s", name)

    # -------------------------
    # Hooks / events
    # -------------------------
    def on(self, event: str, cb: callable) -> None:
        self._hooks.setdefault(event, []).append(cb)

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        try:
            for cb in list(self._hooks.get(event, [])):
                try:
                    cb(payload)
                except Exception:
                    logger.exception("Hook callback failed for %s", event)
        except Exception:
            logger.exception("Hook emission failed")

    # -------------------------
    # Repo config management
    # -------------------------
    def list_repos(self) -> List[RepoConfig]:
        return list(self.repo_configs.values())

    def get_repo(self, name: str) -> RepoConfig:
        if name not in self.repo_configs:
            raise KeyError("Unknown repo: " + name)
        return self.repo_configs[name]

    def add_repo(self, cfg: Dict[str, Any], persist: bool = False) -> RepoConfig:
        name = cfg.get("name")
        if not name:
            raise ValueError("Repo config must include 'name'")
        if name in self.repo_configs:
            raise ValueError("Repo already exists: " + name)
        typ = cfg.get("type", "git")
        urls = cfg.get("urls") or ( [cfg.get("url")] if cfg.get("url") else [] )
        path = Path(cfg.get("path") or (self.repos_dir / name))
        branch = cfg.get("branch")
        rc = RepoConfig(name=name, type=typ, urls=urls, path=path, branch=branch, auto_sync=bool(cfg.get("auto_sync", False)), priority=int(cfg.get("priority", 0) or 0), hooks=cfg.get("hooks", {}) or {}, verify=cfg.get("verify", {}) or {})
        self.repo_configs[name] = rc
        self.repo_status.setdefault(name, RepoStatus(name=name))
        # persist to cfg if desired (best-effort)
        if persist and _cfg is not None:
            try:
                conf = _cfg.get_raw() if hasattr(_cfg, "get_raw") else None
                # writing back into config system is environment-specific; skip automatic persistence if not supported
            except Exception:
                logger.debug("No persistence for config available")
        return rc

    def remove_repo(self, name: str, remove_files: bool = False) -> None:
        if name not in self.repo_configs:
            raise KeyError("Unknown repo: " + name)
        cfg = self.repo_configs.pop(name)
        self.repo_status.pop(name, None)
        if remove_files and cfg.path.exists():
            shutil.rmtree(cfg.path, ignore_errors=True)

    # -------------------------
    # Lock helpers
    # -------------------------
    def _lock_path(self, name: str) -> Path:
        return self.lock_dir / f"{name}.lock"

    @contextlib.contextmanager
    def _repo_lock(self, name: str, timeout: float = 300.0):
        lock_file = self._lock_path(name)
        _ensure_dir(lock_file.parent)
        fh = open(lock_file, "w")
        got = False
        start = time.time()
        try:
            while True:
                try:
                    # flock
                    if os.name == "posix":
                        import fcntl
                        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        got = True
                        break
                    else:
                        # best effort: create file exclusively
                        if not lock_file.exists():
                            fh.write(str(os.getpid()))
                            fh.flush()
                            got = True
                            break
                except BlockingIOError:
                    pass
                if (time.time() - start) > timeout:
                    raise TimeoutError("Timeout acquiring lock for repo " + name)
                time.sleep(0.1)
            yield
        finally:
            try:
                if got:
                    if os.name == "posix":
                        import fcntl
                        fcntl.flock(fh, fcntl.LOCK_UN)
                    else:
                        try:
                            fh.close()
                            if lock_file.exists():
                                lock_file.unlink()
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                fh.close()
            except Exception:
                pass

    # -------------------------
    # Mirror selection & benchmarking
    # -------------------------
    def _choose_mirror(self, cfg: RepoConfig) -> Optional[str]:
        """
        Choose the best mirror by simple benchmark:
         - for http(s): HEAD request timing via curl or python (fallback)
         - for rsync/git: attempt quick connect (git ls-remote or rsync --list-only)
        Return first responsive mirror or fastest measured.
        """
        candidates = list(cfg.urls)
        if not candidates:
            return None
        results: List[Tuple[str, float]] = []
        for url in candidates:
            t0 = time.time()
            ok = False
            try:
                if url.startswith("http://") or url.startswith("https://"):
                    # try curl head if available
                    try:
                        _run_cmd(["curl", "-s", "-I", "--max-time", "5", url], capture=True, check=False)
                        ok = True
                    except Exception:
                        # fallback to Python request-like attempt
                        import urllib.request
                        req = urllib.request.Request(url, method="HEAD")
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            ok = True
                elif url.startswith("rsync://") or url.endswith("/"):
                    # attempt rsync list
                    try:
                        _run_cmd(["rsync", "--list-only", "--timeout=5", url], capture=True, check=False)
                        ok = True
                    except Exception:
                        ok = False
                elif url.startswith("git@") or url.endswith(".git") or url.startswith("ssh://") or url.startswith("git://"):
                    # use git ls-remote
                    try:
                        _run_cmd(["git", "ls-remote", "--heads", url], capture=True, check=False)
                        ok = True
                    except Exception:
                        ok = False
                else:
                    # local path
                    p = Path(url)
                    ok = p.exists()
            except Exception:
                ok = False
            elapsed = time.time() - t0
            if ok:
                results.append((url, elapsed))
        if not results:
            return None
        # choose fastest
        results.sort(key=lambda x: x[1])
        chosen = results[0][0]
        logger.debug("Mirror selection for %s: chosen %s (bench results: %s)", cfg.name, chosen, results)
        return chosen

    # -------------------------
    # Verification helpers
    # -------------------------
    def _verify_checksums(self, cfg: RepoConfig, path: Path) -> Tuple[bool, str]:
        """
        Verify checksums if repo provides a checksums file expected at path/<checksum_file>
        cfg.verify may include {"checksum": "sha256", "checksum_file": "SHA256SUMS"}
        """
        verify = cfg.verify or {}
        checksum_alg = verify.get("checksum")
        checksum_file = verify.get("checksum_file", "SHA256SUMS")
        if not checksum_alg:
            return True, "no_checksum_configured"
        chk_path = path / checksum_file
        if not chk_path.exists():
            return False, f"checksum file {checksum_file} not found"
        # parse SHA256SUMS style: "<hash>  <path>"
        try:
            lines = chk_path.read_text(encoding="utf-8").splitlines()
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 2:
                    h = parts[0]
                    rel = parts[-1]
                    fpath = path / rel
                    if not fpath.exists():
                        return False, f"file missing {rel}"
                    # compute hash
                    import hashlib
                    hfunc = getattr(hashlib, checksum_alg, None)
                    if hfunc is None:
                        return False, f"unsupported checksum algorithm {checksum_alg}"
                    with fpath.open("rb") as fh:
                        dh = hfunc()
                        for chunk in iter(lambda: fh.read(8192), b""):
                            dh.update(chunk)
                        if dh.hexdigest() != h.lower():
                            return False, f"checksum mismatch for {rel}"
            return True, "checksums_ok"
        except Exception as e:
            logger.exception("Checksum verification failed")
            return False, f"checksum_error: {e}"

    def _verify_gpg(self, cfg: RepoConfig, path: Path) -> Tuple[bool, str]:
        """
        If GPG verification requested, try to verify a signed file or tag.
        cfg.verify may include {"gpg": True, "signature_file": "SHA256SUMS.asc"}
        """
        verify = cfg.verify or {}
        if not verify.get("gpg"):
            return True, "no_gpg"
        sigfile = verify.get("signature_file", "SHA256SUMS.asc")
        sig_path = path / sigfile
        if not sig_path.exists():
            return False, f"signature file {sigfile} not found"
        # attempt gpg --verify signature checksumfile
        try:
            # find checksum file name: default SHA256SUMS
            checksum_file = verify.get("checksum_file", "SHA256SUMS")
            checksum_path = path / checksum_file
            if not checksum_path.exists():
                return False, f"checksum file {checksum_file} for signature not found"
            _run_cmd(["gpg", "--verify", str(sig_path), str(checksum_path)], capture=True, check=True)
            return True, "gpg_ok"
        except Exception as e:
            logger.exception("GPG verification failed")
            return False, f"gpg_failed: {e}"

    # -------------------------
    # Snapshot / rollback helpers
    # -------------------------
    def _snapshot_repo(self, cfg: RepoConfig) -> Optional[Path]:
        """
        Create a snapshot of repo path before applying changes. Snapshot is a directory copy.
        """
        try:
            _ensure_dir(self.snapshots_dir)
            snap_id = f"{cfg.name}-{_now_timestamp()}"
            snap_dir = self.snapshots_dir / snap_id
            if cfg.path.exists():
                shutil.copytree(cfg.path, snap_dir)
            else:
                snap_dir.mkdir(parents=True, exist_ok=True)
            # rotate snapshots for this repo
            self._rotate_snapshots(cfg)
            logger.info("Snapshot created for repo %s at %s", cfg.name, snap_dir)
            return snap_dir
        except Exception:
            logger.exception("Snapshot creation failed for %s", cfg.name)
            return None

    def _rotate_snapshots(self, cfg: RepoConfig) -> None:
        snaps = sorted([p for p in self.snapshots_dir.iterdir() if p.is_dir() and p.name.startswith(cfg.name+"-")], key=lambda p: p.stat().st_mtime, reverse=True)
        keep = int(cfg.snapshot_retention or _DEFAULT_SNAPSHOT_RETENTION)
        for p in snaps[keep:]:
            try:
                shutil.rmtree(p)
            except Exception:
                logger.exception("Failed to remove old snapshot %s", p)

    def _rollback_repo(self, cfg: RepoConfig, snapshot: Path) -> bool:
        try:
            if cfg.path.exists():
                shutil.rmtree(cfg.path)
            shutil.copytree(snapshot, cfg.path)
            logger.info("Rolled back repo %s to snapshot %s", cfg.name, snapshot)
            return True
        except Exception:
            logger.exception("Rollback failed for %s", cfg.name)
            return False

    # -------------------------
    # Backend sync implementations
    # -------------------------
    def _sync_git(self, cfg: RepoConfig, mirror: str, tmpdir: Path) -> Tuple[bool, str, int]:
        """
        Use git clone/fetch to update repository. Strategy:
         - if cfg.path/.git exists: git fetch + checkout branch
         - else: git clone (shallow by default)
        Returns (success, detail, files_count)
        """
        start = time.time()
        try:
            repo_path = cfg.path
            git_cmd = shutil.which("git")
            if git_cmd is None:
                raise RuntimeError("git not found")
            branch = cfg.branch or "master"
            if repo_path.joinpath(".git").exists():
                # fetch
                try:
                    _run_cmd([git_cmd, "fetch", "--all"], cwd=repo_path, capture=True, check=True)
                except Exception:
                    logger.warning("git fetch failed, attempting reclone")
                    shutil.rmtree(repo_path)
                    _run_cmd([git_cmd, "clone", "--depth", "1", "--branch", branch, mirror, str(repo_path)], capture=True, check=True)
                # checkout branch
                _run_cmd([git_cmd, "checkout", branch], cwd=repo_path, capture=True, check=True)
                _run_cmd([git_cmd, "pull", "--ff-only"], cwd=repo_path, capture=True, check=False)
            else:
                _ensure_dir(repo_path.parent)
                _run_cmd([git_cmd, "clone", "--depth", "1", "--branch", branch, mirror, str(repo_path)], capture=True, check=True)
            # after clone/pull, get current commit
            rc, out, _ = _run_cmd([git_cmd, "rev-parse", "HEAD"], cwd=repo_path, capture=True, check=True)
            commit = out.strip()
            duration = time.time() - start
            files_count = sum([len(files) for _, _, files in os.walk(repo_path)])
            return True, commit, files_count
        except Exception as e:
            logger.exception("Git sync failed for %s: %s", cfg.name, e)
            return False, str(e), 0

    def _sync_rsync(self, cfg: RepoConfig, mirror: str, tmpdir: Path) -> Tuple[bool, str, int]:
        """
        Use rsync to sync mirror into cfg.path (into tmpdir then replace).
        Returns (success, detail, files_count)
        """
        start = time.time()
        try:
            _ensure_dir(tmpdir)
            # rsync options: archive, compress, partial
            rsync_bin = shutil.which("rsync")
            if rsync_bin is None:
                raise RuntimeError("rsync not found")
            # destination is tmpdir
            cmd = [rsync_bin, "-a", "--delete", "--partial", "--inplace", mirror, str(tmpdir)]
            _run_cmd(cmd, capture=True, check=True)
            # stats: count files
            files_count = sum([len(files) for _, _, files in os.walk(tmpdir)])
            duration = time.time() - start
            return True, "rsync_ok", files_count
        except Exception as e:
            logger.exception("Rsync sync failed for %s: %s", cfg.name, e)
            return False, str(e), 0

    def _sync_tarball(self, cfg: RepoConfig, mirror: str, tmpdir: Path) -> Tuple[bool, str, int]:
        """
        Download tarball (http/https) and extract into tmpdir.
        Supports mirrors list: mirror could be direct tarball URL or directory containing tarballs.
        Returns (success, snapshot_id, files_count)
        """
        start = time.time()
        try:
            _ensure_dir(tmpdir)
            url = mirror
            # choose download tool: curl or wget or urllib
            fname = tmpdir / "snapshot.tar"
            # attempt curl
            try:
                curl = shutil.which("curl")
                if curl:
                    _run_cmd([curl, "-L", "-o", str(fname), "--fail", url], capture=True, check=True)
                else:
                    wget = shutil.which("wget")
                    if wget:
                        _run_cmd([wget, "-O", str(fname), url], capture=True, check=True)
                    else:
                        # fallback to urllib
                        import urllib.request
                        with urllib.request.urlopen(url, timeout=60) as resp:
                            with open(fname, "wb") as fh:
                                fh.write(resp.read())
            except Exception:
                raise
            # extract tarball
            import tarfile
            try:
                with tarfile.open(fname) as tf:
                    tf.extractall(path=str(tmpdir))
            except tarfile.ReadError:
                # try compressed suffixes
                with tarfile.open(fname, mode='r:*') as tf:
                    tf.extractall(path=str(tmpdir))
            files_count = sum([len(files) for _, _, files in os.walk(tmpdir)])
            duration = time.time() - start
            return True, "tarball_ok", files_count
        except Exception as e:
            logger.exception("Tarball sync failed for %s: %s", cfg.name, e)
            return False, str(e), 0

    def _sync_local(self, cfg: RepoConfig, mirror: str, tmpdir: Path) -> Tuple[bool, str, int]:
        """
        Mirror is a local path. Copy contents to tmpdir.
        """
        try:
            src = Path(mirror)
            if not src.exists():
                raise FileNotFoundError("local mirror not found: " + str(src))
            if tmpdir.exists():
                shutil.rmtree(tmpdir)
            shutil.copytree(src, tmpdir)
            files_count = sum([len(files) for _, _, files in os.walk(tmpdir)])
            return True, "local_copy", files_count
        except Exception as e:
            logger.exception("Local sync failed for %s: %s", cfg.name, e)
            return False, str(e), 0

    # -------------------------
    # High-level sync for a single repo
    # -------------------------
    def sync_repo(self, name: str, *, force: bool = False, dry_run: bool = False, mirror_override: Optional[str] = None) -> RepoStatus:
        if name not in self.repo_configs:
            raise KeyError("Unknown repo: " + name)
        cfg = self.repo_configs[name]
        status = self.repo_status.get(name, RepoStatus(name=name))
        start_time = time.time()
        status.status = "syncing"
        status.detail = "starting"
        self._persist_status()
        # lock repo
        with self._repo_lock(name):
            tmpdir = Path(tempfile.mkdtemp(prefix=f"repo_sync_{name}_"))
            chosen_mirror = mirror_override or self._choose_mirror(cfg)
            if not chosen_mirror:
                status.status = "failed"
                status.detail = "no_mirror"
                status.last_sync = _now_iso()
                self.repo_status[name] = status
                self._persist_status()
                shutil.rmtree(tmpdir, ignore_errors=True)
                self._emit("repo.sync_failed", {"name": name, "reason": "no_mirror"})
                return status
            status.mirror_used = chosen_mirror
            # run pre-sync hooks
            pre_hooks = cfg.hooks.get("pre_sync", []) if cfg.hooks else []
            for cmd in pre_hooks:
                try:
                    _run_cmd(cmd if isinstance(cmd, list) else cmd.split(), capture=False, check=True)
                except Exception:
                    logger.exception("Pre-sync hook failed for %s: %s", name, cmd)
                    # do not abort hooks failure necessarily
            # create snapshot before changes
            snapshot = self._snapshot_repo(cfg)
            # perform backend-specific sync into tmpdir
            success = False
            detail = ""
            files_count = 0
            try:
                if cfg.type == "git":
                    success, detail, files_count = self._sync_git(cfg, chosen_mirror, tmpdir)
                elif cfg.type == "rsync":
                    success, detail, files_count = self._sync_rsync(cfg, chosen_mirror, tmpdir)
                elif cfg.type == "tarball":
                    success, detail, files_count = self._sync_tarball(cfg, chosen_mirror, tmpdir)
                elif cfg.type == "local":
                    success, detail, files_count = self._sync_local(cfg, chosen_mirror, tmpdir)
                else:
                    raise ValueError("Unsupported repo type: " + cfg.type)
                # verification
                if success:
                    ok_chk, chk_detail = self._verify_checksums(cfg, tmpdir)
                    if not ok_chk:
                        raise RuntimeError("Checksum verification failed: " + chk_detail)
                    ok_gpg, gpg_detail = self._verify_gpg(cfg, tmpdir)
                    if not ok_gpg:
                        raise RuntimeError("GPG verification failed: " + gpg_detail)
                    # apply tmpdir to repo path atomically: move old to backup and move tmpdir
                    # use a temporary dir replacement
                    target = cfg.path
                    backup = None
                    if target.exists():
                        backup = target.with_suffix(".bak-" + _now_timestamp())
                        try:
                            target.replace(backup)
                        except Exception:
                            shutil.move(str(target), str(backup))
                    try:
                        shutil.move(str(tmpdir), str(target))
                    except Exception:
                        # restore backup if failed
                        if backup and backup.exists():
                            backup.replace(target)
                        raise
                    # record success
                    status.status = "ok"
                    status.detail = detail
                    status.last_sync = _now_iso()
                    status.last_duration_s = time.time() - start_time
                    status.last_files = files_count
                    status.current_ref = detail if cfg.type == "git" else (snapshot.name if snapshot else None)
                    # history
                    self._record_history(name, {"time": status.last_sync, "mirror": chosen_mirror, "detail": detail, "files": files_count})
                    # post-sync hooks
                    post_hooks = cfg.hooks.get("post_sync", []) if cfg.hooks else []
                    for cmd in post_hooks:
                        try:
                            _run_cmd(cmd if isinstance(cmd, list) else cmd.split(), capture=False, check=True)
                        except Exception:
                            logger.exception("Post-sync hook failed for %s: %s", name, cmd)
                    # Integration: notify other modules
                    try:
                        if _dbmod and hasattr(_dbmod, "repo_synced"):
                            _dbmod.repo_synced(name, status.to_dict())  # optional hook in db module
                    except Exception:
                        logger.debug("db.repo_synced not available or failed")
                    # apply masks and slots updates if provided by repo
                    try:
                        if _masks and hasattr(_masks, "import_rules"):
                            # optional: if repo contains masks.toml, import to masks
                            masks_file = cfg.path / "masks.toml"
                            if masks_file.exists():
                                _masks.import_rules(str(masks_file), scope=None, persist=True)
                    except Exception:
                        logger.debug("masks import failed or not available")
                    self._emit("repo.synced", {"name": name, "status": status.to_dict()})
                else:
                    # non-success path
                    status.status = "failed"
                    status.detail = detail
                    status.last_sync = _now_iso()
                    # rollback to snapshot if available
                    if snapshot:
                        self._rollback_repo(cfg, snapshot)
                        status.detail = "rolled_back_after_failed_sync"
                    self._emit("repo.sync_failed", {"name": name, "detail": detail})
            except Exception as e:
                logger.exception("Sync failed for repo %s: %s", name, e)
                status.status = "failed"
                status.detail = str(e)
                status.last_sync = _now_iso()
                # attempt rollback
                if snapshot:
                    try:
                        self._rollback_repo(cfg, snapshot)
                        status.detail = "rolled_back_after_exception"
                    except Exception:
                        logger.exception("Rollback after failed sync also failed")
                self._emit("repo.sync_failed", {"name": name, "exception": str(e)})
            finally:
                self.repo_status[name] = status
                self._persist_status()
                # cleanup tmpdir if exists
                try:
                    if tmpdir.exists():
                        shutil.rmtree(tmpdir)
                except Exception:
                    pass
            return status

    # -------------------------
    # Sync all repos (parallel)
    # -------------------------
    def sync_all(self, *, parallel: bool = True, force: bool = False, dry_run: bool = False) -> Dict[str, RepoStatus]:
        names = [n for n, rc in self.repo_configs.items() if rc.auto_sync or force]
        results: Dict[str, RepoStatus] = {}
        if not names:
            # if none auto_sync, sync all when force True
            if force:
                names = list(self.repo_configs.keys())
            else:
                names = [n for n in self.repo_configs.keys()]
        if parallel:
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {ex.submit(self.sync_repo, name, force=force, dry_run=dry_run): name for name in names}
                for fut in as_completed(futures):
                    name = futures[fut]
                    try:
                        status = fut.result()
                    except Exception:
                        logger.exception("Sync thread failed for %s", name)
                        status = RepoStatus(name=name, status="failed", detail="thread_exception")
                    results[name] = status
        else:
            for name in names:
                try:
                    status = self.sync_repo(name, force=force, dry_run=dry_run)
                except Exception:
                    logger.exception("Sync failed for %s", name)
                    status = RepoStatus(name=name, status="failed", detail="exception")
                results[name] = status
        return results

    # -------------------------
    # History and status persistence
    # -------------------------
    def _record_history(self, name: str, entry: Dict[str, Any]) -> None:
        try:
            _ensure_dir(self.history_dir)
            hist_file = self.history_dir / f"{name}.history.jsonl"
            entry_with_ts = {"time": _now_iso(), **entry}
            with open(hist_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry_with_ts, ensure_ascii=False) + "\n")
        except Exception:
            logger.exception("Failed to record history for %s", name)

    def history(self, name: str, limit: int = 50) -> List[Dict[str, Any]]:
        hist_file = self.history_dir / f"{name}.history.jsonl"
        if not hist_file.exists():
            return []
        out = []
        with open(hist_file, "r", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                try:
                    out.append(json.loads(ln))
                except Exception:
                    continue
        return out[-limit:]

    def _persist_status(self):
        try:
            with self._status_lock:
                obj = {name: st.to_dict() for name, st in self.repo_status.items()}
                _atomic_write_json(self._status_file, obj)
        except Exception:
            logger.exception("Failed to persist repo manager status")

    def load_status(self):
        try:
            obj = _read_json(self._status_file)
            if not obj:
                return
            for name, st in obj.items():
                self.repo_status[name] = RepoStatus(**st)  # type: ignore
        except Exception:
            logger.exception("Failed to load status")

    # -------------------------
    # Mirror testing utility
    # -------------------------
    def test_mirrors(self, name: str) -> List[Tuple[str, Optional[float], str]]:
        if name not in self.repo_configs:
            raise KeyError("Unknown repo: " + name)
        cfg = self.repo_configs[name]
        res = []
        for url in cfg.urls:
            t0 = time.time()
            success = False
            reason = ""
            try:
                # lightweight check similar to choose_mirror
                if url.startswith("http://") or url.startswith("https://"):
                    try:
                        _run_cmd(["curl", "-s", "-I", "--max-time", "5", url], capture=True, check=False)
                        success = True
                    except Exception:
                        success = False
                elif url.startswith("rsync://"):
                    try:
                        _run_cmd(["rsync", "--list-only", "--timeout=5", url], capture=True, check=False)
                        success = True
                    except Exception:
                        success = False
                elif url.endswith(".git") or url.startswith("git@") or url.startswith("ssh://"):
                    try:
                        _run_cmd(["git", "ls-remote", "--heads", url], capture=True, check=False)
                        success = True
                    except Exception:
                        success = False
                else:
                    p = Path(url)
                    success = p.exists()
                elapsed = time.time() - t0
                if success:
                    res.append((url, elapsed, "ok"))
                else:
                    res.append((url, None, "unreachable"))
            except Exception as e:
                res.append((url, None, f"error:{e}"))
        return res

    # -------------------------
    # Daemon mode
    # -------------------------
    def start_daemon(self, interval_seconds: int = 3600):
        if self._daemon_thread and self._daemon_thread.is_alive():
            logger.info("Daemon already running")
            return
        self._daemon_stop.clear()
        def _run():
            logger.info("Repo sync daemon started (interval=%ds)", interval_seconds)
            while not self._daemon_stop.is_set():
                try:
                    self.sync_all(parallel=True)
                except Exception:
                    logger.exception("Daemon sync loop error")
                # wait with early exit
                for _ in range(int(interval_seconds)):
                    if self._daemon_stop.is_set():
                        break
                    time.sleep(1)
            logger.info("Repo sync daemon stopped")
        self._daemon_thread = threading.Thread(target=_run, daemon=True, name="pkgtool-repo-daemon")
        self._daemon_thread.start()

    def stop_daemon(self):
        if not self._daemon_thread:
            return
        self._daemon_stop.set()
        self._daemon_thread.join(timeout=10)
        self._daemon_thread = None

# ---------------------------
# Singleton manager
# ---------------------------
_repo_mgr = RepoManager()
_repo_mgr.load_status()

# ---------------------------
# Public API
# ---------------------------
def list_repos() -> List[Dict[str, Any]]:
    return [rc.to_dict() for rc in _repo_mgr.list_repos()]

def get_status(name: str) -> Dict[str, Any]:
    st = _repo_mgr.repo_status.get(name)
    return st.to_dict() if st else {}

def sync_repo(name: str, **kwargs) -> Dict[str, Any]:
    st = _repo_mgr.sync_repo(name, **kwargs)
    return st.to_dict()

def sync_all(parallel: bool = True, **kwargs) -> Dict[str, Dict[str, Any]]:
    res = _repo_mgr.sync_all(parallel=parallel, **kwargs)
    return {k: v.to_dict() for k, v in res.items()}

def add_repo(cfg: Dict[str, Any], persist: bool = False) -> Dict[str, Any]:
    rc = _repo_mgr.add_repo(cfg, persist=persist)
    return rc.to_dict()

def remove_repo(name: str, remove_files: bool = False) -> None:
    _repo_mgr.remove_repo(name, remove_files=remove_files)

def rollback(name: str, snapshot_name: str) -> bool:
    cfg = _repo_mgr.get_repo(name)
    snap = _repo_mgr.snapshots_dir / snapshot_name
    if not snap.exists():
        raise FileNotFoundError("Snapshot not found: " + str(snap))
    return _repo_mgr._rollback_repo(cfg, snap)

def test_mirrors(name: str):
    return _repo_mgr.test_mirrors(name)

def start_daemon(interval_seconds: int = 3600):
    _repo_mgr.start_daemon(interval_seconds)

def stop_daemon():
    _repo_mgr.stop_daemon()

# ---------------------------
# CLI
# ---------------------------
def _build_cli():
    p = argparse.ArgumentParser(prog="pkgtool-repo", description="Repository synchronization tool for pkgtool")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List configured repositories")

    p_status = sub.add_parser("status", help="Show repo status")
    p_status.add_argument("repo", nargs="?")

    p_sync = sub.add_parser("sync", help="Sync repos")
    p_sync.add_argument("repo", nargs="?", help="Repo name (omit for all)")
    p_sync.add_argument("--parallel", action="store_true")
    p_sync.add_argument("--force", action="store_true", help="Sync regardless of auto_sync flag")

    p_add = sub.add_parser("add", help="Add a repo (json config)")
    p_add.add_argument("json", help="Repo config as JSON")

    p_remove = sub.add_parser("remove", help="Remove a repo")
    p_remove.add_argument("repo")
    p_remove.add_argument("--files", action="store_true")

    p_history = sub.add_parser("history", help="Show repo history")
    p_history.add_argument("repo")

    p_rollback = sub.add_parser("rollback", help="Rollback repo to snapshot")
    p_rollback.add_argument("repo")
    p_rollback.add_argument("snapshot")

    p_test = sub.add_parser("test-mirrors", help="Test mirrors speed/availability")
    p_test.add_argument("repo")

    p_daemon = sub.add_parser("daemon", help="Daemon control")
    p_daemon.add_argument("action", choices=["start", "stop", "status"])
    p_daemon.add_argument("--interval", type=int, default=3600)

    return p

def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "list":
            for rc in _repo_mgr.list_repos():
                print(json.dumps(rc.to_dict(), indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "status":
            if args.repo:
                st = get_status(args.repo)
                print(json.dumps(st, indent=2, ensure_ascii=False))
            else:
                s = {n: st.to_dict() for n, st in _repo_mgr.repo_status.items()}
                print(json.dumps(s, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "sync":
            if args.repo:
                st = sync_repo(args.repo, force=bool(args.force))
                print(json.dumps(st, indent=2, ensure_ascii=False))
            else:
                res = sync_all(parallel=bool(args.parallel), force=bool(args.force))
                print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "add":
            cfg = json.loads(args.json)
            rc = add_repo(cfg, persist=True)
            print("Added repo:", json.dumps(rc, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "remove":
            remove_repo(args.repo, remove_files=bool(args.files))
            print("Removed repo", args.repo)
            return 0

        if args.cmd == "history":
            hist = _repo_mgr.history(args.repo)
            print(json.dumps(hist, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "rollback":
            ok = rollback(args.repo, args.snapshot)
            print("Rollback ok" if ok else "Rollback failed")
            return 0

        if args.cmd == "test-mirrors":
            res = test_mirrors(args.repo)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "daemon":
            act = args.action
            if act == "start":
                start_daemon(interval_seconds=int(args.interval))
                print("Daemon started")
            elif act == "stop":
                stop_daemon()
                print("Daemon stopped")
            else:
                running = _repo_mgr._daemon_thread is not None and _repo_mgr._daemon_thread.is_alive()
                print("Daemon running" if running else "Daemon stopped")
            return 0

    except Exception as e:
        logger.exception("CLI command failed")
        print("Error:", str(e), file=sys.stderr)
        return 2

    return 0

# ---------------------------
# Auto-load hooks: register integration hooks
# ---------------------------
def _autoregister_hooks():
    # Example: after repo synced, ask db to refresh metadata if available
    def on_synced(payload):
        try:
            name = payload.get("name")
            if _dbmod and hasattr(_dbmod, "update_repo_metadata"):
                try:
                    _dbmod.update_repo_metadata(name)
                except Exception:
                    logger.debug("db.update_repo_metadata failed")
        except Exception:
            logger.exception("on_synced failed")

    _repo_mgr.on("repo.synced", on_synced)

try:
    _autoregister_hooks()
except Exception:
    pass

# ---------------------------
# If executed as script
# ---------------------------
if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
