# Pkgtool/pkgtool1.0/modules/patches.py
# -*- coding: utf-8 -*-
"""
patches.py - advanced patch manager for pkgtool

Features:
- apply/reverse/dry-run patches and patch series
- sandboxed application (apply to temp copy first)
- overlay patches (user overlays override official)
- integration with fetcher (to auto-download patches)
- integration with db.py/log.py/config.py when available
- history/audit JSONL per package
- ML-assisted conflict suggestions (optional, uses scikit-learn if available)
- integration with upstream (git format-patch, fetch PR patches)
- CLI: pkgtool-patch
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Optional integrations (best-effort)
try:
    from modules import log as _logmod  # type: ignore
    logger = _logmod.get_logger("pkgtool.patches")
except Exception:
    import logging as _logging
    logger = _logging.getLogger("pkgtool.patches")
    if not logger.handlers:
        logger.addHandler(_logging.StreamHandler())
    logger.setLevel(_logging.INFO)

try:
    from modules import fetcher as _fetcher  # type: ignore
except Exception:
    _fetcher = None

try:
    from modules import db as _dbmod  # type: ignore
except Exception:
    _dbmod = None

try:
    from modules.config import cfg as _cfg  # type: ignore
except Exception:
    _cfg = None

# ML optional
try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.linear_model import LogisticRegression  # type: ignore
    _ML_AVAILABLE = True
except Exception:
    _ML_AVAILABLE = False

# Config defaults (override with modules.config if present)
BASE_DIR = Path.cwd() / "Pkgtool" / "pkgtool1.0"
HISTORY_DIR = BASE_DIR / "patches_history"
DECISIONS_FILE = BASE_DIR / "patch_decisions.jsonl"  # past human decisions for ML training
DEFAULT_SANDBOX_DIR = BASE_DIR / "patches_sandbox"
PATCHES_CONFIG = {
    "sandbox_dir": str(DEFAULT_SANDBOX_DIR),
    "abort_on_fail": True,
    "use_git_apply_if_repo": True,
    "ml_enabled": True,
    "overlay_priority": "overlay_first",  # overlay_first or official_first
}

# Load config overrides if available
if _cfg:
    try:
        pc = _cfg.get("patches") or {}
        PATCHES_CONFIG.update(pc)
    except Exception:
        logger.debug("Failed to read patches config from config module")

# Ensure directories
HISTORY_DIR.mkdir(parents=True, exist_ok=True)
Path(PATCHES_CONFIG["sandbox_dir"]).mkdir(parents=True, exist_ok=True)


# ---------------------------
# Utilities
# ---------------------------
def _now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _atomic_write(path: Path, data: str) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp.{int(time.time()*1000)}")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _run_cmd(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> Tuple[int, str, str]:
    logger.debug("CMD: %s (cwd=%s)", " ".join(cmd), cwd)
    p = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    sout = out.decode("utf-8", errors="replace")
    serr = err.decode("utf-8", errors="replace")
    if check and p.returncode != 0:
        logger.debug("cmd failed stdout=%s stderr=%s", sout, serr)
        raise subprocess.CalledProcessError(p.returncode, cmd, output=sout, stderr=serr)
    return p.returncode, sout, serr


def _safe_relative_targets_in_patch(patch_text: str) -> List[str]:
    """
    Parse naïvely the 'diff --git a/xxx b/yyy' lines to extract target paths.
    Used to check patch tries to write outside target_dir.
    """
    targets = []
    for ln in patch_text.splitlines():
        if ln.startswith("diff --git"):
            parts = ln.split()
            if len(parts) >= 3:
                a = parts[2]
                b = parts[3] if len(parts) > 3 else None
                # cleanup a/ b/
                if a.startswith("a/"):
                    targets.append(a[2:])
                elif a.startswith("b/"):
                    targets.append(a[2:])
                elif b and b.startswith("b/"):
                    targets.append(b[2:])
    return targets


# ---------------------------
# History / audit
# ---------------------------
def _history_file_for_pkg(pkg_name: str) -> Path:
    p = HISTORY_DIR / f"{pkg_name}.history.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def record_history(pkg_name: str, rec: Dict[str, Any]) -> None:
    p = _history_file_for_pkg(pkg_name)
    entry = {"ts": _now_iso(), **rec}
    try:
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        logger.exception("Failed to record patch history for %s", pkg_name)
    # db integration
    try:
        if _dbmod and hasattr(_dbmod, "record_patch_history"):
            _dbmod.record_patch_history(pkg_name, entry)  # optional API
    except Exception:
        logger.debug("db.record_patch_history not available/failed")


def read_history(pkg_name: str, limit: int = 100) -> List[Dict[str, Any]]:
    p = _history_file_for_pkg(pkg_name)
    if not p.exists():
        return []
    out = []
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
    return out[-limit:]


# ---------------------------
# ML-assisted helpers
# ---------------------------
class _MLAdvisor:
    """
    Lightweight ML advisor: trains a simple classifier from historical decisions file.
    Each decision record expected to include:
      { "patch_hash": "...", "hunk_text": "...", "decision": "accept|reject|manual" }
    Features: TF-IDF on hunk_text, LogisticRegression classifier.
    If sklearn not available or no data, falls back to heuristics.
    """

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.available = False
        # if sklearn available and data present, train
        if _ML_AVAILABLE and DECISIONS_FILE.exists():
            try:
                X_text = []
                y = []
                with DECISIONS_FILE.open("r", encoding="utf-8", errors="replace") as fh:
                    for ln in fh:
                        try:
                            d = json.loads(ln)
                            if "hunk_text" in d and "decision" in d:
                                X_text.append(d["hunk_text"])
                                y.append(d["decision"])
                        except Exception:
                            continue
                if X_text and y:
                    self.vectorizer = TfidfVectorizer(max_features=2000)
                    X = self.vectorizer.fit_transform(X_text)
                    self.model = LogisticRegression(max_iter=1000)
                    self.model.fit(X, y)
                    self.available = True
                    logger.info("patches.MLAdvisor: trained model on %d samples", len(y))
            except Exception:
                logger.exception("Failed to build ML model; falling back to heuristics")
                self.available = False

    def suggest(self, hunk_text: str) -> Tuple[str, float]:
        """
        Return (decision, confidence). decision in 'accept'|'reject'|'manual'.
        If model not available, use heuristics:
          - short hunks (<30 chars diff) -> accept with moderate confidence
          - hunks with >> many context changes -> manual
        """
        if self.available and self.model and self.vectorizer:
            try:
                X = self.vectorizer.transform([hunk_text])
                probs = self.model.predict_proba(X)[0]
                labels = self.model.classes_
                # choose top
                idx = int(probs.argmax())
                return labels[idx], float(probs[idx])
            except Exception:
                logger.exception("ML prediction error")
        # heuristic fallback
        lines = hunk_text.count("\n")
        ratio = 0.5
        if lines < 10:
            decision = "accept"
            ratio = 0.7
        elif lines < 40:
            decision = "manual"
            ratio = 0.5
        else:
            decision = "manual"
            ratio = 0.3
        return decision, ratio


_ML_ADVISOR = _MLAdvisor() if PATCHES_CONFIG.get("ml_enabled", True) else None


# ---------------------------
# Patch application primitives
# ---------------------------
def _apply_patch_with_patch_tool(patch_file: Path, target_dir: Path, level: int = 1, reverse: bool = False) -> Tuple[bool, str]:
    """
    Use system 'patch' tool. Return (success, output).
    """
    cmd = ["patch", f"-p{level}"]
    if reverse:
        cmd.append("-R")
    cmd += ["--forward", "-i", str(patch_file)]
    try:
        ret, out, err = _run_cmd(cmd, cwd=target_dir, check=False)
        ok = ret == 0
        return ok, out + ("\n" + err if err else "")
    except Exception as e:
        logger.exception("patch tool failed")
        return False, str(e)


def _apply_patch_with_git_apply(patch_file: Path, target_dir: Path, reverse: bool = False) -> Tuple[bool, str]:
    """
    Use 'git apply' if repo. Supports 3-way merge with --3way to attempt resolving offsets.
    """
    cmd = ["git", "apply", "--index", "--whitespace=nowarn"]
    if reverse:
        cmd.append("--reverse")
    # try 3-way
    cmd.append("--3way")
    cmd.append(str(patch_file))
    try:
        ret, out, err = _run_cmd(cmd, cwd=target_dir, check=False)
        ok = ret == 0
        return ok, out + ("\n" + err if err else "")
    except Exception as e:
        logger.exception("git apply failed")
        return False, str(e)


def _apply_patch_python(patch_file: Path, target_dir: Path, level: int = 1, reverse: bool = False) -> Tuple[bool, str]:
    """
    Fallback: apply simple unified diff hunks via difflib. This is limited and best-effort.
    """
    try:
        text = patch_file.read_text(encoding="utf-8", errors="replace")
        # parse hunks naive way: look for '--- a/..' '+++ b/..' then '@@'
        # We'll implement a very small subset: reject complex patches
        if "Binary files" in text:
            return False, "binary patch - cannot apply via python fallback"
        # find file targets
        targets = _safe_relative_targets_in_patch(text)
        if not targets:
            return False, "no file targets found - python fallback cannot apply"
        # naive application: for each file, reconstruct patched content using difflib
        applied_files = []
        for tgt in set(targets):
            tgt_path = target_dir / tgt
            if not tgt_path.exists():
                # create empty
                tgt_path.parent.mkdir(parents=True, exist_ok=True)
                old = ""
            else:
                old = tgt_path.read_text(encoding="utf-8", errors="replace")
            # find diff block intended for this file
            # very naive: build patched by applying unified diff using difflib
            ud = difflib.unified_diff(old.splitlines(keepends=True), old.splitlines(keepends=True))
            # cannot reconstruct from diff easily; bail out
            return False, "python fallback: complex patch - abort"
        return False, "python fallback not implemented for complex patches"
    except Exception as e:
        logger.exception("python patch apply failed")
        return False, str(e)


def _verify_patch_safety(patch_path: Path, target_dir: Path) -> Tuple[bool, str]:
    """
    Ensure patch doesn't attempt to modify files outside target_dir.
    """
    try:
        text = patch_path.read_text(encoding="utf-8", errors="replace")
        targets = _safe_relative_targets_in_patch(text)
        for t in targets:
            # prevent absolute paths or '../'
            if t.startswith("/") or ".." in t.split("/"):
                return False, f"patch targets unsafe path: {t}"
        return True, "ok"
    except Exception:
        return False, "failed to parse patch for safety"


# ---------------------------
# Higher-level patch operations
# ---------------------------
def apply_patch(patch_path: Union[str, Path], target_dir: Union[str, Path], *,
                level: int = 1, mode: str = "auto", sandbox: bool = True, dry_run: bool = False,
                pkg_name: Optional[str] = None, checksum: Optional[str] = None, gpg_sig: Optional[Path] = None,
                force: bool = False) -> Dict[str, Any]:
    """
    Apply a single patch to target_dir.
    mode: "auto" (choose best tool), "patch", "git", "python"
    sandbox: if True apply to a temporary copy first
    dry_run: if True do not persist changes, return what would happen
    pkg_name: used to record history
    checksum/gpg_sig: verify patch file before applying (if provided)
    force: bypass masks / errors (use carefully)
    Returns a result dict with keys: success(bool), applied(bool), output(str), sandbox_path(optional)
    """
    ppath = Path(patch_path)
    tdir = Path(target_dir)
    res = {"success": False, "applied": False, "output": "", "sandbox": None, "patch": str(ppath)}
    logger.info("Applying patch %s to %s (mode=%s sandbox=%s dry_run=%s)", ppath, tdir, mode, sandbox, dry_run)
    # ensure patch exists; if not try fetcher
    if not ppath.exists():
        if _fetcher:
            try:
                fetched = _fetcher.fetch(str(ppath), checksum=checksum)  # ppath might be URL
                ppath = Path(fetched)
                logger.info("Fetched patch to %s", ppath)
            except Exception:
                logger.exception("Failed to fetch patch from %s", ppath)
                res["output"] = "patch not found and fetch failed"
                return res
        else:
            res["output"] = "patch file not found and fetcher not available"
            return res
    # verify checksum/gpg
    if checksum:
        try:
            algo, expected = checksum.split(":", 1)
            got = _sha256_of_file(ppath) if algo == "sha256" else None
            if got is None or got != expected:
                res["output"] = f"checksum mismatch: expected {expected} got {got}"
                return res
        except Exception:
            res["output"] = "checksum verification failed"
            return res
    if gpg_sig:
        # rely on fetcher or external GPG verify if available - for now we log
        logger.info("GPG signature validation requested for %s (path %s) - ensure externally validated", ppath, gpg_sig)
    # safety check
    ok, reason = _verify_patch_safety(ppath, tdir)
    if not ok:
        res["output"] = f"patch safety check failed: {reason}"
        return res
    # prepare sandbox
    apply_dir = tdir
    sandbox_path = None
    if sandbox:
        sandbox_path = Path(tempfile.mkdtemp(prefix="patch-sandbox-"))
        logger.debug("Creating sandbox copy %s -> %s", tdir, sandbox_path)
        shutil.copytree(tdir, sandbox_path, dirs_exist_ok=True)
        apply_dir = sandbox_path
        res["sandbox"] = str(sandbox_path)
    # choose mode
    chosen_mode = mode
    if mode == "auto":
        if _is_git_repo(tdir) and PATCHES_CONFIG.get("use_git_apply_if_repo", True):
            chosen_mode = "git"
        else:
            # prefer system patch tool if present
            if shutil.which("patch"):
                chosen_mode = "patch"
            else:
                chosen_mode = "python"
    logger.debug("Chosen patch mode: %s", chosen_mode)
    # try to apply
    try:
        applied = False
        output = ""
        if chosen_mode == "git":
            applied, output = _apply_patch_with_git_apply(ppath, apply_dir, reverse=False)
            if not applied:
                # fallback to patch tool
                if shutil.which("patch"):
                    applied, output = _apply_patch_with_patch_tool(ppath, apply_dir, level=level, reverse=False)
        elif chosen_mode == "patch":
            applied, output = _apply_patch_with_patch_tool(ppath, apply_dir, level=level, reverse=False)
            if not applied and _is_git_repo(tdir) and shutil.which("git"):
                # try git apply with 3way
                applied, out2 = _apply_patch_with_git_apply(ppath, apply_dir)
                output += "\n" + out2
        else:
            applied, output = _apply_patch_python(ppath, apply_dir, level=level)
        res["output"] = output
        if not applied:
            # capture .rej files if any
            rej_files = list(Path(apply_dir).rglob("*.rej"))
            if rej_files:
                res["output"] += f"\nRejected hunks: {len(rej_files)}"
            # if abort_on_fail and not force -> failure
            if PATCHES_CONFIG.get("abort_on_fail", True) and not force:
                res["success"] = False
                res["applied"] = False
                # cleanup sandbox if requested
                if sandbox and sandbox_path:
                    shutil.rmtree(sandbox_path, ignore_errors=True)
                record_history(pkg_name or "unknown", {"action": "apply_failed", "patch": str(ppath), "output": output})
                return res
        # if dry_run, do not move sandbox into place; report success
        res["success"] = True
        res["applied"] = True
        if dry_run:
            res["output"] += "\nDRY-RUN: changes not persisted"
            # keep sandbox for inspection
            return res
        # persist: move sandbox back to target (atomically if possible)
        if sandbox and sandbox_path:
            # backup original
            backup = tdir.with_suffix(".orig-backup-" + str(int(time.time())))
            try:
                if tdir.exists():
                    tdir.replace(backup)
                shutil.move(str(sandbox_path), str(tdir))
                # remove backup
                if backup.exists():
                    shutil.rmtree(backup, ignore_errors=True)
            except Exception:
                # try fallback: restore backup and fail
                if backup.exists():
                    backup.replace(tdir)
                raise
        # record applied patch in history and db
        record_history(pkg_name or "unknown", {"action": "apply", "patch": str(ppath), "mode": chosen_mode})
        try:
            if _dbmod and hasattr(_dbmod, "record_applied_patch"):
                _dbmod.record_applied_patch(pkg_name or "unknown", str(ppath))
        except Exception:
            logger.debug("db.record_applied_patch not available")
        return res
    except Exception as e:
        logger.exception("Exception while applying patch")
        res["success"] = False
        res["applied"] = False
        res["output"] += f"\nException: {e}"
        # cleanup sandbox
        if sandbox_path:
            shutil.rmtree(sandbox_path, ignore_errors=True)
        record_history(pkg_name or "unknown", {"action": "apply_exception", "patch": str(ppath), "error": str(e)})
        return res


def reverse_patch(patch_path: Union[str, Path], target_dir: Union[str, Path], *,
                  level: int = 1, sandbox: bool = True, dry_run: bool = False, pkg_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Reverse (unapply) a patch. Works similarly to apply but with reverse flag.
    """
    ppath = Path(patch_path)
    tdir = Path(target_dir)
    res = {"success": False, "reversed": False, "output": "", "sandbox": None}
    # sandbox copy
    sandbox_path = None
    apply_dir = tdir
    if sandbox:
        sandbox_path = Path(tempfile.mkdtemp(prefix="patch-sandbox-"))
        shutil.copytree(tdir, sandbox_path, dirs_exist_ok=True)
        apply_dir = sandbox_path
        res["sandbox"] = str(sandbox_path)
    # try git reverse first then patch -R
    try:
        ok = False
        out = ""
        if _is_git_repo(tdir) and shutil.which("git"):
            ok, out = _apply_patch_with_git_apply(ppath, apply_dir, reverse=True)
        if not ok and shutil.which("patch"):
            ok, out = _apply_patch_with_patch_tool(ppath, apply_dir, level=level, reverse=True)
        res["output"] = out
        if not ok:
            res["success"] = False
            res["reversed"] = False
            if sandbox and sandbox_path:
                shutil.rmtree(sandbox_path, ignore_errors=True)
            record_history(pkg_name or "unknown", {"action": "reverse_failed", "patch": str(ppath)})
            return res
        # persist if not dry_run
        if dry_run:
            res["success"] = True
            res["reversed"] = True
            res["output"] += "\nDRY-RUN: changes not persisted"
            return res
        if sandbox and sandbox_path:
            # replace target_dir atomically
            backup = tdir.with_suffix(".orig-backup-" + str(int(time.time())))
            try:
                if tdir.exists():
                    tdir.replace(backup)
                shutil.move(str(sandbox_path), str(tdir))
                if backup.exists():
                    shutil.rmtree(backup, ignore_errors=True)
            except Exception:
                if backup.exists():
                    backup.replace(tdir)
                raise
        record_history(pkg_name or "unknown", {"action": "reverse", "patch": str(ppath)})
        res["success"] = True
        res["reversed"] = True
        return res
    except Exception as e:
        logger.exception("reverse patch exception")
        res["output"] += f"\nException: {e}"
        if sandbox and sandbox_path:
            shutil.rmtree(sandbox_path, ignore_errors=True)
        record_history(pkg_name or "unknown", {"action": "reverse_exception", "patch": str(ppath), "error": str(e)})
        return res


def dry_run_patch(patch_path: Union[str, Path], target_dir: Union[str, Path], *, level: int = 1, pkg_name: Optional[str] = None) -> Dict[str, Any]:
    return apply_patch(patch_path, target_dir, level=level, sandbox=True, dry_run=True, pkg_name=pkg_name)


# ---------------------------
# Series / quilt-like handling
# ---------------------------
def _read_series(series_file: Path) -> List[str]:
    """
    Read a simple 'series' file (one filename per line, ignore comments).
    """
    if not series_file.exists():
        return []
    lines = series_file.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln)
    return out


def list_available_patches(package_name: str, series_file: Optional[Union[str, Path]] = None,
                           official_dir: Optional[Path] = None, overlay_dirs: Optional[List[Path]] = None) -> List[Dict[str, Any]]:
    """
    Return list of patches described by the series file, annotated with origin (official/overlay).
    """
    # determine series file
    if series_file:
        sf = Path(series_file)
    else:
        sf = (official_dir or Path.cwd()) / "debian" / "patches" / "series"
    series = _read_series(sf)
    out = []
    # overlay precedence
    overlay_dirs = overlay_dirs or []
    for name in series:
        origin = "official"
        patch_path = (sf.parent / name).resolve()
        # check overlays
        for ov in overlay_dirs:
            op = Path(ov) / name
            if op.exists():
                patch_path = op.resolve()
                origin = f"overlay:{ov}"
                if PATCHES_CONFIG.get("overlay_priority", "overlay_first") == "overlay_first":
                    # stop at first overlay found
                    break
        out.append({"name": name, "path": str(patch_path), "origin": origin})
    # also include overlays that are not in series (user added)
    for ov in overlay_dirs:
        for p in Path(ov).glob("*.patch"):
            if p.name not in series:
                out.append({"name": p.name, "path": str(p.resolve()), "origin": f"overlay:{ov}"})
    return out


def apply_series(package_name: str, source_dir: Union[str, Path], series_file: Optional[Union[str, Path]] = None,
                 overlay_dirs: Optional[List[Union[str, Path]]] = None, sandbox: bool = True, dry_run: bool = False,
                 pkg_name: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    """
    Apply a series of patches in order. Overlay patches override official ones per priority rule.
    Returns dict with per-patch results.
    """
    src = Path(source_dir)
    overlay_dirs = [Path(x) for x in (overlay_dirs or [])]
    # series file resolution
    if series_file:
        sf = Path(series_file)
    else:
        sf = src / "debian" / "patches" / "series"
    series = _read_series(sf)
    results = []
    for name in series:
        # compute patch path with overlay precedence
        patch_path = (sf.parent / name)
        origin = "official"
        if PATCHES_CONFIG.get("overlay_priority", "overlay_first") == "overlay_first":
            # check overlays first
            found_overlay = None
            for ov in overlay_dirs:
                op = ov / name
                if op.exists():
                    patch_path = op
                    origin = f"overlay:{ov}"
                    found_overlay = op
                    break
            if not found_overlay:
                patch_path = (sf.parent / name)
                origin = "official"
        else:
            # official first, overlay overrides only if configured otherwise
            patch_path = (sf.parent / name)
            origin = "official"
            for ov in overlay_dirs:
                op = ov / name
                if op.exists():
                    patch_path = op
                    origin = f"overlay:{ov}"
                    break
        # apply patch
        r = apply_patch(patch_path, src, sandbox=sandbox, dry_run=dry_run, pkg_name=package_name, force=force)
        r["name"] = name
        r["origin"] = origin
        results.append(r)
        if not r.get("success") and PATCHES_CONFIG.get("abort_on_fail", True) and not force:
            # stop series application
            break
    # write series application summary to history
    record_history(package_name or pkg_name or "unknown", {"action": "apply_series", "series": str(sf), "results": [{"name": rr.get("name"), "applied": rr.get("applied"), "success": rr.get("success")} for rr in results]})
    return {"package": package_name, "series": str(sf), "results": results}


# ---------------------------
# Upstream integration
# ---------------------------
def fetch_upstream_patches_from_git(git_url: str, dest_dir: Union[str, Path], since: Optional[str] = None, max_patches: int = 10) -> List[Path]:
    """
    Clone or fetch git_url into a temp repo and export recent commits as patches (format-patch).
    since: commit-ish to start from (e.g. 'origin/main~5'), else use last N commits.
    Returns list of patch file paths.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="patches-upstream-"))
    try:
        # shallow clone
        if shutil.which("git") is None:
            raise RuntimeError("git required for upstream fetch")
        _run_cmd(["git", "clone", "--depth", str(max_patches), git_url, str(tmp)], check=True)
        os.chdir(str(tmp))
        if since:
            rng = f"{since}..HEAD"
            _run_cmd(["git", "format-patch", "--output-directory", str(dest_dir), rng], check=True)
        else:
            _run_cmd(["git", "format-patch", f"-{max_patches}", "--output-directory", str(dest_dir)], check=True)
        patches = list(dest_dir.glob("*.patch"))
        return patches
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass


def fetch_pr_patch(git_host_pr_url: str, dest_path: Union[str, Path]) -> Path:
    """
    For hosting providers that provide a downloadable patch/patch URL (GitHub/GitLab): fetch the patch.
    Example GitHub PR patch URL: https://github.com/user/repo/pull/123.patch
    """
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # try wget/curl or requests
    try:
        if shutil.which("curl"):
            _run_cmd(["curl", "-L", "-s", "-o", str(dest), git_host_pr_url], check=True)
        elif shutil.which("wget"):
            _run_cmd(["wget", "-q", "-O", str(dest), git_host_pr_url], check=True)
        else:
            import urllib.request
            with urllib.request.urlopen(git_host_pr_url, timeout=60) as resp:
                dest.write_bytes(resp.read())
        return dest
    except Exception as e:
        logger.exception("Failed to fetch PR patch")
        raise


# ---------------------------
# Suggestions / ML-assisted conflict resolution
# ---------------------------
def suggest_resolution_for_hunk(hunk_text: str) -> Dict[str, Any]:
    """
    Suggest what to do with a conflicting hunk. Returns dict {decision, confidence, explanation}
    """
    if _ML_ADVISOR and getattr(_ML_ADVISOR, "available", False):
        dec, conf = _ML_ADVISOR.suggest(hunk_text)
        return {"decision": dec, "confidence": conf, "source": "ml"}
    # fallback heuristics
    # use difflib ratio vs empty? use presence of many context lines as manual
    lines = hunk_text.splitlines()
    n = len(lines)
    ratio = 0.5
    if n < 8:
        return {"decision": "accept", "confidence": 0.75, "source": "heuristic", "note": "small hunk"}
    if any(l.startswith("+++ ") or l.startswith("--- ") for l in lines):
        return {"decision": "manual", "confidence": 0.45, "source": "heuristic", "note": "file target changes present"}
    return {"decision": "manual", "confidence": 0.4, "source": "heuristic", "note": "large or complex hunk"}


# ---------------------------
# Overlay application helper
# ---------------------------
def apply_overlay_first(official_series_dir: Path, overlay_dirs: List[Path]) -> List[Dict[str, Any]]:
    """
    Build ordered list of patches by overlay priority and return entries with paths and origins.
    This is a helper used by apply_series when overlay_priority == overlay_first.
    """
    series_file = official_series_dir / "series"
    series = _read_series(series_file)
    ordered = []
    for name in series:
        chosen = None
        origin = "official"
        for ov in overlay_dirs:
            op = ov / name
            if op.exists():
                chosen = op
                origin = f"overlay:{ov}"
                break
        if not chosen:
            chosen = official_series_dir / name
            origin = "official"
        ordered.append({"name": name, "path": str(chosen), "origin": origin})
    # include overlays not in series at end
    for ov in overlay_dirs:
        for p in ov.glob("*.patch"):
            if p.name not in series:
                ordered.append({"name": p.name, "path": str(p), "origin": f"overlay:{ov}"})
    return ordered


# ---------------------------
# Status / bookkeeping
# ---------------------------
def status(pkg_name: str) -> Dict[str, Any]:
    """
    Return status: which patches applied (from history), which pending (from series).
    """
    hist = read_history(pkg_name, limit=1000)
    applied = [h for h in hist if h.get("action") == "apply"]
    return {"package": pkg_name, "applied_count": len(applied), "history_sample": applied[-10:]}


# ---------------------------
# CLI
# ---------------------------
def _build_cli():
    p = argparse.ArgumentParser(prog="pkgtool-patch", description="Patch manager for pkgtool")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_apply = sub.add_parser("apply", help="Apply a patch or series")
    p_apply.add_argument("pkg", help="package name or source dir")
    p_apply.add_argument("--patch", help="single patch path or URL")
    p_apply.add_argument("--series", help="series file path")
    p_apply.add_argument("--overlay", help="overlay directory (can be repeated)", action="append")
    p_apply.add_argument("--no-sandbox", help="do not use sandbox", dest="sandbox", action="store_false")
    p_apply.add_argument("--dry-run", action="store_true")
    p_apply.add_argument("--force", action="store_true")

    p_reverse = sub.add_parser("reverse", help="Reverse/unapply a patch")
    p_reverse.add_argument("target_dir")
    p_reverse.add_argument("patch")

    p_dry = sub.add_parser("dry-run", help="Dry-run apply")
    p_dry.add_argument("target_dir")
    p_dry.add_argument("patch")

    p_list = sub.add_parser("list", help="List patches in series")
    p_list.add_argument("source_dir")
    p_list.add_argument("--series")

    p_status = sub.add_parser("status", help="Status for package")
    p_status.add_argument("pkg")

    p_history = sub.add_parser("history", help="Patch history")
    p_history.add_argument("pkg")
    p_history.add_argument("--limit", type=int, default=50)

    p_fetch_up = sub.add_parser("fetch-upstream", help="Fetch patches from upstream git")
    p_fetch_up.add_argument("git_url")
    p_fetch_up.add_argument("--out", help="output dir", default=str(DEFAULT_SANDBOX_DIR))

    p_suggest = sub.add_parser("suggest", help="ML-assisted suggestion for given hunk file")
    p_suggest.add_argument("hunk_file")

    return p


def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "apply":
            src = args.pkg
            # if patch provided -> single patch apply to src dir
            if args.patch:
                res = apply_patch(args.patch, Path(src), sandbox=args.sandbox, dry_run=args.dry_run, pkg_name=os.path.basename(src), force=args.force)
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                # series apply
                res = apply_series(os.path.basename(src), Path(src), series_file=args.series, overlay_dirs=[Path(x) for x in (args.overlay or [])], sandbox=args.sandbox, dry_run=args.dry_run, force=args.force)
                print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "reverse":
            res = reverse_patch(args.patch, args.target_dir)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "dry-run":
            res = dry_run_patch(args.patch, args.target_dir)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "list":
            lst = list_available_patches(Path(args.source_dir).name, series_file=args.series, official_dir=Path(args.source_dir) / "debian" / "patches")
            print(json.dumps(lst, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "status":
            print(json.dumps(status(args.pkg), indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "history":
            h = read_history(args.pkg, limit=args.limit)
            print(json.dumps(h, indent=2, ensure_ascii=False))
            return 0

        if args.cmd == "fetch-upstream":
            patches = fetch_upstream_patches_from_git(args.git_url, Path(args.out), max_patches=20)
            print("Fetched patches:", [str(p) for p in patches])
            return 0

        if args.cmd == "suggest":
            text = Path(args.hunk_file).read_text(encoding="utf-8", errors="replace")
            sug = suggest_resolution_for_hunk(text)
            print(json.dumps(sug, indent=2, ensure_ascii=False))
            return 0

    except Exception as e:
        logger.exception("CLI error")
        print("Error:", str(e))
        return 2

    return 0


# Allow direct execution
if __name__ == "__main__":
    import sys
    sys.exit(cli_main(sys.argv[1:]))
