"""
pkgtool.runtime_manager

Módulo responsável por garantir que o runtime Python do pkgtool esteja sempre disponível,
protegê-lo de remoção acidental, checar integridade e tentar reparo automático usando
artefatos locais (tarballs de runtime) ou metas no ports_dir.

Este é um módulo autônomo que fornece:
 - RuntimeManager: classe principal com métodos check(), repair(), get_info(), protect(), unprotect()
 - CLI utilitário (quando executado como script): check | repair | info | protect | unprotect

Notas:
 - Este módulo faz suposições pragmáticas: procura config YAML em /etc/pkgtool/config.yml
   ou ~/.config/pkgtool/config.yml. A config deve conter chaves usadas abaixo (ver default_cfg).
 - Repair tenta extrair um tarball em locais conhecidos (config['runtime_cache'] or ports_dir/runtime)
   e criar o prefix esperado. Não implementa compilação completa — isso pertence ao builder/toolchain.
 - Proteção é registrada em SQLite (db_path). A tabela `protected_runtimes` guarda entries.

Use este módulo como ponto de partida. Integre chamadas de proteção no fluxo de remoção de pacotes
(no módulo installer/remove) chamando `RuntimeManager.assert_not_protected(package_name)`.

"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import yaml
except Exception:
    yaml = None

# Try to use rich for color logging if available
try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
except Exception:
    console = None


DEFAULT_CONFIG_PATHS = [
    Path("/etc/pkgtool/config.yml"),
    Path.home() / ".config" / "pkgtool" / "config.yml",
]

DEFAULT_CFG = {
    "pkgtool_runtime": {
        "python": {
            "version": "3.12.5",
            "path": "/opt/pkgtool/runtime/python/3.12.5/bin/python3",
        }
    },
    "ports_dir": "/usr/ports/pkgtool",
    "runtime_cache": "/var/cache/pkgtool/runtime",
    "db_path": "/var/lib/pkgtool/pkgtool.db",
}


@dataclass
class RuntimeInfo:
    family: str  # "python"
    version: str
    path: Path


class RuntimeManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = load_config()
        self.cfg = config
        self.db_path = Path(self.cfg.get("db_path", DEFAULT_CFG["db_path"]))
        self._ensure_db()

    def _ensure_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS protected_runtimes (
                id INTEGER PRIMARY KEY,
                family TEXT NOT NULL,
                version TEXT NOT NULL,
                path TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def get_runtime_info(self) -> RuntimeInfo:
        rt = self.cfg.get("pkgtool_runtime", {}).get("python")
        if not rt:
            raise RuntimeError("pkgtool_runtime.python is not defined in config")
        return RuntimeInfo(family="python", version=str(rt["version"]), path=Path(rt["path"]))

    def is_protected(self, family: str = "python") -> bool:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM protected_runtimes WHERE family = ?", (family,))
        c = cur.fetchone()[0]
        conn.close()
        return c > 0

    def protect(self, info: Optional[RuntimeInfo] = None) -> None:
        if info is None:
            info = self.get_runtime_info()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO protected_runtimes (family, version, path, created_at) VALUES (?,?,?,?)",
            (info.family, info.version, str(info.path), int(time.time())),
        )
        conn.commit()
        conn.close()
        _log(f"Protected runtime: {info.family} {info.version} @ {info.path}")

    def unprotect(self, family: str = "python") -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM protected_runtimes WHERE family = ?", (family,))
        conn.commit()
        conn.close()
        _log(f"Unprotected runtime: {family}")

    def assert_not_protected(self, package_name: str) -> None:
        """Raise RuntimeError if package_name matches the protected runtime package.

        This should be called by package removal logic before proceeding.
        """
        info = self.get_runtime_info()
        # Some ports may have different naming schemas; check simple membership
        protected_pkg_prefix = f"python-{info.version}"  # heuristic
        if package_name == protected_pkg_prefix or f"python-{info.version}" in package_name:
            raise RuntimeError(
                f"Refusing to remove package '{package_name}': it matches protected runtime {info.version}"
            )
        if self.is_protected(info.family):
            # also prevent removal if any protection exists for family and package equals 'python'
            if package_name == "python" or package_name.startswith("python"):
                raise RuntimeError(f"Refusing to remove Python packages while {info.family} is protected")

    def check(self) -> Dict[str, Any]:
        """Check the runtime is present and functional.

        Returns a dict with keys: ok (bool), detail (str), version (optional)
        """
        info = self.get_runtime_info()
        path = info.path
        if not path.exists():
            _log_error(f"Runtime python not found at {path}")
            return {"ok": False, "detail": f"Missing runtime at {path}"}
        if not os.access(path, os.X_OK):
            _log_error(f"Runtime python at {path} is not executable")
            return {"ok": False, "detail": f"Not executable: {path}"}

        # Execute a tiny healthcheck using the runtime
        try:
            out = subprocess.check_output([str(path), "-c", "import sys, json; print(json.dumps({'v': sys.version}) )"], stderr=subprocess.STDOUT, timeout=10)
            try:
                parsed = json.loads(out.decode().strip())
                version_str = parsed.get("v", "")
            except Exception:
                version_str = out.decode().strip()
            _log(f"Runtime python OK: {version_str}")
            return {"ok": True, "detail": "OK", "version": version_str}
        except subprocess.CalledProcessError as e:
            _log_error(f"Runtime python failed to execute: {e.output.decode(errors='ignore')}")
            return {"ok": False, "detail": "Runtime execution failed"}
        except Exception as e:
            _log_error(f"Runtime healthcheck error: {e}")
            return {"ok": False, "detail": str(e)}

    def repair(self) -> Dict[str, Any]:
        """Try to repair the runtime.

        Strategy:
         - Look for a tarball in runtime_cache matching the version
         - If found, extract it atomically to the target path (backup existing)
         - If not found, try to locate a meta in ports_dir/runtime/... (NOT implemented full build)

        Returns dict with keys: ok (bool), detail (str)
        """
        info = self.get_runtime_info()
        cache_dir = Path(self.cfg.get("runtime_cache", DEFAULT_CFG["runtime_cache"]))
        cache_dir.mkdir(parents=True, exist_ok=True)

        candidates = list(cache_dir.glob(f"*{info.version}*.tar*"))
        if not candidates:
            # try ports_dir/runtime tarball
            ports_dir = Path(self.cfg.get("ports_dir", DEFAULT_CFG["ports_dir"]))
            runtime_tar = ports_dir / "runtime" / f"python-{info.version}.tar.xz"
            if runtime_tar.exists():
                candidates = [runtime_tar]

        if not candidates:
            msg = f"No runtime tarball found for {info.version} in {cache_dir} or ports_dir/runtime"
            _log_error(msg)
            return {"ok": False, "detail": msg}

        tarball = candidates[0]
        _log(f"Attempting to repair runtime by extracting {tarball} -> {info.path.parent}")
        try:
            # Backup existing
            target_prefix = info.path.parent.parent  # assume .../bin/python3 -> prefix
            backup_prefix = target_prefix.with_suffix(".backup.pkgtool")
            if target_prefix.exists():
                if backup_prefix.exists():
                    shutil.rmtree(backup_prefix)
                shutil.move(str(target_prefix), str(backup_prefix))
                _log(f"Backed up existing runtime to {backup_prefix}")

            target_prefix.mkdir(parents=True, exist_ok=True)
            # Extract tarball into target_prefix
            with tarfile.open(tarball, "r:*") as tf:
                tf.extractall(path=str(target_prefix))

            # Verify presence
            if not info.path.exists():
                raise RuntimeError(f"After extraction runtime binary not found at {info.path}")

            _log(f"Runtime repaired and placed at {info.path}")
            return {"ok": True, "detail": f"Extracted {tarball} -> {target_prefix}"}
        except Exception as e:
            _log_error(f"Failed to repair runtime: {e}")
            # attempt to restore backup
            try:
                if backup_prefix.exists():
                    if target_prefix.exists():
                        shutil.rmtree(target_prefix)
                    shutil.move(str(backup_prefix), str(target_prefix))
                    _log("Restored backup of runtime after failed repair")
            except Exception:
                _log_error("Failed to restore backup runtime")
            return {"ok": False, "detail": str(e)}


# ----------------------
# Utilities
# ----------------------

def load_config() -> Dict[str, Any]:
    # Try default paths
    for p in DEFAULT_CONFIG_PATHS:
        if p.exists():
            if yaml is None:
                raise RuntimeError("PyYAML required to parse config.yml but not installed")
            with open(p, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh)
    # fallback to default hardcoded
    return DEFAULT_CFG.copy()


def _log(msg: str) -> None:
    if console:
        console.print(Panel(msg, title="pkgtool:runtime", subtitle="info"))
    else:
        print(f"[pkgtool:runtime] {msg}")


def _log_error(msg: str) -> None:
    if console:
        console.print(Panel(msg, title="pkgtool:runtime", subtitle="error"))
    else:
        print(f"[pkgtool:runtime][ERROR] {msg}", file=sys.stderr)


# ----------------------
# CLI
# ----------------------

def _cli():
    parser = argparse.ArgumentParser(prog="pkgtool-runtime", description="Manage pkgtool's protected runtime")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("info", help="Show runtime info")
    sub.add_parser("check", help="Check runtime health")
    sub.add_parser("repair", help="Attempt to repair runtime from cached tarball")
    sub.add_parser("protect", help="Mark runtime as protected in DB")
    sub.add_parser("unprotect", help="Remove runtime protection")

    args = parser.parse_args()
    rm = RuntimeManager()

    if args.cmd == "info":
        info = rm.get_runtime_info()
        print(json.dumps({"family": info.family, "version": info.version, "path": str(info.path)}, indent=2))
        return
    if args.cmd == "check":
        res = rm.check()
        print(json.dumps(res, indent=2))
        return
    if args.cmd == "repair":
        res = rm.repair()
        print(json.dumps(res, indent=2))
        return
    if args.cmd == "protect":
        rm.protect()
        print("ok")
        return
    if args.cmd == "unprotect":
        rm.unprotect()
        print("ok")
        return

    parser.print_help()


if __name__ == "__main__":
    _cli()
