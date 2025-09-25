
# pkgtool/config.py
\"\"\"Configuration loader for pkgtool.

Search order:
 - /etc/pkgtool/config.yml
 - ~/.config/pkgtool/config.yml

If none present, sensible defaults are used.

Exposes:
 - load_config()
 - get_config()
 - get_path(name, default)
 - get_toolchain_config()
\"\"\"

from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, Optional
import json

try:
    import yaml
except Exception:
    yaml = None

DEFAULTS = {
    "ports_dir": "/usr/ports/pkgtool",
    "toolchain_dir": "/opt/pkgtool/toolchains",
    "build_root": "/var/tmp/pkgtool/builds",
    "destdir_root": "/var/tmp/pkgtool/dest",
    "package_store": "/var/pkgtool/packages",
    "log_dir": "/var/log/pkgtool",
    "db_path": "/var/lib/pkgtool/pkgtool.db",
    "cache_dir": "/var/cache/pkgtool",
    "runtime_cache": "/var/cache/pkgtool/runtime",
    "search_path": ["/opt/pkgtool/toolchains/current/bin", "/usr/local/bin", "/usr/bin", "/bin"],
    "default_path": ["/usr/local/bin", "/usr/bin", "/bin", "/sbin"],
    "max_parallel_builds": 4,
    "default_jobs": 4,
    "pkgtool_runtime": {
        "python": {
            "version": "3.12.5",
            "path": "/opt/pkgtool/runtime/python/3.12.5/bin/python3"
        }
    },
    "toolchain": {
        "gcc": {"default": None, "versions": []},
        "binutils": {"default": None, "versions": []},
        "glibc": {"default": None, "versions": []},
        "kernel": {"default": None, "versions": []}
    }
}

CONFIG_PATHS = [
    Path("/etc/pkgtool/config.yml"),
    Path.home() / ".config" / "pkgtool" / "config.yml"
]

_loaded_config: Optional[Dict[str, Any]] = None

def _read_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to parse YAML config files (pip install pyyaml)")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}

def load_config() -> Dict[str, Any]:
    global _loaded_config
    if _loaded_config is not None:
        return _loaded_config
    for p in CONFIG_PATHS:
        if p.exists():
            conf = _read_yaml(p)
            merged = DEFAULTS.copy()
            # shallow merge; config may override keys
            merged.update(conf)
            _loaded_config = merged
            return _loaded_config
    # fallback to defaults
    _loaded_config = DEFAULTS.copy()
    return _loaded_config

def get_config() -> Dict[str, Any]:
    return load_config()

def get_path(name: str, default: Optional[str] = None) -> str:
    cfg = load_config()
    v = cfg.get(name)
    if v is None:
        if default is not None:
            return default
        raise KeyError(f"Config key '{name}' not found")
    return v

def get_search_path() -> list:
    cfg = load_config()
    sp = cfg.get("search_path") or cfg.get("default_path") or DEFAULTS["default_path"]
    return list(sp)

def get_toolchain_config() -> Dict[str, Any]:
    cfg = load_config()
    return cfg.get("toolchain", DEFAULTS["toolchain"])
