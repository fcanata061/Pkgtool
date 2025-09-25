# pkgtool/env.py
\"\"\"Build environment utilities.

- Builds a clean PATH/LD_LIBRARY_PATH/PKG_CONFIG_PATH for sandboxed builds
- Resolves toolchain current symlinks
- find_program(name) that searches only in configured search_path
\"\"\"

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional, Dict
from .config import get_search_path, get_config
from .logger import info, warn

def build_env(extra: Optional[Dict[str,str]] = None) -> Dict[str,str]:
    cfg = get_config()
    search_path = get_search_path()
    # ensure unique entries, preserve order
    seen = set()
    path_list = []
    for p in search_path:
        if p not in seen:
            path_list.append(p)
            seen.add(p)
    # also add default_path at end if not present
    for p in cfg.get("default_path", []):
        if p not in seen:
            path_list.append(p)
            seen.add(p)
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(path_list)
    # LD_LIBRARY_PATH, PKG_CONFIG_PATH can be built from toolchain dirs
    toolchain_dir = Path(cfg.get("toolchain_dir", "/opt/pkgtool/toolchains"))
    ld_list = []
    pc_list = []
    # look for current symlinks
    current = toolchain_dir / "current"
    if current.exists() and current.is_dir():
        for comp in current.iterdir():
            b = comp / "lib"
            if b.exists():
                ld_list.append(str(b))
            pc = comp / "lib" / "pkgconfig"
            if pc.exists():
                pc_list.append(str(pc))
    if ld_list:
        env["LD_LIBRARY_PATH"] = os.pathsep.join(ld_list + [env.get("LD_LIBRARY_PATH","")])
    if pc_list:
        env["PKG_CONFIG_PATH"] = os.pathsep.join(pc_list + [env.get("PKG_CONFIG_PATH","")])
    if extra:
        env.update(extra)
    return env

def find_program(prog: str) -> Optional[str]:
    search_path = get_search_path()
    for d in search_path:
        p = Path(d) / prog
        if p.exists() and os.access(str(p), os.X_OK):
            return str(p)
    # also try with .exe on windows-like but we assume linux
    return None

def which(prog: str) -> Optional[str]:
    return find_program(prog)
