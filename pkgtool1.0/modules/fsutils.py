# pkgtool/fsutils.py
\"\"\"Filesystem helpers: atomic move, safe rmtree, download with resume (simple)\n\"\"\"

from __future__ import annotations
import os
import shutil
from pathlib import Path
from typing import Optional
import urllib.request
import tempfile

def safe_rmtree(p: Path):
    try:
        if p.exists():
            shutil.rmtree(str(p))
    except Exception:
        # try more aggressive approach
        for root, dirs, files in os.walk(str(p), topdown=False):
            for name in files:
                try:
                    os.unlink(os.path.join(root, name))
                except Exception:
                    pass
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except Exception:
                    pass
        try:
            if p.exists():
                os.rmdir(str(p))
        except Exception:
            pass

def atomic_move(src: Path, dest: Path):
    dest_parent = dest.parent
    dest_parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(prefix="pkgtool-mv-", dir=str(dest_parent), delete=False)
    tmp.close()
    os.rename(str(src), tmp.name)
    os.replace(tmp.name, str(dest))

def download_url(url: str, dest: Path, chunk_size: int = 8192) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    # simple download
    with urllib.request.urlopen(url) as r, open(dest, "wb") as fh:
        while True:
            chunk = r.read(chunk_size)
            if not chunk:
                break
            fh.write(chunk)
    return dest
