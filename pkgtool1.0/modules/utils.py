#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils.py
Funções utilitárias para pkgtool.

Responsabilidades:
- Execução segura de subprocessos (com suporte a dry-run, logs coloridos, captura de saída).
- Manipulação de arquivos (escrita atômica, criação de diretórios).
- Checksums (SHA256).
- Logging básico com cores (INFO, WARN, ERROR).
- Funções auxiliares que outros módulos podem usar.
"""

from __future__ import annotations
import os
import subprocess
import hashlib
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple, Optional, Union

# -----------------------
# Cores para logs
# -----------------------
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"

def log_info(msg: str) -> None:
    sys.stderr.write(f"{Colors.BLUE}[INFO]{Colors.RESET} {msg}\n")

def log_warn(msg: str) -> None:
    sys.stderr.write(f"{Colors.YELLOW}[WARN]{Colors.RESET} {msg}\n")

def log_error(msg: str) -> None:
    sys.stderr.write(f"{Colors.RED}[ERROR]{Colors.RESET} {msg}\n")

def log_success(msg: str) -> None:
    sys.stderr.write(f"{Colors.GREEN}[ OK ]{Colors.RESET} {msg}\n")

# -----------------------
# Execução segura
# -----------------------
class CommandError(Exception):
    def __init__(self, cmd: List[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command {' '.join(cmd)} failed with code {returncode}")

def safe_run(
    cmd: Union[List[str], str],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    capture: bool = False,
    check: bool = True,
    dry_run: bool = False
) -> Tuple[int, str, str]:
    """
    Run a command safely.
    Args:
        cmd: list of str (recommended) or str
        cwd: working directory
        env: environment variables (merged with os.environ)
        capture: capture stdout/stderr
        check: raise CommandError if non-zero
        dry_run: just print command, don't execute
    Returns:
        (returncode, stdout, stderr)
    """
    if isinstance(cmd, str):
        display_cmd = cmd
    else:
        display_cmd = " ".join(cmd)

    if dry_run:
        log_info(f"[dry-run] {display_cmd}")
        return (0, "", "")

    log_info(f"exec: {display_cmd}")

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    try:
        if capture:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=merged_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            rc = proc.returncode
            out = proc.stdout
            err = proc.stderr
        else:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                env=merged_env,
                check=False,
            )
            rc = proc.returncode
            out, err = "", ""
    except FileNotFoundError as e:
        raise CommandError([str(cmd)], 127, "", str(e))

    if check and rc != 0:
        raise CommandError(cmd if isinstance(cmd, list) else [cmd], rc, out, err)

    return (rc, out, err)

# -----------------------
# Arquivos
# -----------------------
def ensure_dir(path: Union[str, Path], mode: int = 0o755) -> None:
    """
    Cria diretório recursivamente se não existir.
    """
    p = Path(path)
    if not p.exists():
        p.mkdir(parents=True, mode=mode, exist_ok=True)

def write_atomic(path: Union[str, Path], data: Union[str, bytes], mode: int = 0o644) -> None:
    """
    Escreve arquivo de forma atômica (em tmp e depois rename).
    """
    p = Path(path)
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(p.parent))
    with os.fdopen(tmp_fd, 'wb' if isinstance(data, bytes) else 'w', encoding=None if isinstance(data, bytes) else 'utf-8') as f:
        f.write(data)
    os.chmod(tmp_name, mode)
    os.replace(tmp_name, p)

# -----------------------
# Checksums
# -----------------------
def sha256sum(path: Union[str, Path]) -> str:
    """
    Calcula sha256 de um arquivo.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_checksum(path: Union[str, Path], expected: str) -> bool:
    """
    Verifica sha256 contra valor esperado.
    """
    actual = sha256sum(path)
    if actual.lower() != expected.lower():
        log_error(f"Checksum mismatch for {path}: expected {expected}, got {actual}")
        return False
    log_success(f"Checksum OK for {path}")
    return True
