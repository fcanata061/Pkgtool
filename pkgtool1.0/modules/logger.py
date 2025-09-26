# pkgtool/logger.py
"""
Logger colorido e animado para pkgtool
- Suporte a níveis (INFO, WARN, ERROR, SUCCESS, DEBUG)
- Logs gravados em arquivo + stdout colorido
- Tail -f colorido para acompanhar instalação
- Integra com configuração (log_dir)
"""

from __future__ import annotations
import os
import sys
import time
import threading
from pathlib import Path
from typing import Optional

from .config import get_config

# Cores ANSI
COLORS = {
    "INFO": "\033[36m",     # ciano
    "WARN": "\033[33m",     # amarelo
    "ERROR": "\033[31m",    # vermelho
    "SUCCESS": "\033[32m",  # verde
    "DEBUG": "\033[35m",    # magenta
    "RESET": "\033[0m",
}

# animações simples
SPINNER = ["|", "/", "-", "\\"]

class Logger:
    def __init__(self, name: str, logfile: Optional[Path] = None):
        self.name = name
        cfg = get_config()
        log_dir = Path(cfg["log_dir"])
        log_dir.mkdir(parents=True, exist_ok=True)

        self.logfile = logfile or (log_dir / f"{name}.log")
        self._lock = threading.Lock()

    def _write_file(self, msg: str):
        with self._lock:
            with open(self.logfile, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    def _print(self, level: str, msg: str):
        color = COLORS.get(level, COLORS["INFO"])
        reset = COLORS["RESET"]
        out = f"[{level}] {msg}"
        # stdout colorido
        print(f"{color}{out}{reset}", file=sys.stdout)
        # salva no log sem cores
        self._write_file(out)

    def info(self, msg: str): self._print("INFO", msg)
    def warn(self, msg: str): self._print("WARN", msg)
    def error(self, msg: str): self._print("ERROR", msg)
    def success(self, msg: str): self._print("SUCCESS", msg)
    def debug(self, msg: str): self._print("DEBUG", msg)

    # animação spinner em background
    def spinner(self, msg: str, duration: float = 3.0):
        stop = threading.Event()

        def spin():
            i = 0
            while not stop.is_set():
                sys.stdout.write(
                    f"\r{COLORS['INFO']}{SPINNER[i % len(SPINNER)]} {msg}{COLORS['RESET']}"
                )
                sys.stdout.flush()
                time.sleep(0.1)
                i += 1
            sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r")
            sys.stdout.flush()

        t = threading.Thread(target=spin)
        t.start()
        time.sleep(duration)
        stop.set()
        t.join()

    # tail -f colorido
    def tail(self, follow: bool = True, filter_level: Optional[str] = None):
        try:
            with open(self.logfile, "r", encoding="utf-8") as f:
                if follow:
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.3)
                            continue
                        line = line.strip()
                        if filter_level and not line.startswith(f"[{filter_level}]"):
                            continue
                        # cor
                        level = line.split("]")[0].strip("[]")
                        color = COLORS.get(level, "")
                        reset = COLORS["RESET"]
                        print(f"{color}{line}{reset}")
                else:
                    for line in f:
                        line = line.strip()
                        if filter_level and not line.startswith(f"[{filter_level}]"):
                            continue
                        level = line.split("]")[0].strip("[]")
                        color = COLORS.get(level, "")
                        reset = COLORS["RESET"]
                        print(f"{color}{line}{reset}")
        except KeyboardInterrupt:
            print("\n[INFO] Tail interrompido pelo usuário.")
        except Exception as e:
            print(f"[ERROR] Falha no tail: {e}", file=sys.stderr)
