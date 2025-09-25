# Pkgtool/pkgtool1.0/modules/log.py
# -*- coding: utf-8 -*-
"""
Módulo de logging para pkgtool
- integração com modules.config (se disponível)
- init_logging(cfg) para inicializar a infraestrutura
- get_logger(name) para obter logger por módulo
- reload_logging(cfg) para reaplicar configurações
- set_level(level) para ajuste dinâmico
- CLI `pkgtool-log` com subcomando `live` (tail -f colorido/detalhado)
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import queue
import re
import sys
import threading
import time
from datetime import datetime
from functools import partial
from logging import Logger
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Tenta importar cfg do módulo config se estiver presente (compatibilidade com seu repo)
try:
    from modules.config import cfg  # type: ignore
except Exception:
    cfg = None  # será necessário passar cfg para init_logging se não disponível

# tenta importar watchdog para file watching (opcional)
try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    _have_watchdog = True
except Exception:
    _have_watchdog = False

# global state
_GLOBAL = {
    "initialized": False,
    "queue": None,  # queue.Queue used by QueueHandler
    "listener": None,  # QueueListener
    "root_logger": logging.getLogger(),
    "config_snapshot": None,
}

# Default logging configuration when config is absent or invalid
_DEFAULT_LOG_CONFIG = {
    "level": "INFO",
    "logfile": None,
    "rotate": True,
    "max_size_mb": 50,
    "backup_count": 5,
    "console": True,
    "console_colors": True,
    "json_format": False,
    "syslog": False,
    "syslog_address": "/dev/log",
    "async": True,
    "queue_size": 10000,
    "context": ["pid", "tid", "user", "elapsed"],
    "levels": {},  # per-namespace levels
}


# ---------------- Formatters ----------------

class ColorFormatter(logging.Formatter):
    COLOR_MAP = {
        "DEBUG": "\033[94m",    # light blue
        "INFO": "\033[92m",     # green
        "WARNING": "\033[93m",  # yellow
        "ERROR": "\033[91m",    # red
        "CRITICAL": "\033[95m", # magenta
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, datefmt: Optional[str] = None, use_colors: bool = True):
        super().__init__(fmt=fmt, datefmt=datefmt, style="%")
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        prefix = ""
        suffix = ""
        if self.use_colors and levelname in self.COLOR_MAP:
            prefix = self.COLOR_MAP[levelname]
            suffix = self.RESET
        msg = super().format(record)
        return f"{prefix}{msg}{suffix}"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "pid": getattr(record, "pid", os.getpid()),
            "tid": getattr(record, "tid", threading.get_ident()),
        }
        if record.exc_info:
            obj["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False)


class StructuredFormatter(logging.Formatter):
    """
    Formatter que inclui o contexto configurável (pid, tid, user, elapsed)
    e produz uma string legível.
    """
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, context: Optional[List[str]] = None):
        fmt = fmt or "%(asctime)s [%(levelname)s] %(name)s %(context)s -> %(message)s"
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.context_keys = context or ["pid", "tid", "user", "elapsed"]
        self.start_time = time.time()

    def format(self, record: logging.LogRecord) -> str:
        ctx = []
        if "pid" in self.context_keys:
            ctx.append(f"pid={getattr(record, 'pid', os.getpid())}")
        if "tid" in self.context_keys:
            ctx.append(f"tid={getattr(record, 'tid', threading.get_ident())}")
        if "user" in self.context_keys:
            try:
                user = os.getlogin()
            except Exception:
                user = os.environ.get("USER", "")
            ctx.append(f"user={user}")
        if "elapsed" in self.context_keys:
            elapsed = time.time() - self.start_time
            ctx.append(f"elapsed={elapsed:.2f}s")
        record.context = "[" + " ".join(ctx) + "]"
        return super().format(record)


# ---------------- Utilities ----------------

def _merge_with_defaults(conf: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    base = dict(_DEFAULT_LOG_CONFIG)
    if not conf:
        return base
    # shallow merge for top-level keys; nested 'levels' handled
    for k, v in conf.items():
        if k == "levels" and isinstance(v, dict):
            base["levels"].update(v)
        else:
            base[k] = v
    return base


def _level_str_to_int(level: str) -> int:
    try:
        return getattr(logging, str(level).upper())
    except Exception:
        return logging.INFO


# ---------------- Initialization / teardown ----------------

def init_logging(config: Optional[Dict[str, Any]] = None, *, cfg_obj: Optional[Any] = None) -> None:
    """
    Inicializa a infraestrutura de logging.

    - config: dicionário com opções (normalmente cfg._state.data['logging'] ou cfg.get('logging')).
    - cfg_obj: se fornecido, será guardado como snapshot (usado por reload_logging).
    """
    # prefer explicit config dict, else try cfg global object if present
    conf_source = config
    if conf_source is None and cfg_obj is None and cfg is not None:
        try:
            conf_source = cfg.get("logging", None)
            cfg_obj = cfg
        except Exception:
            conf_source = None

    conf = _merge_with_defaults(conf_source)

    # teardown previous listener if any
    if _GLOBAL.get("listener"):
        try:
            _GLOBAL["listener"].stop()
        except Exception:
            pass
        _GLOBAL["listener"] = None
        _GLOBAL["queue"] = None

    # prepare handlers
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    root.setLevel(_level_str_to_int(conf.get("level", "INFO")))

    handlers: List[logging.Handler] = []

    # Console handler
    if conf.get("console", True):
        fmt = "%(asctime)s [%(levelname)s] %(name)s %(context)s -> %(message)s"
        sf = StructuredFormatter(fmt=fmt, datefmt="%Y-%m-%d %H:%M:%S", context=conf.get("context"))
        use_colors = bool(conf.get("console_colors", True))
        cf = ColorFormatter(fmt=sf._style._fmt, datefmt=sf.datefmt, use_colors=use_colors)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(_level_str_to_int(conf.get("level", "INFO")))
        ch.setFormatter(cf)
        handlers.append(ch)

    # File handler (rotating)
    logfile = conf.get("logfile")
    if logfile:
        try:
            Path(logfile).parent.mkdir(parents=True, exist_ok=True)
            if conf.get("rotate", True):
                max_bytes = int(conf.get("max_size_mb", 50)) * 1024 * 1024
                fh = logging.handlers.RotatingFileHandler(
                    logfile,
                    maxBytes=max_bytes,
                    backupCount=int(conf.get("backup_count", 5)),
                    encoding="utf-8",
                )
            else:
                fh = logging.FileHandler(logfile, encoding="utf-8")
            # choose formatter: json or structured
            if conf.get("json_format", False):
                fh.setFormatter(JsonFormatter())
            else:
                fh.setFormatter(StructuredFormatter(context=conf.get("context")))
            fh.setLevel(_level_str_to_int(conf.get("level", "INFO")))
            handlers.append(fh)
        except Exception:
            # fallback to stderr
            fallback = logging.StreamHandler(sys.stderr)
            fallback.setFormatter(StructuredFormatter(context=conf.get("context")))
            handlers.append(fallback)
            root.warning("Não foi possível criar arquivo de log '%s', fallback para stderr.", logfile)

    # Syslog handler (optional)
    if conf.get("syslog", False):
        try:
            addr = conf.get("syslog_address", "/dev/log")
            if isinstance(addr, str) and ":" in addr:
                host, port_s = addr.rsplit(":", 1)
                handler = logging.handlers.SysLogHandler(address=(host, int(port_s)))
            else:
                handler = logging.handlers.SysLogHandler(address=addr)
            handler.setFormatter(StructuredFormatter(context=conf.get("context")))
            handler.setLevel(_level_str_to_int(conf.get("level", "INFO")))
            handlers.append(handler)
        except Exception:
            root.warning("Syslog não configurado (falha ao criar handler).")

    # Per-namespace log levels
    levels = conf.get("levels", {}) or {}
    for name, lvl in levels.items():
        try:
            logging.getLogger(name).setLevel(_level_str_to_int(lvl))
        except Exception:
            pass

    # Async handling via QueueHandler + QueueListener
    if conf.get("async", True):
        qsize = int(conf.get("queue_size", 10000) or 10000)
        q: queue.Queue = queue.Queue(maxsize=qsize)
        _GLOBAL["queue"] = q
        # QueueHandler
        qh = logging.handlers.QueueHandler(q)
        root.addHandler(qh)
        # listener uses the real handlers
        listener = logging.handlers.QueueListener(q, *handlers, respect_handler_level=True)
        listener.start()
        _GLOBAL["listener"] = listener
    else:
        # synchronous: add handlers to root directly
        for h in handlers:
            root.addHandler(h)

    _GLOBAL["initialized"] = True
    _GLOBAL["root_logger"] = root
    _GLOBAL["config_snapshot"] = conf
    # ensure that logging from other places includes pid/tid context via filter if desired
    # add a small filter to attach pid/tid to records
    root.addFilter(_ContextFilter())

    root.debug("Logging inicializado. Config: %s", conf)


def shutdown_logging() -> None:
    """
    Para listeners e limpa handlers.
    """
    if _GLOBAL.get("listener"):
        try:
            _GLOBAL["listener"].stop()
        except Exception:
            pass
        _GLOBAL["listener"] = None
    root = logging.getLogger()
    for h in list(root.handlers):
        try:
            h.flush()
            h.close()
        except Exception:
            pass
        root.removeHandler(h)
    _GLOBAL["initialized"] = False


def reload_logging(config: Optional[Dict[str, Any]] = None, *, cfg_obj: Optional[Any] = None) -> None:
    """
    Reaplica configurações de logging. Se config None e cfg global existe, usa cfg.
    """
    init_logging(config, cfg_obj=cfg_obj)


def set_level(level: str) -> None:
    lvl = _level_str_to_int(level)
    logging.getLogger().setLevel(lvl)


def get_logger(name: str) -> Logger:
    """
    Retorna um logger com preenchimento básico (mantém compatibilidade).
    """
    return logging.getLogger(name)


# ---------------- Context Filter ----------------

class _ContextFilter(logging.Filter):
    """
    Anexa pid/tid/extra campos ao registro, para formatters usarem.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        record.pid = os.getpid()
        record.tid = threading.get_ident()
        # user may be requested in formatters; do not obtain os.getlogin() for performance each time
        record.user = os.environ.get("USER", "")
        return True


# ---------------- Live tail (tail -f colorido) ----------------

def _follow_with_polling(path: Path, callback, stop_event: threading.Event, sleep: float = 0.2, start_pos: Optional[int] = None):
    """
    Implementação básica de tail -f por polling; chama callback(line) para cada nova linha.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            if start_pos:
                try:
                    f.seek(start_pos)
                except Exception:
                    pass
            else:
                # start at end (like tail -f)
                f.seek(0, os.SEEK_END)
            while not stop_event.is_set():
                line = f.readline()
                if line:
                    callback(line.rstrip("\n"))
                else:
                    time.sleep(sleep)
    except FileNotFoundError:
        # wait until file appears
        while not stop_event.is_set():
            if path.exists():
                return _follow_with_polling(path, callback, stop_event, sleep, start_pos)
            time.sleep(sleep)
    except Exception as e:
        # fatal I/O error -> call callback with an error line
        callback(f"[log.follow error] {e}")


if _have_watchdog:
    class _WatchdogHandler(FileSystemEventHandler):
        def __init__(self, path: Path, callback, stop_event: threading.Event):
            super().__init__()
            self._path = path
            self._callback = callback
            self._stop_event = stop_event
            self._file = None
            self._inode = None
            self._open_file()

        def _open_file(self):
            try:
                self._file = self._path.open("r", encoding="utf-8", errors="replace")
                self._file.seek(0, os.SEEK_END)
                self._inode = os.fstat(self._file.fileno()).st_ino
            except Exception:
                self._file = None
                self._inode = None

        def on_modified(self, event):
            if self._stop_event.is_set():
                return
            if event.src_path != str(self._path):
                return
            if not self._file:
                self._open_file()
                if not self._file:
                    return
            while True:
                line = self._file.readline()
                if not line:
                    break
                self._callback(line.rstrip("\n"))

        def on_moved(self, event):
            # logrotate may move the file; re-open new file if present
            if event.dest_path == str(self._path):
                try:
                    self._open_file()
                except Exception:
                    pass


def follow_log(live_file: Optional[str] = None, level: Optional[str] = None,
               module: Optional[str] = None, regex: Optional[str] = None,
               color: Optional[bool] = None) -> None:
    """
    Segue o arquivo de log (modo tail -f) imprimindo linhas coloridas e detalhadas.
    - live_file: caminho para arquivo de log (se None, tenta usar config)
    - level: filtrar por nível (INFO, ERROR, etc.)
    - module: filtrar por nome do logger que aparece na linha
    - regex: regex a aplicar na linha completa
    """
    # Determine file
    conf = _GLOBAL.get("config_snapshot") or {}
    if not live_file:
        live_file = conf.get("logfile") or os.environ.get("PKGTOOL_LOG_FILE")
    if not live_file:
        print("Nenhum arquivo de log configurado. Passe --file ou configure logging.logfile.", file=sys.stderr)
        return
    path = Path(live_file)
    # precompile regex and level
    regex_re = re.compile(regex) if regex else None
    level_upper = level.upper() if level else None
    colorize = color if color is not None else bool(conf.get("console_colors", True))

    # prepare simple pretty printer that parses a structured log line or JSON
    def pretty_print_line(line: str):
        # try JSON
        try:
            obj = json.loads(line)
            # structured JSON produced by JsonFormatter
            ts = obj.get("timestamp", "")
            lvl = obj.get("level", "")
            mod = obj.get("module", "")
            msg = obj.get("message", "")
            pid = obj.get("pid", "")
            tid = obj.get("tid", "")
            out = f"{ts} [{lvl}] ({mod}) pid={pid} tid={tid} -> {msg}"
        except Exception:
            # not JSON; attempt to print raw but colorize level tokens like [INFO]
            out = line
            ts = ""
            lvl = None
            m = re.search(r"\[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\]", line)
            if m:
                lvl = m.group(1)
            modm = re.search(r"\] (\S+)", line)
            mod = modm.group(1) if modm else ""
        # apply filters
        if level_upper and lvl and lvl != level_upper:
            return
        if module and module not in (mod or ""):
            return
        if regex_re and not regex_re.search(line):
            return
        # colorize based on level tokens
        if colorize and lvl:
            color_map = {
                "DEBUG": "\033[94m",
                "INFO": "\033[92m",
                "WARNING": "\033[93m",
                "ERROR": "\033[91m",
                "CRITICAL": "\033[95m",
            }
            clr = color_map.get(lvl, "")
            reset = "\033[0m"
            print(f"{clr}{out}{reset}")
        else:
            print(out)

    stop_event = threading.Event()
    try:
        if _have_watchdog:
            # use watchdog observer
            observer = Observer()
            handler = _WatchdogHandler(path, pretty_print_line, stop_event)
            observer.schedule(handler, str(path.parent), recursive=False)
            observer.start()
            print(f"Seguindo {path} (watchdog). Ctrl-C para parar.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                stop_event.set()
                observer.stop()
                observer.join()
        else:
            # fallback polling style
            print(f"Seguindo {path} (polling). Ctrl-C para parar.")
            _follow_with_polling(path, pretty_print_line, stop_event)
    except KeyboardInterrupt:
        stop_event.set()
    except Exception as e:
        print(f"Erro ao seguir log: {e}", file=sys.stderr)


# ---------------- CLI ----------------

def _build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkgtool-log", description="Ferramenta de inspeção de logs do pkgtool")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("show", help="Mostra a configuração atual de logging")

    p_tail = sub.add_parser("tail", help="Segue arquivo de log (modo tail -f simples)")
    p_tail.add_argument("--file", "-f", help="Arquivo de log para seguir (se omitido usa config)")

    p_live = sub.add_parser("live", help="Seguir log em tempo real (colorido/detalhado).")
    p_live.add_argument("--file", "-f", help="Arquivo de log para seguir (se omitido usa config)")
    p_live.add_argument("--level", help="Filtrar por nível (DEBUG/INFO/WARNING/ERROR)")
    p_live.add_argument("--module", help="Filtrar por módulo (ex: pkgtool.build)")
    p_live.add_argument("--regex", help="Filtrar por regex")
    p_live.add_argument("--no-color", dest="no_color", action="store_true", help="Desabilitar cores")

    p_grep = sub.add_parser("grep", help="Pesquisar texto nos logs")
    p_grep.add_argument("pattern", help="Padrão regex")
    p_grep.add_argument("--file", "-f", help="Arquivo de log")

    p_export = sub.add_parser("export", help="Exportar logs em JSON (se o arquivo estiver em texto estruturado)")
    p_export.add_argument("--file", "-f", help="Arquivo de log")
    p_export.add_argument("--out", "-o", help="Arquivo de saída (stdout se omitido)")
    return p


def cli_main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    # ensure logging is initialized (try to use cfg)
    try:
        if not _GLOBAL.get("initialized"):
            if cfg is not None:
                init_logging(cfg.get("logging", {}), cfg_obj=cfg)
            else:
                init_logging(None)
    except Exception:
        init_logging(None)

    if args.cmd == "show":
        conf = _GLOBAL.get("config_snapshot") or {}
        print(json.dumps(conf, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "tail":
        file = getattr(args, "file", None)
        follow_log(live_file=file, color=True)
        return 0

    if args.cmd == "live":
        file = getattr(args, "file", None)
        lvl = getattr(args, "level", None)
        mod = getattr(args, "module", None)
        regex = getattr(args, "regex", None)
        color = not getattr(args, "no_color", False)
        follow_log(live_file=file, level=lvl, module=mod, regex=regex, color=color)
        return 0

    if args.cmd == "grep":
        file = getattr(args, "file", None)
        pattern = args.pattern
        conf = _GLOBAL.get("config_snapshot") or {}
        fpath = file or conf.get("logfile")
        if not fpath:
            print("Especifique um arquivo de log com --file ou configure logging.logfile.", file=sys.stderr)
            return 2
        try:
            regex = re.compile(pattern)
        except re.error as e:
            print(f"Regex inválida: {e}", file=sys.stderr)
            return 3
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                if regex.search(ln):
                    print(ln.rstrip("\n"))
        return 0

    if args.cmd == "export":
        file = getattr(args, "file", None)
        out = getattr(args, "out", None)
        conf = _GLOBAL.get("config_snapshot") or {}
        fpath = file or conf.get("logfile")
        if not fpath:
            print("Especifique um arquivo de log com --file ou configure logging.logfile.", file=sys.stderr)
            return 2
        out_fp = open(out, "w", encoding="utf-8") if out else sys.stdout
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                # tenta interpretar linha como JSON já estruturada
                try:
                    obj = json.loads(ln)
                    out_fp.write(json.dumps(obj, ensure_ascii=False) + "\n")
                except Exception:
                    # fallback: wrap raw line
                    out_fp.write(json.dumps({"raw": ln}, ensure_ascii=False) + "\n")
        if out:
            out_fp.close()
        return 0

    parser.print_help()
    return 1


# ---------------- Auto-init on import (best-effort) ----------------

# If a cfg object is present and has logging section, initialize automatically.
try:
    if not _GLOBAL.get("initialized") and cfg is not None:
        try:
            init_logging(cfg.get("logging", {}), cfg_obj=cfg)
        except Exception:
            init_logging(None)
except Exception:
    # do not raise on import errors
    init_logging(None)


# ---------------- If executed as script ----------------
if __name__ == "__main__":
    try:
        sys.exit(cli_main())
    except KeyboardInterrupt:
        print("Interrompido.", file=sys.stderr)
        sys.exit(130)
