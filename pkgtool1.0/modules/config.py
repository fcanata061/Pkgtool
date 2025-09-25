# Pkgtool/pkgtool1.0/modules/config.py
# -*- coding: utf-8 -*-
"""
Config module for pkgtool
- suporta TOML e JSON
- múltiplos mirrors (incluindo git)
- API thread-safe para leitura/escrita
- hooks de mudança
- utilitários para build env
- CLI 'pkgtool-config' com subcomandos
- gera config.sample.toml automaticamente via função/write-sample subcommand
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import shutil
import stat
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

# tomllib disponível em Python 3.11+; fallback para 'toml' package se instalado.
try:
    import tomllib as _toml_lib  # type: ignore
    _have_toml = True
    def parse_toml_bytes(b: bytes) -> dict:
        return _toml_lib.loads(b.decode('utf-8')) if isinstance(b, bytes) else _toml_lib.loads(b)
except Exception:
    try:
        import toml as _toml  # type: ignore
        _have_toml = True
        def parse_toml_bytes(b: bytes) -> dict:
            return _toml.loads(b.decode('utf-8')) if isinstance(b, bytes) else _toml.loads(b)
    except Exception:
        _have_toml = False

# Logging básico para o módulo — a aplicação principal pode reconfigurar.
logger = logging.getLogger("pkgtool.config")
if not logger.handlers:
    h = logging.StreamHandler()
    fmt = logging.Formatter("%(asctime)s %(levelname)s [pkgtool.config] %(message)s")
    h.setFormatter(fmt)
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# Exceptions
class ConfigError(Exception):
    pass

# Types
MirrorType = Dict[str, Any]  # exemplo: {'name': 'mirror1', 'type': 'http'|'git', 'url': 'https://...', 'priority': 10}

DEFAULT_SAMPLE_TOML = r"""# Pkgtool configuration sample (config.sample.toml)
# Coloque seu config em /etc/pkgtool/config.toml ou em Pkgtool/pkgtool1.0/config.toml para desenvolvimento.

[paths]
install_root = "/usr/local"
build_root = "/var/lib/pkgtool/build"
cache_dir = "/var/cache/pkgtool"
repo_dir = "/var/lib/pkgtool/repo"
toolchain_dir = "/opt/pkgtool/toolchains"
log_dir = "/var/log/pkgtool"

[network]
# mirrors: lista de tabelas com name, type (http|git), url, priority
# Exemplo de mirror HTTP:
[[network.mirrors]]
name = "main-http"
type = "http"
url = "https://mirror1.example/packages/"
priority = 100

# Exemplo de mirror git:
[[network.mirrors]]
name = "main-git"
type = "git"
url = "git+https://github.com/example/pkg-repo.git"
priority = 50

timeout = 30
max_retries = 3

[security]
keyring = "/etc/pkgtool/keys/pubring.gpg"
verify_signatures = true
allow_unsigned = false

[build]
default_cflags = "-O2 -pipe"
jobs = 4
bootstrap = true
sysroot = ""

[logging]
level = "INFO"
logfile = "/var/log/pkgtool/pkgtool.log"
rotate = true
max_size_mb = 50

[profiles.dev]
paths_override = { install_root = "/home/dev/.local", build_root = "/home/dev/.cache/pkgtool/build" }

[profiles.ci]
paths_override = { build_root = "/tmp/ci-build", cache_dir = "/tmp/ci-cache" }
"""

@dataclass
class _InternalState:
    data: Dict[str, Any] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)
    hooks: List[Callable[[Dict[str, Any]], None]] = field(default_factory=list)
    source_path: Optional[Path] = None
    format: Optional[str] = None  # 'toml' or 'json'

@dataclass
class Config:
    """
    Classe principal de configuração. Trabalha com um dicionário aninhado internamente.
    Todas as operações públicas são thread-safe.
    """
    _state: _InternalState = field(default_factory=_InternalState)

    # --- carregamento / salvamento ---
    @classmethod
    def load(cls, path: Optional[Union[str, Path]] = None, fallback_sample: bool = True) -> "Config":
        """
        Carrega configuração de `path`. Se None, tenta uma lista de locais padrões:
        - /etc/pkgtool/config.toml
        - ./Pkgtool/pkgtool1.0/config.toml
        - ./config.toml
        Se não encontrar e fallback_sample=True -> escreve config.sample.toml (local de repo) e carrega defaults.
        """
        cfg = cls()
        with cfg._state.lock:
            tried = []
            candidates = []
            if path:
                candidates.append(Path(path))
            else:
                candidates.extend([
                    Path("/etc/pkgtool/config.toml"),
                    Path.cwd() / "Pkgtool" / "pkgtool1.0" / "config.toml",
                    Path.cwd() / "config.toml",
                    Path.cwd() / "Pkgtool" / "pkgtool1.0" / "config.json",
                    Path.cwd() / "config.json",
                ])
            for p in candidates:
                try:
                    if p.exists() and p.is_file():
                        cfg._load_from_file(p)
                        cfg._state.source_path = p
                        logger.info("Config carregada de %s", str(p))
                        return cfg
                    else:
                        tried.append(str(p))
                except Exception as e:
                    logger.warning("Falha ao ler config %s: %s", p, e)
            # fallback: se sample solicitado, escreve um sample no repo se possível
            if fallback_sample:
                sample_path = Path.cwd() / "Pkgtool" / "pkgtool1.0" / "config.sample.toml"
                try:
                    if not sample_path.exists():
                        sample_path.parent.mkdir(parents=True, exist_ok=True)
                        sample_path.write_text(DEFAULT_SAMPLE_TOML, encoding="utf-8")
                        logger.info("Wrote sample config to %s", str(sample_path))
                except Exception as e:
                    logger.debug("Não foi possível escrever sample config: %s", e)
            # se não encontrou, inicializa defaults mínimos
            cfg._state.data = _default_config_dict()
            cfg._state.format = "toml"
            logger.info("Nenhum arquivo de configuração local encontrado; usando defaults em memória.")
            return cfg

    def _load_from_file(self, p: Path) -> None:
        raw = p.read_bytes()
        # detect format: .toml or .json or try toml then json
        fmt = None
        if p.suffix.lower() in (".toml",):
            if not _have_toml:
                raise ConfigError("TOML não suportado nesta instalação de Python (não há tomllib nem toml).")
            parsed = parse_toml_bytes(raw)
            fmt = "toml"
        elif p.suffix.lower() in (".json",):
            parsed = json.loads(raw.decode("utf-8"))
            fmt = "json"
        else:
            # tentativa inteligente: se TOML possível, tente; senão JSON
            if _have_toml:
                try:
                    parsed = parse_toml_bytes(raw)
                    fmt = "toml"
                except Exception:
                    parsed = json.loads(raw.decode("utf-8"))
                    fmt = "json"
            else:
                parsed = json.loads(raw.decode("utf-8"))
                fmt = "json"
        if not isinstance(parsed, dict):
            raise ConfigError("Formato de configuração inválido: raiz não é um objeto/dicionário.")
        self._state.data = parsed
        self._state.format = fmt

    def save(self, path: Optional[Union[str, Path]] = None, fmt: Optional[str] = None) -> None:
        """
        Persiste a configuração atual para `path`. Se path None e _state.source_path conhecido -> sobrescreve.
        `fmt` força "toml" ou "json".
        """
        with self._state.lock:
            target = Path(path) if path else (self._state.source_path or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "config.toml"))
            # determine format
            chosen_fmt = fmt or self._state.format or ( "toml" if str(target).lower().endswith(".toml") else "json" )
            # serialize
            if chosen_fmt == "toml":
                if not _have_toml:
                    raise ConfigError("TOML não disponível; instale 'toml' ou use formato json.")
                # use simple conversion via toml package if available or tomllib alternative
                try:
                    # prefer using toml.dumps if we have the package
                    if 'toml' in sys.modules:
                        dumps = sys.modules['toml'].dumps  # type: ignore
                        content = dumps(self._state.data)
                    else:
                        # tomllib doesn't provide dumps; fall back to json-like writing as simple manual conversion is fragile
                        # So convert to json with indent as fallback but keep .toml extension only if toml package present.
                        content = json.dumps(self._state.data, indent=2, ensure_ascii=False)
                        logger.warning("Escrevendo em arquivo .toml mas sem toml.dumps disponível; escrevendo JSON em .toml")
                except Exception as e:
                    raise ConfigError(f"Erro ao serializar para TOML: {e}")
            elif chosen_fmt == "json":
                content = json.dumps(self._state.data, indent=2, ensure_ascii=False)
            else:
                raise ConfigError(f"Formato desconhecido para salvar: {chosen_fmt}")
            # ensure parent dir
            target.parent.mkdir(parents=True, exist_ok=True)
            # write atomically
            tmp = target.with_suffix(target.suffix + f".{int(time.time())}.tmp")
            tmp.write_text(content, encoding="utf-8")
            # set permissions - readable and writable by owner, readable by group
            try:
                tmp.chmod(0o644)
            except Exception:
                pass
            tmp.replace(target)
            self._state.source_path = target
            self._state.format = chosen_fmt
            logger.info("Config salva em %s (formato=%s)", str(target), chosen_fmt)
            # call hooks
            self._call_hooks()

    # --- leitura / escrita ---
    def get(self, dotted_key: str, default: Any = None) -> Any:
        """
        Busca usando chave pontuada, ex: 'paths.install_root'
        """
        with self._state.lock:
            parts = dotted_key.split(".") if dotted_key else []
            cur = self._state.data
            for p in parts:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    return default
            return cur

    def set(self, dotted_key: str, value: Any, persist: bool = False) -> None:
        """
        Seta valor em chave pontuada; cria dicionários intermediários se necessário.
        Se persist=True -> salva em disco no mesmo caminho anterior (ou em config.toml do repo).
        """
        with self._state.lock:
            parts = dotted_key.split(".") if dotted_key else []
            if not parts:
                raise ConfigError("Chave vazia não é permitida.")
            cur = self._state.data
            for p in parts[:-1]:
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
            cur[parts[-1]] = value
            logger.debug("Config set: %s = %r", dotted_key, value)
            self._call_hooks()
            if persist:
                # tentativa de salvar; se falhar, lança
                self.save()

    def merge(self, overrides: Dict[str, Any]) -> "Config":
        """
        Retorna nova instância Config com dicicionário mesclado (deep merge).
        """
        with self._state.lock:
            base = _deep_copy(self._state.data)
            merged = _deep_merge_dict(base, overrides)
            newcfg = Config()
            newcfg._state.data = merged
            newcfg._state.format = self._state.format
            newcfg._state.source_path = self._state.source_path
            return newcfg

    def apply_profile(self, profile_name: str, persist: bool = False) -> None:
        """
        Aplica um perfil a partir de 'profiles.<profile_name>'. Perfil pode conter 'paths_override' etc.
        """
        with self._state.lock:
            profiles = self._state.data.get("profiles", {})
            prof = profiles.get(profile_name)
            if not prof:
                raise ConfigError(f"Perfil '{profile_name}' não existe.")
            overrides = prof.get("paths_override", {})
            if overrides:
                # mescla simples nas paths
                paths = self._state.data.setdefault("paths", {})
                for k, v in overrides.items():
                    paths[k] = v
            # aplicar outros campos do perfil se existirem
            other = {k: v for k, v in prof.items() if k != "paths_override"}
            if other:
                self._state.data = _deep_merge_dict(self._state.data, {"profiles_applied": {profile_name: other}})
            logger.info("Perfil '%s' aplicado.", profile_name)
            self._call_hooks()
            if persist:
                self.save()

    def validate(self, strict: bool = True) -> None:
        """
        Valida algumas regras de integridade. Se strict=True levanta ConfigError em falhas graves.
        Tenta corrigir problemas menores automaticamente (por ex. criando dirs).
        """
        with self._state.lock:
            errors = []
            # validate paths
            paths = self._state.data.setdefault("paths", {})
            must_have = ["install_root", "build_root", "cache_dir", "repo_dir", "toolchain_dir", "log_dir"]
            for k in must_have:
                p = Path(paths.get(k, ""))
                if not p:
                    # set default
                    paths.setdefault(k, f"/var/lib/pkgtool/{k}")
                    p = Path(paths[k])
                try:
                    p.mkdir(parents=True, exist_ok=True)
                    # permissões básicas
                    _safe_chmod(p, 0o755)
                except Exception as e:
                    msg = f"Não foi possível criar/garantir path {p}: {e}"
                    logger.warning(msg)
                    errors.append(msg)
            # network mirrors validation
            nets = self._state.data.setdefault("network", {})
            mirrors = nets.get("mirrors", [])
            valid_mirrors: List[MirrorType] = []
            if isinstance(mirrors, list):
                for m in mirrors:
                    try:
                        mm = _validate_mirror_entry(m)
                        valid_mirrors.append(mm)
                    except Exception as e:
                        msg = f"Mirror inválido {m}: {e}"
                        logger.warning(msg)
                        if strict:
                            errors.append(msg)
            nets["mirrors"] = valid_mirrors
            # security
            sec = self._state.data.setdefault("security", {})
            if sec.get("verify_signatures", False):
                keyring = Path(sec.get("keyring", ""))
                if not keyring.exists():
                    msg = f"Keyring não encontrado em {keyring}"
                    logger.warning(msg)
                    if strict:
                        errors.append(msg)
            # logging
            lg = self._state.data.setdefault("logging", {})
            level = lg.get("level", "INFO").upper()
            if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                msg = f"Nível de log inválido '{level}', usando 'INFO'"
                logger.warning(msg)
                lg["level"] = "INFO"
            # numeric bounds
            b = self._state.data.setdefault("build", {})
            jobs = int(b.get("jobs", 1) or 1)
            if jobs < 1:
                jobs = 1
            if jobs > os.cpu_count() * 4:
                jobs = os.cpu_count() or 4
            b["jobs"] = jobs
            # finalize
            if errors:
                if strict:
                    raise ConfigError("Erros de validação: " + "; ".join(errors))
                else:
                    logger.warning("Validação gerou warnings: %s", errors)

    # --- hooks ---
    def register_change_hook(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        with self._state.lock:
            if fn not in self._state.hooks:
                self._state.hooks.append(fn)

    def unregister_change_hook(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        with self._state.lock:
            if fn in self._state.hooks:
                self._state.hooks.remove(fn)

    def _call_hooks(self) -> None:
        hooks_copy = list(self._state.hooks)
        data_snapshot = _deep_copy(self._state.data)
        for fn in hooks_copy:
            try:
                fn(data_snapshot)
            except Exception:
                logger.exception("Hook de config falhou")

    # --- utilitários ---
    def ensure_paths_exist(self) -> None:
        with self._state.lock:
            paths = self._state.data.get("paths", {})
            for name, pstr in paths.items():
                try:
                    p = Path(pstr)
                    p.mkdir(parents=True, exist_ok=True)
                    _safe_chmod(p, 0o755)
                except Exception as e:
                    logger.warning("Falha ao criar path %s (%s): %s", name, pstr, e)

    def get_build_env(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Gera um dicionário de environment variables recomendado para subprocessos de build
        (CFLAGS, LDFLAGS, PATH etc).
        """
        with self._state.lock:
            env = dict(os.environ)  # start from current environment
            build = self._state.data.get("build", {})
            paths = self._state.data.get("paths", {})
            default_cflags = build.get("default_cflags", "")
            jobs = str(build.get("jobs", 1))
            toolchain_dir = paths.get("toolchain_dir")
            if default_cflags:
                env["CFLAGS"] = env.get("CFLAGS", "") + " " + default_cflags
            env["PKGTOOL_JOBS"] = env.get("PKGTOOL_JOBS", jobs)
            if toolchain_dir:
                env["PATH"] = str(toolchain_dir) + os.pathsep + env.get("PATH", "")
            sysroot = build.get("sysroot")
            if sysroot:
                env["SYSROOT"] = str(sysroot)
            if extra:
                env.update({k: str(v) for k, v in extra.items()})
            return env

    def list_mirrors(self) -> List[MirrorType]:
        with self._state.lock:
            nets = self._state.data.setdefault("network", {})
            return list(nets.get("mirrors", []))

    def add_mirror(self, mirror: MirrorType, persist: bool = False) -> None:
        with self._state.lock:
            nets = self._state.data.setdefault("network", {})
            mirrors = nets.setdefault("mirrors", [])
            mm = _validate_mirror_entry(mirror)
            # avoid duplicates by name or url
            for existing in mirrors:
                if existing.get("name") == mm.get("name") or existing.get("url") == mm.get("url"):
                    raise ConfigError("Mirror com mesmo nome ou URL já existe.")
            mirrors.append(mm)
            # sort by priority desc
            mirrors.sort(key=lambda x: int(x.get("priority", 0)), reverse=True)
            logger.info("Mirror '%s' adicionado.", mm.get("name"))
            self._call_hooks()
            if persist:
                self.save()

    def remove_mirror(self, name_or_url: str, persist: bool = False) -> None:
        with self._state.lock:
            nets = self._state.data.setdefault("network", {})
            mirrors = nets.setdefault("mirrors", [])
            new = [m for m in mirrors if not (m.get("name") == name_or_url or m.get("url") == name_or_url)]
            if len(new) == len(mirrors):
                raise ConfigError("Mirror não encontrado com esse nome ou url.")
            nets["mirrors"] = new
            logger.info("Mirror removido: %s", name_or_url)
            self._call_hooks()
            if persist:
                self.save()

# ---------------- helper functions ----------------

def _default_config_dict() -> Dict[str, Any]:
    # defaults coerentes
    return {
        "paths": {
            "install_root": "/usr/local",
            "build_root": "/var/lib/pkgtool/build",
            "cache_dir": "/var/cache/pkgtool",
            "repo_dir": "/var/lib/pkgtool/repo",
            "toolchain_dir": "/opt/pkgtool/toolchains",
            "log_dir": "/var/log/pkgtool",
        },
        "network": {
            "mirrors": [],
            "timeout": 30,
            "max_retries": 3,
        },
        "security": {
            "keyring": "/etc/pkgtool/keys/pubring.gpg",
            "verify_signatures": True,
            "allow_unsigned": False,
        },
        "build": {
            "default_cflags": "-O2 -pipe",
            "jobs": 1,
            "bootstrap": True,
            "sysroot": "",
        },
        "logging": {
            "level": "INFO",
            "logfile": "/var/log/pkgtool/pkgtool.log",
            "rotate": True,
            "max_size_mb": 50,
        },
        "profiles": {}
    }

def _deep_merge_dict(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge b into a recursively returning a (does not modify original a argument)."""
    result = _deep_copy(a)
    for k, v in b.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge_dict(result[k], v)
        else:
            result[k] = _deep_copy(v)
    return result

def _deep_copy(obj: Any) -> Any:
    return json.loads(json.dumps(obj)) if not isinstance(obj, (dict, list)) else _dc(obj)

def _dc(o):
    if isinstance(o, dict):
        return {k: _dc(v) for k, v in o.items()}
    elif isinstance(o, list):
        return [_dc(i) for i in o]
    else:
        return o

def _validate_mirror_entry(m: Any) -> MirrorType:
    if not isinstance(m, dict):
        raise ConfigError("Mirror deve ser um dicionário.")
    name = m.get("name")
    url = m.get("url")
    typ = (m.get("type") or "http").lower()
    priority = int(m.get("priority", 0) or 0)
    if not name or not isinstance(name, str):
        raise ConfigError("Mirror precisa de 'name' string.")
    if not url or not isinstance(url, str):
        raise ConfigError("Mirror precisa de 'url' string.")
    if typ not in ("http", "https", "git", "ssh"):
        # aceitar 'https' e mapear para http tipo
        if typ in ("https",):
            typ = "http"
        else:
            # permitir git urls começando com git+
            if url.startswith("git+") or url.startswith("git://") or url.endswith(".git"):
                typ = "git"
            else:
                raise ConfigError("Mirror 'type' inválido (esperado http|git|ssh|https).")
    # normalize git urls that prepend git+
    if url.startswith("git+"):
        url = url[len("git+"):]
    return {"name": name, "type": typ, "url": url, "priority": priority}

def _safe_chmod(p: Path, mode: int) -> None:
    try:
        p.chmod(mode)
    except Exception:
        # se não puder mudar permissões, apenas log
        logger.debug("Não foi possível ajustar permissões de %s para %o", str(p), mode)

# ----------------- CLI -----------------

def _cli_build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pkgtool-config", description="CLI de configuração do pkgtool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # show
    p_show = sub.add_parser("show", help="Exibe a config atual (formato JSON)")
    p_show.add_argument("--path", "-p", help="Caminho do arquivo de config para carregar (opcional)")

    # set
    p_set = sub.add_parser("set", help="Define uma chave pontuada na config (ex: paths.install_root)")
    p_set.add_argument("key", help="Chave pontuada")
    p_set.add_argument("value", help="Valor (JSON literal ou string)")
    p_set.add_argument("--persist", action="store_true", help="Salvar após setar")
    p_set.add_argument("--path", "-p", help="Arquivo de config para carregar/salvar")

    # save
    p_save = sub.add_parser("save", help="Salva a config atual em disco")
    p_save.add_argument("--path", "-p", help="Destino do arquivo de config (opcional)")
    p_save.add_argument("--format", "-f", choices=["toml", "json"], help="Forçar formato")

    # apply-profile
    p_profile = sub.add_parser("apply-profile", help="Aplica um perfil configurado")
    p_profile.add_argument("profile", help="Nome do perfil")
    p_profile.add_argument("--persist", action="store_true", help="Persistir mudanças")

    # mirrors: list/add/remove
    p_list = sub.add_parser("list-mirrors", help="Lista mirrors configurados")
    p_list.add_argument("--path", "-p", help="Arquivo de configuração (opcional)")

    p_add = sub.add_parser("add-mirror", help="Adiciona um mirror")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--url", required=True)
    p_add.add_argument("--type", choices=["http", "https", "git", "ssh"], default="http")
    p_add.add_argument("--priority", type=int, default=0)
    p_add.add_argument("--persist", action="store_true")
    p_add.add_argument("--path", "-p", help="Arquivo de config (opcional)")

    p_rm = sub.add_parser("remove-mirror", help="Remove um mirror por nome ou url")
    p_rm.add_argument("name_or_url", help="Nome ou URL do mirror")
    p_rm.add_argument("--persist", action="store_true")
    p_rm.add_argument("--path", "-p", help="Arquivo de config (opcional)")

    # write-sample
    p_sample = sub.add_parser("write-sample", help="Escreve config.sample.toml no repo (Pkgtool/pkgtool1.0/)")
    p_sample.add_argument("--out", help="Local de saída (path para config.sample.toml)")

    # init (cria diretórios)
    p_init = sub.add_parser("init", help="Cria diretórios base (paths) conforme a config")
    p_init.add_argument("--path", "-p", help="Arquivo de config a usar (opcional)")
    p_init.add_argument("--persist", action="store_true", help="Salvar após init")

    return parser

def cli_main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _cli_build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if getattr(args, "path", None):
            cfg = load_config_from_path_or_default(args.path)
        else:
            cfg = load_config_from_path_or_default(None)
        # map commands
        if args.cmd == "show":
            # print JSON to stdout
            print(json.dumps(cfg._state.data, indent=2, ensure_ascii=False))
            return 0
        elif args.cmd == "set":
            # try to parse value as JSON literal
            try:
                val = json.loads(args.value)
            except Exception:
                val = args.value
            cfg.set(args.key, val, persist=bool(args.persist))
            if args.persist:
                print("Salvo.")
            return 0
        elif args.cmd == "save":
            cfg.save(path=args.path, fmt=args.format)
            print(f"Config salva em {cfg._state.source_path} (formato={cfg._state.format})")
            return 0
        elif args.cmd == "apply-profile":
            cfg.apply_profile(args.profile, persist=bool(args.persist))
            if args.persist:
                print("Perfil aplicado e persistido.")
            else:
                print("Perfil aplicado em memória.")
            return 0
        elif args.cmd == "list-mirrors":
            for m in cfg.list_mirrors():
                print(f"- {m.get('name')} ({m.get('type')}) {m.get('url')} [priority={m.get('priority')}]")
            return 0
        elif args.cmd == "add-mirror":
            mirror = {"name": args.name, "url": args.url, "type": args.type, "priority": args.priority}
            cfg.add_mirror(mirror, persist=bool(args.persist))
            print(f"Mirror '{args.name}' adicionado.")
            return 0
        elif args.cmd == "remove-mirror":
            cfg.remove_mirror(args.name_or_url, persist=bool(args.persist))
            print("Mirror removido.")
            return 0
        elif args.cmd == "write-sample":
            out = args.out or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "config.sample.toml")
            outp = Path(out)
            outp.parent.mkdir(parents=True, exist_ok=True)
            outp.write_text(DEFAULT_SAMPLE_TOML, encoding="utf-8")
            print(f"Wrote sample config to {outp}")
            return 0
        elif args.cmd == "init":
            cfg.ensure_paths_exist()
            if args.persist:
                cfg.save()
                print("Diretórios criados e config salva.")
            else:
                print("Diretórios criados (config não persistida).")
            return 0
        else:
            parser.print_help()
            return 2
    except ConfigError as e:
        print(f"ConfigError: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        logger.exception("Erro inesperado no CLI")
        print(f"Erro inesperado: {e}", file=sys.stderr)
        return 4

def load_config_from_path_or_default(path: Optional[str]) -> Config:
    if path:
        return Config.load(path=path)
    return Config.load()

# allow import like: from modules.config import cfg
# create a global cfg loaded from default locations (non-strict, fallback sample)
try:
    cfg = Config.load()
except Exception as e:
    logger.warning("Falha ao carregar config default: %s. Usando defaults em memória.", e)
    cfg = Config()
    cfg._state.data = _default_config_dict()

# if module executed as script, run CLI
if __name__ == "__main__":
    sys.exit(cli_main())
