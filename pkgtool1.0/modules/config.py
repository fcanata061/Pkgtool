# pkgtool/config.py
"""
Config manager do pkgtool
- Lê YAML de configuração
- Expande variáveis
- Merge entre defaults e overrides
- Retorna dict pronto e ambiente montado
"""

from __future__ import annotations
import os
import sys
import yaml
from pathlib import Path
from typing import Dict, Any

# paths padrão
SYSTEM_CONFIG = Path("/etc/pkgtool/config.yaml")
USER_CONFIG = Path.home() / ".config" / "pkgtool" / "config.yaml"

# cache em memória
_config_cache: Dict[str, Any] | None = None

# defaults
DEFAULT_CONFIG: Dict[str, Any] = {
    "toolchain_dir": "/opt/pkgtool/toolchains",
    "ports_dir": "/usr/ports/pkgtool",
    "build_root": "/var/tmp/pkgtool/builds",
    "log_dir": "/var/log/pkgtool",
    "package_store": "/var/pkgtool/packages",
    "cache_dir": "/var/cache/pkgtool",
    "db_path": "/var/lib/pkgtool/pkgtool.db",
    "default_jobs": 4,
    "sandbox": True,
    "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    },
}


def _expand_vars(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Expande ${VAR} usando os.environ e valores do próprio cfg"""
    def expand_val(val: Any) -> Any:
        if isinstance(val, str):
            return os.path.expandvars(
                val.replace("${toolchain_dir}", cfg.get("toolchain_dir", ""))
                   .replace("${ports_dir}", cfg.get("ports_dir", ""))
                   .replace("${build_root}", cfg.get("build_root", ""))
                   .replace("${log_dir}", cfg.get("log_dir", ""))
                   .replace("${package_store}", cfg.get("package_store", ""))
                   .replace("${cache_dir}", cfg.get("cache_dir", ""))
            )
        elif isinstance(val, dict):
            return {k: expand_val(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [expand_val(v) for v in val]
        return val

    return {k: expand_val(v) for k, v in cfg.items()}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """merge recursivo de configs"""
    merged = dict(base)
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_config(force: bool = False) -> Dict[str, Any]:
    """Carrega configuração (com cache)"""
    global _config_cache
    if _config_cache is not None and not force:
        return _config_cache

    cfg = dict(DEFAULT_CONFIG)

    # carrega system e user
    for path in (SYSTEM_CONFIG, USER_CONFIG):
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text()) or {}
                if not isinstance(data, dict):
                    print(f"[WARN] Ignorando config inválida em {path}", file=sys.stderr)
                    continue
                cfg = _merge(cfg, data)
            except Exception as e:
                print(f"[WARN] Falha lendo config {path}: {e}", file=sys.stderr)

    cfg = _expand_vars(cfg)

    # cria dirs importantes
    ensure_dirs(cfg)

    _config_cache = cfg
    return cfg


def get_config() -> Dict[str, Any]:
    """retorna config atual"""
    return load_config()


def ensure_dirs(cfg: Dict[str, Any] | None = None):
    """cria diretórios críticos"""
    cfg = cfg or get_config()
    for k in ("toolchain_dir", "ports_dir", "build_root", "log_dir", "package_store", "cache_dir"):
        try:
            Path(cfg[k]).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[WARN] não consegui criar {cfg[k]}: {e}", file=sys.stderr)


def get_env(extra: Dict[str, str] | None = None) -> Dict[str, str]:
    """monta ambiente baseado na config"""
    cfg = get_config()
    env = os.environ.copy()
    for k, v in cfg.get("env", {}).items():
        env[k] = str(v)
    if extra:
        env.update(extra)
    return env
