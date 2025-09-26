
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.py
Config loader/validator for pkgtool.

Responsabilidades:
- Carregar arquivo YAML de configuração (path por PKGTOOL_CONF, --config ou padrão).
- Mesclar com valores padrão.
- Validar tipos básicos do schema.
- Expandir variáveis de ambiente (~ e ${VAR}).
- Garantir criação automática de diretórios essenciais (workdir, builddir, cachedir, destdir, repo_path, toolchains_dir).
- Fornecer acesso conveniente via Config.get(...) e propriedades.
- Salvar config (write_atomic) se necessário.

Uso:
    cfg = Config.load('/etc/pkgtool/config.yaml')        # carrega do arquivo
    cfg = Config.load()                                  # usa env PKGTOOL_CONF ou /etc/pkgtool/config.yaml
    cfg.get('global', 'builddir')                        # retorna valor
"""

from __future__ import annotations
import os
import stat
import yaml
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from pathlib import Path
import tempfile
import json

# -----------------------
# Defaults
# -----------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    'global': {
        # defaults chosen to match your requirement (repo local default)
        'workdir': '/var/tmp/pkgtool/work',
        'builddir': '/var/tmp/pkgtool/build',
        'cachedir': '/var/cache/pkgtool',
        'destdir': '/var/tmp/pkgtool/dest',
        'repo_path': '/usr/ports/pkgtool',   # default repo path as requested
        'toolchains_dir': '/opt/pkgtool/toolchains',
        'allow_multiple_versions': True,
        'network_isolation': True,
        'sandbox_backend': 'bwrap',  # bwrap or unshare
        'parallel_jobs': 4,
    },
    'fetch': {
        'http_timeout': 60,
        'retry': 3,
        'git_depth': 1,
    },
    'logging': {
        'level': 'INFO',
        'logs_dir': '/var/log/pkgtool',
    },
    'notifications': {
        'enabled': True,
        'method': 'notify-send',
    },
    'resolver': {
        'conflict_policy': 'allow-multiple'  # allow-multiple | prefer-upstream | fail
    },
    'security': {
        'validate_checksums': True,
        'allow_unverified_sources': False,
    }
}

# -----------------------
# Exceptions
# -----------------------
class ConfigError(Exception):
    pass

# -----------------------
# Utilities
# -----------------------
def _expand_path(val: str) -> str:
    """Expand ~ and environment variables in path-like strings."""
    if not isinstance(val, str):
        return val
    return os.path.expanduser(os.path.expandvars(val))

def _deep_update(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively update base with override and return new dict.
    Similar to a deep merge: dict values are merged, non-dict override replaces.
    """
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_update(result[k], v)
        else:
            result[k] = v
    return result

def _write_atomic(path: Path, data: str, mode: int = 0o644) -> None:
    tmp = Path(tempfile.mkstemp(dir=str(path.parent))[1])
    tmp.write_text(data, encoding='utf-8')
    tmp.chmod(mode)
    tmp.replace(path)

def _ensure_dir(p: Path, mode: int = 0o755) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        p.chmod(mode)
    except Exception:
        # Not fatal if chmod fails (e.g., non-root)
        pass

# -----------------------
# Config dataclass
# -----------------------
@dataclass
class Config:
    raw: Dict[str, Any] = field(default_factory=dict)
    source_path: Optional[Path] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> 'Config':
        """
        Load configuration.
        Resolution order:
          1. explicit `path` argument,
          2. environment variable PKGTOOL_CONF,
          3. /etc/pkgtool/config.yaml,
          4. ~/.config/pkgtool/config.yaml (if exists),
          5. fallback to DEFAULT_CONFIG
        """
        cfg_path = None
        if path:
            cfg_path = Path(path)
        else:
            envp = os.environ.get('PKGTOOL_CONF')
            if envp:
                cfg_path = Path(envp)
            elif Path('/etc/pkgtool/config.yaml').exists():
                cfg_path = Path('/etc/pkgtool/config.yaml')
            elif Path.home().joinpath('.config/pkgtool/config.yaml').exists():
                cfg_path = Path.home().joinpath('.config/pkgtool/config.yaml')
            else:
                cfg_path = None

        # Start from defaults
        base = DEFAULT_CONFIG.copy()

        # If there is a file, load and deep-merge
        if cfg_path and cfg_path.exists():
            try:
                raw_user = yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
                base = _deep_update(base, raw_user)
            except Exception as e:
                raise ConfigError(f"failed to parse config file {cfg_path}: {e}")
            cfg = cls(raw=base, source_path=cfg_path)
        else:
            cfg = cls(raw=base, source_path=None)

        # Normalize paths and ensure directories exist
        cfg._normalize_and_create_dirs()
        return cfg

    def _normalize_and_create_dirs(self) -> None:
        """
        Expand env vars/tilde in configured path entries and ensure directories exist.
        Creates: workdir, builddir, cachedir, destdir, repo_path, toolchains_dir, logs_dir
        """
        g = self.raw.setdefault('global', {})
        # keys of interest
        path_keys = ['workdir', 'builddir', 'cachedir', 'destdir', 'repo_path', 'toolchains_dir']
        for k in path_keys:
            if k in g and g[k] is not None:
                g[k] = _expand_path(str(g[k]))
            else:
                # ensure fallback present
                g[k] = _expand_path(str(DEFAULT_CONFIG['global'][k]))

        # logging dir
        logs = self.raw.setdefault('logging', {})
        logs_dir = logs.get('logs_dir', DEFAULT_CONFIG['logging']['logs_dir'])
        logs['logs_dir'] = _expand_path(str(logs_dir))

        # ensure directories exist with safe permissions
        for d in [g['workdir'], g['builddir'], g['cachedir'], g['destdir'], g['repo_path'], g['toolchains_dir'], logs['logs_dir']]:
            try:
                _ensure_dir(Path(d), mode=0o755)
            except PermissionError:
                # If user cannot create, we still keep the path; some operations will fail later with clearer errors.
                pass

        # sanity: parallel_jobs must be int >=1
        pj = g.get('parallel_jobs', DEFAULT_CONFIG['global']['parallel_jobs'])
        try:
            pj = int(pj)
            if pj < 1:
                pj = DEFAULT_CONFIG['global']['parallel_jobs']
        except Exception:
            pj = DEFAULT_CONFIG['global']['parallel_jobs']
        g['parallel_jobs'] = pj

        # coerce booleans
        for bkey in ('allow_multiple_versions', 'network_isolation'):
            g[bkey] = bool(g.get(bkey, DEFAULT_CONFIG['global'][bkey]))

        # fetch defaults
        f = self.raw.setdefault('fetch', {})
        f.setdefault('http_timeout', DEFAULT_CONFIG['fetch']['http_timeout'])
        f.setdefault('retry', DEFAULT_CONFIG['fetch']['retry'])
        f.setdefault('git_depth', DEFAULT_CONFIG['fetch']['git_depth'])

        # resolver policy validation
        resolver = self.raw.setdefault('resolver', {})
        policy = resolver.get('conflict_policy', DEFAULT_CONFIG['resolver']['conflict_policy'])
        if policy not in ('allow-multiple', 'prefer-upstream', 'fail'):
            resolver['conflict_policy'] = DEFAULT_CONFIG['resolver']['conflict_policy']

    # Convenience getters
    def get(self, *keys, default: Any = None) -> Any:
        """
        cfg.get('global', 'builddir') or cfg.get('fetch','http_timeout')
        """
        node = self.raw
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    @property
    def workdir(self) -> str:
        return self.get('global', 'workdir')

    @property
    def builddir(self) -> str:
        return self.get('global', 'builddir')

    @property
    def cachedir(self) -> str:
        return self.get('global', 'cachedir')

    @property
    def destdir(self) -> str:
        return self.get('global', 'destdir')

    @property
    def repo_path(self) -> str:
        return self.get('global', 'repo_path')

    @property
    def toolchains_dir(self) -> str:
        return self.get('global', 'toolchains_dir')

    # Save function for writing generated configs (atomic)
    def save(self, target: Optional[str] = None) -> None:
        target_path = Path(target) if target else (self.source_path if self.source_path else Path.home().joinpath('.config/pkgtool/config.yaml'))
        target_path.parent.mkdir(parents=True, exist_ok=True)
        data = yaml.safe_dump(self.raw, default_flow_style=False, sort_keys=False)
        _write_atomic(target_path, data, mode=0o644)
        # ensure dirs exist after write
        self._normalize_and_create_dirs()

    # Debug pretty print (json)
    def pretty(self) -> str:
        return json.dumps(self.raw, indent=2, ensure_ascii=False)

# if run as script, print resolved config
if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(prog='config.py', description='Load and print pkgtool config')
    p.add_argument('--config', '-c', help='config file path (yaml)')
    p.add_argument('--save-as', '-s', help='save merged config to path')
    args = p.parse_args()

    cfg = Config.load(args.config)
    print(cfg.pretty())
    if args.save_as:
        cfg.save(args.save_as)
        print(f"Saved merged config to {args.save_as}")
