#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
meta.py
Carregamento e validação dos arquivos de metadados (meta.yaml) dos pacotes.

Responsabilidades:
- Procurar recursivamente em repo_path (/usr/ports/pkgtool por padrão) por meta.yaml ou meta.
- Carregar YAML e validar campos obrigatórios.
- Suporte a múltiplas versões do mesmo pacote.
- Suporte a hooks (inline e scripts) em todas as fases, incluindo pre_remove/post_remove.
- Expor classes MetaPackage e MetaIndex para consulta e manipulação.
"""

from __future__ import annotations
import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from utils import log_info, log_warn, log_error

# -----------------------
# Exceptions
# -----------------------
class MetaError(Exception):
    pass

# -----------------------
# MetaPackage
# -----------------------
class MetaPackage:
    """
    Representa os metadados de um pacote (meta.yaml).
    """

    def __init__(self, path: Path, data: Dict[str, Any]):
        self.path = path
        self.data = data
        self.name: str = data.get("name")
        self.version: str = str(data.get("version"))
        self.release: str = str(data.get("release", "1"))
        self.build_system: str = data.get("build", {}).get("system", "autotools")
        self.source: List[Dict[str, Any]] = data.get("source", [])
        self.dependencies: Dict[str, List[str]] = data.get("dependencies", {})
        self.hooks: Dict[str, Dict[str, List[str]]] = data.get("hooks", {})

        self._validate()

    def _validate(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise MetaError(f"Invalid meta at {self.path}: missing 'name'")
        if not self.version:
            raise MetaError(f"Invalid meta at {self.path}: missing 'version'")
        if not isinstance(self.source, list):
            raise MetaError(f"Invalid meta at {self.path}: 'source' must be a list")
        # normalize hooks
        valid_hooks = {
            "pre_fetch", "post_fetch",
            "pre_patch", "post_patch",
            "pre_build", "post_build",
            "pre_package", "post_package",
            "pre_install", "post_install",
            "pre_remove", "post_remove",
        }
        hooks = {}
        for hk, val in self.hooks.items():
            if hk not in valid_hooks:
                log_warn(f"{self.name}-{self.version}: invalid hook {hk} ignored")
                continue
            if not isinstance(val, dict):
                raise MetaError(f"{self.name}-{self.version}: hook {hk} must be a dict")
            hooks[hk] = {
                "inline": val.get("inline", []) or [],
                "scripts": val.get("scripts", []) or [],
            }
        self.hooks = hooks

    def get_dependencies(self, kind: str = "build") -> List[str]:
        """
        Retorna lista de dependências de um tipo: build, runtime, test
        """
        return self.dependencies.get(kind, [])

    def get_sources(self) -> List[Dict[str, Any]]:
        """
        Retorna lista de fontes de código (urls, git, etc.)
        """
        return self.source

    def __repr__(self) -> str:
        return f"<MetaPackage {self.name}-{self.version} (path={self.path})>"

# -----------------------
# MetaIndex
# -----------------------
class MetaIndex:
    """
    Índice de todos os pacotes no repo local.
    Suporta múltiplas versões do mesmo pacote.
    """

    def __init__(self, repo_path: str = "/usr/ports/pkgtool"):
        self.repo_path = Path(repo_path)
        self.packages: Dict[str, List[MetaPackage]] = {}

    def load(self) -> None:
        """
        Escaneia repo_path recursivamente e carrega todos os meta.yaml/meta
        """
        if not self.repo_path.exists():
            log_warn(f"Repo path {self.repo_path} does not exist")
            return

        for meta_file in self.repo_path.rglob("meta*"):
            if meta_file.is_file() and meta_file.name in ("meta", "meta.yaml"):
                try:
                    data = yaml.safe_load(meta_file.read_text(encoding="utf-8")) or {}
                    pkg = MetaPackage(meta_file, data)
                    self._add_package(pkg)
                    log_info(f"Loaded meta {pkg.name}-{pkg.version} from {meta_file}")
                except Exception as e:
                    log_error(f"Failed to load meta {meta_file}: {e}")

    def _add_package(self, pkg: MetaPackage) -> None:
        versions = self.packages.setdefault(pkg.name, [])
        versions.append(pkg)
        # manter ordenado por versão (simples: string, depois vamos sofisticar)
        versions.sort(key=lambda p: p.version)

    def find(self, name: str, version: Optional[str] = None) -> Optional[MetaPackage]:
        """
        Busca pacote por nome (e opcionalmente versão).
        Se não passar versão, retorna a mais nova.
        """
        versions = self.packages.get(name)
        if not versions:
            return None
        if version:
            for p in versions:
                if p.version == version:
                    return p
            return None
        return versions[-1]  # mais nova

    def all_packages(self) -> List[MetaPackage]:
        result = []
        for vs in self.packages.values():
            result.extend(vs)
        return result

    def list_versions(self, name: str) -> List[str]:
        return [p.version for p in self.packages.get(name, [])]

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    idx = MetaIndex("/usr/ports/pkgtool")
    idx.load()
    for pkg in idx.all_packages():
        print(f"- {pkg.name}-{pkg.version} (build={pkg.build_system}, deps={pkg.dependencies})")
