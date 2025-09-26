#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remove.py
Responsável por remover pacotes do sistema.

Funcionalidades:
- Executa hooks pre_remove/post_remove
- Remove arquivos listados no tarball
- Atualiza banco de dados installed_db.yaml
- Suporta dry-run (simulação)
- Detecta dependências órfãs
"""

from __future__ import annotations
import os
import tarfile
import yaml
from pathlib import Path
from typing import Dict, Any
from utils import log_info, log_warn, log_success, log_error
from config import Config
from meta import MetaPackage
from patches_and_hooks import PatchHookManager

class RemoveError(Exception):
    pass

class Remover:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dbfile = Path(cfg.pkgdir) / "installed_db.yaml"
        self.hookmgr = PatchHookManager(cfg)

    def remove(self, pkg_name: str, version: str, dry_run: bool = False) -> None:
        """
        Remove pacote instalado do sistema.
        """
        log_info(f"Removendo {pkg_name}-{version} (dry_run={dry_run})")

        db = self._load_db()
        if pkg_name not in db or version not in db[pkg_name]:
            raise RemoveError(f"Pacote {pkg_name}-{version} não está instalado")

        entry = db[pkg_name][version]
        tarball = Path(entry["tarball"])

        # hooks pre_remove
        dummy_pkg = MetaPackage(
            name=pkg_name,
            version=version,
            release=entry.get("release", "1"),
            source=[],
        )
        self.hookmgr.run_hooks(dummy_pkg, "pre_remove", Path(self.cfg.workdir))

        if not dry_run:
            # remover arquivos listados no tarball
            try:
                with tarfile.open(tarball, "r:xz") as tf:
                    for member in tf.getmembers():
                        path = Path("/") / member.name.lstrip("/")
                        if path.exists():
                            try:
                                if path.is_file() or path.is_symlink():
                                    path.unlink(missing_ok=True)
                                elif path.is_dir():
                                    # só remove diretórios se estiverem vazios
                                    try:
                                        path.rmdir()
                                    except OSError:
                                        pass
                            except Exception as e:
                                log_warn(f"Falha ao remover {path}: {e}")
            except Exception as e:
                raise RemoveError(f"Falha ao processar {tarball}: {e}")

            # atualizar DB
            del db[pkg_name][version]
            if not db[pkg_name]:
                del db[pkg_name]
            self._save_db(db)
            log_success(f"Removido: {pkg_name}-{version}")
        else:
            log_warn("Dry-run: remoção simulada, nada foi apagado")

        # hooks post_remove
        self.hookmgr.run_hooks(dummy_pkg, "post_remove", Path(self.cfg.workdir))

        # detectar órfãos
        self._check_orphans(db)

    def _check_orphans(self, db: Dict[str, Any]) -> None:
        """
        Detecta pacotes instalados que não são dependência de nenhum outro.
        """
        all_deps = set()
        for name, versions in db.items():
            for v, entry in versions.items():
                deps = entry.get("depends", [])
                all_deps.update(deps)

        orphans = []
        for name in db:
            if name not in all_deps:
                orphans.append(name)

        if orphans:
            log_warn(f"Possíveis pacotes órfãos: {', '.join(orphans)}")

    def _load_db(self) -> Dict[str, Any]:
        if not self.dbfile.exists():
            return {}
        return yaml.safe_load(self.dbfile.read_text(encoding="utf-8")) or {}

    def _save_db(self, db: Dict[str, Any]) -> None:
        self.dbfile.write_text(yaml.safe_dump(db), encoding="utf-8")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    rm = Remover(cfg)
    try:
        rm.remove("exemplo", "1.0", dry_run=True)
    except RemoveError as e:
        log_error(str(e))
