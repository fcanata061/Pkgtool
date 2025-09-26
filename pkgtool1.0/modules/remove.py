#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
remove.py
Remoção segura de pacotes.

Funcionalidades:
- Remover pacotes do sistema
- Executar hooks de pré e pós-remove
- Limpar dependências órfãs
- Manter banco installed_db.yaml
"""

from __future__ import annotations
import os
import shutil
import yaml
import subprocess
from pathlib import Path
from typing import Dict, List
from utils import log_info, log_warn, log_success, log_error, safe_run, ensure_dir
from config import Config
from deps import DependencyResolver, DependencyError
from meta import MetaIndex

class RemoveError(Exception):
    pass

class RemoveManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.installdb = Path(cfg.pkgdir) / "installed_db.yaml"
        self.repo_index = MetaIndex(str(Path("/usr/ports/pkgtool")))

    def _load_db(self) -> Dict[str, Dict]:
        if not self.installdb.exists():
            return {}
        return yaml.safe_load(self.installdb.read_text(encoding="utf-8")) or {}

    def _save_db(self, db: Dict[str, Dict]) -> None:
        self.installdb.write_text(yaml.safe_dump(db, sort_keys=False), encoding="utf-8")

    def remove(self, name: str) -> None:
        """
        Remove pacote e executa hooks.
        """
        db = self._load_db()
        if name not in db:
            raise RemoveError(f"Pacote {name} não está instalado")

        pkginfo = db[name]
        path = Path(pkginfo["install_path"])

        # Executa hook pré-remove
        self._run_hooks(path, "pre-remove")

        log_info(f"Removendo arquivos do pacote {name}")
        try:
            shutil.rmtree(path)
        except Exception as e:
            log_warn(f"Erro ao remover {path}: {e}")

        # Remove do banco
        del db[name]
        self._save_db(db)

        # Executa hook pós-remove
        self._run_hooks(path, "post-remove")

        log_success(f"Pacote {name} removido com sucesso")

        # Limpa dependências órfãs
        self.clean_orphans()

    def clean_orphans(self) -> None:
        """
        Remove dependências que não são usadas por mais nenhum pacote.
        """
        db = self._load_db()
        used: set[str] = set()

        # Identifica dependências usadas
        self.repo_index.load()
        for pkgname, meta in db.items():
            mpkg = self.repo_index.find(pkgname, meta.get("version"))
            if mpkg:
                for dep in mpkg.depends:
                    used.add(dep.split("=")[0])

        # Remove pacotes órfãos
        for pkgname in list(db.keys()):
            if pkgname not in used:
                log_warn(f"Pacote órfão detectado: {pkgname}")
                self.remove(pkgname)

    def _run_hooks(self, path: Path, stage: str) -> None:
        """
        Executa scripts de hook se existirem.
        """
        hooksdir = path / "hooks"
        if not hooksdir.exists():
            return

        for script in hooksdir.glob(f"{stage}*"):
            if script.is_file() and os.access(script, os.X_OK):
                log_info(f"Executando hook {stage}: {script.name}")
                try:
                    safe_run([str(script)])
                except Exception as e:
                    log_warn(f"Hook {script} falhou: {e}")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    mgr = RemoveManager(cfg)
    try:
        mgr.remove("exemplo")
    except RemoveError as e:
        log_error(str(e))
