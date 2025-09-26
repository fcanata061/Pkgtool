#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gitrepo.py
Sincronização do repositório de pacotes via Git.

Funcionalidades:
- Clonar repositório de metas em /usr/ports/pkgtool
- Atualizar via git pull
- Listar pacotes disponíveis
"""

from __future__ import annotations
import os
import subprocess
import shutil
from pathlib import Path
from typing import List
from utils import log_info, log_warn, log_success, log_error, safe_run, ensure_dir
from config import Config

class GitRepoError(Exception):
    pass

class GitRepoManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.repo_path = Path("/usr/ports/pkgtool")
        ensure_dir(self.repo_path)

    def clone_or_update(self, url: str, branch: str = "main") -> None:
        """
        Clona ou atualiza o repositório de metas.
        """
        if (self.repo_path / ".git").exists():
            log_info(f"Atualizando repositório {self.repo_path}")
            try:
                safe_run(["git", "pull"], cwd=str(self.repo_path))
                log_success("Repositório atualizado com sucesso")
            except Exception as e:
                raise GitRepoError(f"Falha ao atualizar: {e}")
        else:
            log_info(f"Clonando repositório {url} em {self.repo_path}")
            try:
                if self.repo_path.exists() and any(self.repo_path.iterdir()):
                    shutil.rmtree(self.repo_path)
                ensure_dir(self.repo_path.parent)
                safe_run(["git", "clone", "-b", branch, url, str(self.repo_path)])
                log_success("Repositório clonado com sucesso")
            except Exception as e:
                raise GitRepoError(f"Falha ao clonar: {e}")

    def list_packages(self) -> List[str]:
        """
        Lista pacotes disponíveis no repositório (pastas com meta.yaml).
        """
        pkgs: List[str] = []
        for path in self.repo_path.rglob("meta.yaml"):
            pkgs.append(path.parent.name)
        return sorted(pkgs)

    def package_path(self, name: str) -> Path:
        """
        Retorna caminho da pasta de um pacote pelo nome.
        """
        candidates = list(self.repo_path.rglob(f"{name}/meta.yaml"))
        if not candidates:
            raise GitRepoError(f"Pacote {name} não encontrado no repositório")
        return candidates[0].parent

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    repo = GitRepoManager(cfg)
    try:
        repo.clone_or_update("https://github.com/exemplo/pkgtool-repo.git")
        print("Pacotes disponíveis:", repo.list_packages())
    except GitRepoError as e:
        log_error(str(e))
