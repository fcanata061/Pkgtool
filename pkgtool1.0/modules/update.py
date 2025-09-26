#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
Sincronização de pacotes com upstream.

Funcionalidades:
- Baixar/atualizar pacotes de http/https/git/rsync/ftp
- Atualizar todos os pacotes do repositório
- Gerar relatório update_report.yaml
- Notificar via notify-send
"""

from __future__ import annotations
import os
import shutil
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List
from utils import log_info, log_warn, log_success, log_error, safe_run, ensure_dir
from config import Config
from meta import MetaIndex, MetaPackage

class UpdateError(Exception):
    pass

class UpdateManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.repo_path = Path("/usr/ports/pkgtool")
        self.index = MetaIndex(str(self.repo_path))
        self.reportfile = Path(cfg.logdir) / "update_report.yaml"

    def update_all(self) -> Dict[str, str]:
        """
        Atualiza todos os pacotes definidos no repositório.
        """
        log_info("Atualizando todos os pacotes com upstream...")
        self.index.load()
        updated: Dict[str, str] = {}

        for pkg in self.index.packages.values():
            try:
                if self._update_pkg(pkg):
                    updated[pkg.name] = pkg.version
            except UpdateError as e:
                log_warn(str(e))

        self._write_report(updated)
        if updated:
            self._notify(updated)
        return updated

    def _update_pkg(self, pkg: MetaPackage) -> bool:
        """
        Atualiza um pacote individual de acordo com seu meta.yaml.
        """
        url = pkg.meta.get("source")
        if not url:
            raise UpdateError(f"{pkg.name} não possui campo 'source' no meta")

        log_info(f"Atualizando {pkg.name} de {url}")

        if url.startswith("git://") or url.startswith("https://") and url.endswith(".git"):
            return self._update_git(pkg, url)
        elif url.startswith("rsync://"):
            return self._update_rsync(pkg, url)
        elif url.startswith("ftp://") or url.startswith("http://") or url.startswith("https://"):
            return self._update_http(pkg, url)
        else:
            raise UpdateError(f"Protocolo não suportado em {url}")

    def _update_git(self, pkg: MetaPackage, url: str) -> bool:
        """
        Atualiza pacote via Git.
        """
        path = Path(pkg.path) / "src"
        ensure_dir(path)
        if (path / ".git").exists():
            safe_run(["git", "pull"], cwd=str(path))
        else:
            safe_run(["git", "clone", url, str(path)])
        log_success(f"{pkg.name} atualizado via Git")
        return True

    def _update_rsync(self, pkg: MetaPackage, url: str) -> bool:
        """
        Atualiza pacote via rsync.
        """
        path = Path(pkg.path) / "src"
        ensure_dir(path)
        safe_run(["rsync", "-avz", url, str(path)])
        log_success(f"{pkg.name} atualizado via rsync")
        return True

    def _update_http(self, pkg: MetaPackage, url: str) -> bool:
        """
        Atualiza pacote via http/https/ftp.
        """
        path = Path(pkg.path) / "src"
        ensure_dir(path)
        tarball = path / os.path.basename(url)
        if shutil.which("curl"):
            safe_run(["curl", "-L", "-o", str(tarball), url])
        elif shutil.which("wget"):
            safe_run(["wget", "-O", str(tarball), url])
        else:
            raise UpdateError("Nem curl nem wget disponíveis")
        log_success(f"{pkg.name} baixado de {url}")
        return True

    def _write_report(self, updates: Dict[str, str]) -> None:
        """
        Escreve relatório update_report.yaml.
        """
        self.reportfile.write_text(
            yaml.safe_dump(updates, sort_keys=False, allow_unicode=True),
            encoding="utf-8"
        )
        log_info(f"Relatório de updates salvo em {self.reportfile}")

    def _notify(self, updates: Dict[str, str]) -> None:
        """
        Envia notificação via notify-send.
        """
        msg = f"{len(updates)} pacotes atualizados do upstream"
        try:
            safe_run(["notify-send", "Pkgtool Update", msg])
        except Exception:
            log_warn("Falha ao enviar notificação")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    updater = UpdateManager(cfg)
    updater.update_all()
