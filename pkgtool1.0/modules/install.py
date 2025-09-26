#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install.py
Responsável por instalar pacotes no sistema.

Funcionalidades:
- Extrai pacote .tar.xz em /usr usando fakeroot
- Executa hooks pre_install/post_install
- Atualiza banco local de pacotes instalados (installed_db.yaml)
- Suporta dry-run (simulação)
"""

from __future__ import annotations
import os
import tarfile
import yaml
from pathlib import Path
from typing import Dict, Any
from utils import log_info, log_warn, log_success, log_error, ensure_dir
from config import Config
from meta import MetaPackage
from patches_and_hooks import PatchHookManager

class InstallError(Exception):
    pass

class Installer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dbfile = Path(cfg.pkgdir) / "installed_db.yaml"
        self.hookmgr = PatchHookManager(cfg)

    def install(self, pkg: MetaPackage, tarball: Path, dry_run: bool = False) -> None:
        """
        Instala um pacote no sistema a partir de um tarball .tar.xz
        """
        log_info(f"Instalando {pkg.name}-{pkg.version} (dry_run={dry_run})")

        # hooks pre_install
        self.hookmgr.run_hooks(pkg, "pre_install", Path(self.cfg.workdir))

        if not dry_run:
            try:
                with tarfile.open(tarball, "r:xz") as tf:
                    tf.extractall(path="/")
                log_success(f"Pacote instalado em /usr: {pkg.name}-{pkg.version}")
            except Exception as e:
                raise InstallError(f"Falha ao instalar {tarball}: {e}")
        else:
            log_warn("Dry-run: instalação simulada, nada foi escrito")

        # hooks post_install
        self.hookmgr.run_hooks(pkg, "post_install", Path(self.cfg.workdir))

        # atualizar DB
        if not dry_run:
            self._update_db(pkg, tarball)

    def _update_db(self, pkg: MetaPackage, tarball: Path) -> None:
        """
        Atualiza banco de dados de pacotes instalados.
        """
        db: Dict[str, Any] = {}
        if self.dbfile.exists():
            try:
                db = yaml.safe_load(self.dbfile.read_text(encoding="utf-8")) or {}
            except Exception:
                log_warn("DB corrompido, recriando")
                db = {}

        db.setdefault(pkg.name, {})
        db[pkg.name][pkg.version] = {
            "release": pkg.release,
            "tarball": str(tarball),
        }

        self.dbfile.write_text(yaml.safe_dump(db), encoding="utf-8")
        log_info(f"DB atualizado: {self.dbfile}")

    def list_installed(self) -> Dict[str, Any]:
        """
        Retorna dicionário com pacotes instalados.
        """
        if not self.dbfile.exists():
            return {}
        return yaml.safe_load(self.dbfile.read_text(encoding="utf-8")) or {}

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    from meta import MetaIndex
    cfg = Config.load()
    idx = MetaIndex(cfg.repo_path)
    idx.load()
    pkgs = idx.all_packages()
    if pkgs:
        pkg = pkgs[0]
        tarball = Path(cfg.pkgdir) / f"{pkg.name}-{pkg.version}-{pkg.release}.tar.xz"
        inst = Installer(cfg)
        inst.install(pkg, tarball, dry_run=True)
        print("Pacotes instalados:", inst.list_installed())
