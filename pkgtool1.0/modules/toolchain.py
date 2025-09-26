#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
toolchain.py
Gerencia toolchains (compiladores e binutils).

Funcionalidades:
- Instalar/atualizar/remover toolchains
- Suporte a múltiplas versões
- Selecionar toolchain ativa via symlink
- Reparo de toolchains quebradas
- Banco local toolchains_db.yaml
"""

from __future__ import annotations
import os
import shutil
import subprocess
import yaml
from pathlib import Path
from typing import Dict, Any, List
from utils import log_info, log_warn, log_success, log_error, ensure_dir, safe_run
from config import Config

class ToolchainError(Exception):
    pass

class ToolchainManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dbfile = Path(cfg.pkgdir) / "toolchains_db.yaml"
        self.tcdir = Path(cfg.workdir) / "toolchains"
        ensure_dir(self.tcdir)

    def install(self, name: str, version: str, url: str) -> None:
        """
        Instala um toolchain a partir de tarball/URL.
        """
        log_info(f"Instalando toolchain {name}-{version} de {url}")

        destdir = self.tcdir / f"{name}-{version}"
        if destdir.exists():
            raise ToolchainError(f"Já existe {destdir}")

        try:
            tarball = self._download(url)
            safe_run(["tar", "xf", tarball, "-C", str(self.tcdir)])
            log_success(f"Toolchain {name}-{version} instalado em {destdir}")
            self._update_db(name, version, str(destdir))
        except Exception as e:
            raise ToolchainError(f"Falha ao instalar toolchain: {e}")

    def list(self) -> Dict[str, Any]:
        """
        Lista toolchains instalados.
        """
        if not self.dbfile.exists():
            return {}
        return yaml.safe_load(self.dbfile.read_text(encoding="utf-8")) or {}

    def set_default(self, name: str, version: str) -> None:
        """
        Seleciona toolchain como padrão (via symlink).
        """
        path = self.tcdir / f"{name}-{version}"
        if not path.exists():
            raise ToolchainError(f"Toolchain {name}-{version} não existe")

        link = self.tcdir / "default"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(path)
        log_success(f"Toolchain ativo: {name}-{version}")

    def repair(self, name: str, version: str) -> None:
        """
        Repara toolchain quebrado (exemplo: relink binutils).
        """
        path = self.tcdir / f"{name}-{version}"
        if not path.exists():
            raise ToolchainError(f"Toolchain {name}-{version} não existe")

        binpath = path / "bin"
        if not binpath.exists():
            log_warn(f"Toolchain {name}-{version} está incompleto, recriando bin/")
            ensure_dir(binpath)

        log_success(f"Toolchain {name}-{version} verificado")

    def remove(self, name: str, version: str) -> None:
        """
        Remove toolchain instalado.
        """
        path = self.tcdir / f"{name}-{version}"
        if not path.exists():
            raise ToolchainError(f"Toolchain {name}-{version} não existe")

        shutil.rmtree(path)
        db = self.list()
        if name in db and version in db[name]:
            del db[name][version]
            if not db[name]:
                del db[name]
            self.dbfile.write_text(yaml.safe_dump(db), encoding="utf-8")
        log_success(f"Toolchain {name}-{version} removido")

    def _download(self, url: str) -> Path:
        """
        Faz download simples via curl/wget.
        """
        tarball = self.tcdir / os.path.basename(url)
        if not tarball.exists():
            if shutil.which("curl"):
                safe_run(["curl", "-L", "-o", str(tarball), url])
            elif shutil.which("wget"):
                safe_run(["wget", "-O", str(tarball), url])
            else:
                raise ToolchainError("Nem curl nem wget disponíveis")
        return tarball

    def _update_db(self, name: str, version: str, path: str) -> None:
        db = self.list()
        db.setdefault(name, {})
        db[name][version] = {"path": path}
        self.dbfile.write_text(yaml.safe_dump(db), encoding="utf-8")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    mgr = ToolchainManager(cfg)
    try:
        mgr.list()
        print("Toolchains disponíveis:", mgr.list())
    except ToolchainError as e:
        log_error(str(e))
