#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pythonmgr.py
Gerenciador de múltiplas versões do Python.

Funcionalidades:
- Instalar/atualizar/remover versões do Python
- Suporte a múltiplas versões lado a lado
- Selecionar versão padrão via symlink
- Reparar versões quebradas
- Garantir versão compatível com pkgtool
"""

from __future__ import annotations
import os
import shutil
import subprocess
import yaml
from pathlib import Path
from typing import Dict, Any
from utils import log_info, log_warn, log_success, log_error, ensure_dir, safe_run
from config import Config

class PythonError(Exception):
    pass

class PythonManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dbfile = Path(cfg.pkgdir) / "python_db.yaml"
        self.pyroot = Path(cfg.workdir) / "python_versions"
        ensure_dir(self.pyroot)

    def install(self, version: str, url: str) -> None:
        """
        Instala versão específica do Python a partir de tarball oficial.
        """
        log_info(f"Instalando Python {version} de {url}")
        destdir = self.pyroot / f"python-{version}"
        if destdir.exists():
            raise PythonError(f"Python {version} já existe")

        tarball = self._download(url)
        builddir = self.pyroot / f"build-{version}"
        ensure_dir(builddir)

        try:
            safe_run(["tar", "xf", tarball, "-C", str(builddir)])
            srcdir = next(builddir.glob("Python-*"))
            safe_run(["./configure", f"--prefix={destdir}"], cwd=str(srcdir))
            safe_run(["make", "-j4"], cwd=str(srcdir))
            safe_run(["make", "install"], cwd=str(srcdir))
            log_success(f"Python {version} instalado em {destdir}")
            self._update_db(version, str(destdir))
        except Exception as e:
            raise PythonError(f"Falha ao instalar Python {version}: {e}")
        finally:
            shutil.rmtree(builddir, ignore_errors=True)

    def list(self) -> Dict[str, Any]:
        """
        Lista versões de Python instaladas.
        """
        if not self.dbfile.exists():
            return {}
        return yaml.safe_load(self.dbfile.read_text(encoding="utf-8")) or {}

    def set_default(self, version: str) -> None:
        """
        Define versão padrão do Python via symlink.
        """
        path = self.pyroot / f"python-{version}"
        if not path.exists():
            raise PythonError(f"Python {version} não existe")

        link = self.pyroot / "default"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(path)
        log_success(f"Python ativo: {version}")

    def repair(self, version: str) -> None:
        """
        Repara instalação de Python (reinstala binários essenciais).
        """
        path = self.pyroot / f"python-{version}"
        if not path.exists():
            raise PythonError(f"Python {version} não existe")

        binpath = path / "bin"
        if not (binpath / "python3").exists():
            log_warn(f"Python {version} incompleto, recriando binários")
            safe_run(["make", "install"], cwd=str(path))
        log_success(f"Python {version} verificado")

    def remove(self, version: str) -> None:
        """
        Remove versão instalada do Python.
        """
        path = self.pyroot / f"python-{version}"
        if not path.exists():
            raise PythonError(f"Python {version} não existe")

        shutil.rmtree(path)
        db = self.list()
        if version in db:
            del db[version]
            self.dbfile.write_text(yaml.safe_dump(db), encoding="utf-8")
        log_success(f"Python {version} removido")

        # garantir que reste uma versão
        if not db:
            raise PythonError("Nenhuma versão de Python restante, instale outra antes de remover")

    def ensure_compat(self, min_version: str = "3.10") -> None:
        """
        Garante que exista pelo menos uma versão compatível com o pkgtool.
        """
        db = self.list()
        if not db:
            raise PythonError("Nenhum Python instalado")
        for v in db.keys():
            if v >= min_version:
                log_info(f"Python {v} é compatível com pkgtool")
                return
        raise PythonError(f"Nenhuma versão de Python >= {min_version} encontrada")

    def _download(self, url: str) -> Path:
        """
        Faz download via curl/wget.
        """
        tarball = self.pyroot / os.path.basename(url)
        if not tarball.exists():
            if shutil.which("curl"):
                safe_run(["curl", "-L", "-o", str(tarball), url])
            elif shutil.which("wget"):
                safe_run(["wget", "-O", str(tarball), url])
            else:
                raise PythonError("Nem curl nem wget disponíveis")
        return tarball

    def _update_db(self, version: str, path: str) -> None:
        db = self.list()
        db[version] = {"path": path}
        self.dbfile.write_text(yaml.safe_dump(db), encoding="utf-8")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    mgr = PythonManager(cfg)
    try:
        print("Versões instaladas:", mgr.list())
        mgr.ensure_compat()
    except PythonError as e:
        log_error(str(e))
