#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
package.py
Responsável por empacotar o software após compilação.

Funcionalidades:
- Instala usando "make install DESTDIR" (fakeroot)
- Aplica strip nos binários
- Empacota em tar.xz dentro do pkgdir
- Executa hooks pre_package/post_package
"""

from __future__ import annotations
import os
import shutil
import tarfile
import subprocess
from pathlib import Path
from typing import Optional
from utils import log_info, log_warn, log_success, log_error, safe_run, ensure_dir
from config import Config
from meta import MetaPackage
from patches_and_hooks import PatchHookManager

class PackageError(Exception):
    pass

class Packager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.pkgdir = Path(cfg.pkgdir)
        ensure_dir(self.pkgdir)
        self.hookmgr = PatchHookManager(cfg)

    def package(self, pkg: MetaPackage, srcdir: Path, builddir: Optional[Path] = None) -> Path:
        """
        Empacota o software compilado.
        - Instala em DESTDIR
        - Strip de binários
        - Cria tar.xz no pkgdir
        Retorna caminho do pacote final.
        """
        log_info(f"Empacotando {pkg.name}-{pkg.version}")

        destdir = srcdir / "_pkg"
        if destdir.exists():
            shutil.rmtree(destdir)
        ensure_dir(destdir)

        # hooks pre_package
        self.hookmgr.run_hooks(pkg, "pre_package", srcdir)

        # instalar
        try:
            if (srcdir / "Makefile").exists():
                safe_run(["fakeroot", "make", "install", f"DESTDIR={destdir}"], cwd=str(srcdir), check=True)
            elif builddir and (builddir / "build.ninja").exists():
                safe_run(["fakeroot", "ninja", "-C", str(builddir), "install"], check=True)
            elif builddir and (builddir / "CMakeCache.txt").exists():
                safe_run(["fakeroot", "cmake", "--install", str(builddir), f"--prefix=/usr", f"--destdir={destdir}"], check=True)
            elif (srcdir / "Cargo.toml").exists():
                safe_run(["fakeroot", "cargo", "install", "--path", ".", f"--root={destdir}/usr"], cwd=str(srcdir), check=True)
            elif (srcdir / "setup.py").exists():
                safe_run(["fakeroot", "python3", "setup.py", "install", f"--root={destdir}", "--prefix=/usr"], cwd=str(srcdir), check=True)
            else:
                raise PackageError("Não foi possível detectar como instalar")
        except Exception as e:
            raise PackageError(f"Falha na instalação: {e}")

        # strip binários
        self._strip_binaries(destdir)

        # criar tarball
        tarname = f"{pkg.name}-{pkg.version}-{pkg.release}.tar.xz"
        tarpath = self.pkgdir / tarname
        with tarfile.open(tarpath, "w:xz") as tf:
            tf.add(destdir, arcname="/")
        log_success(f"Pacote criado: {tarpath}")

        # hooks post_package
        self.hookmgr.run_hooks(pkg, "post_package", srcdir)

        return tarpath

    def _strip_binaries(self, root: Path) -> None:
        """
        Remove símbolos desnecessários de binários para reduzir tamanho.
        """
        log_info("Aplicando strip em binários")
        for path in root.rglob("*"):
            if path.is_file() and os.access(path, os.X_OK):
                try:
                    safe_run(["strip", "--strip-unneeded", str(path)], check=False)
                except Exception as e:
                    log_warn(f"Falha ao strip {path}: {e}")

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
        src = Path(cfg.workdir) / "build" / f"{pkg.name}-{pkg.version}"
        p = Packager(cfg)
        tarball = p.package(pkg, src, src / "build")
        print("Criado:", tarball)
