
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build.py
Responsável por compilar pacotes conforme o build system do meta.yaml.

Suporta:
- Autotools
- Meson
- CMake
- Rust (Cargo)
- Python (setuptools/pip)

Integração:
- Executa hooks pre_build/post_build
- Cria pasta build automaticamente
- Usa número de jobs configurado em config.yaml
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Optional
from utils import log_info, log_warn, log_success, log_error, safe_run, ensure_dir
from config import Config
from meta import MetaPackage
from patches_and_hooks import PatchHookManager, PatchHookError

class BuildError(Exception):
    pass

class Builder:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.jobs = int(cfg.get("build", "jobs", default=4))
        self.hookmgr = PatchHookManager(cfg)

    def build(self, pkg: MetaPackage, srcdir: Path) -> None:
        """
        Compila o pacote de acordo com seu sistema de build.
        """
        build_system = pkg.build_system.lower()
        log_info(f"Iniciando build: {pkg.name}-{pkg.version} [{build_system}]")

        # criar pasta build dentro do srcdir (isolada)
        builddir = srcdir / "build"
        ensure_dir(builddir)

        # hooks pre_build
        self.hookmgr.run_hooks(pkg, "pre_build", srcdir)

        try:
            if build_system == "autotools":
                self._build_autotools(srcdir, builddir)
            elif build_system == "meson":
                self._build_meson(srcdir, builddir)
            elif build_system == "cmake":
                self._build_cmake(srcdir, builddir)
            elif build_system == "rust":
                self._build_rust(srcdir)
            elif build_system == "python":
                self._build_python(srcdir, builddir)
            else:
                raise BuildError(f"Sistema de build desconhecido: {build_system}")
        except Exception as e:
            raise BuildError(f"Falha na compilação {pkg.name}-{pkg.version}: {e}")

        # hooks post_build
        self.hookmgr.run_hooks(pkg, "post_build", srcdir)

        log_success(f"Build concluído: {pkg.name}-{pkg.version}")

    # -----------------------
    # Autotools
    # -----------------------
    def _build_autotools(self, srcdir: Path, builddir: Path) -> None:
        log_info("Usando Autotools")
        safe_run(["./configure", f"--prefix=/usr"], cwd=str(srcdir), check=True)
        safe_run(["make", f"-j{self.jobs}"], cwd=str(srcdir), check=True)

    # -----------------------
    # Meson
    # -----------------------
    def _build_meson(self, srcdir: Path, builddir: Path) -> None:
        log_info("Usando Meson")
        safe_run(["meson", "setup", str(builddir), str(srcdir), f"-Dprefix=/usr"], check=True)
        safe_run(["ninja", "-C", str(builddir), f"-j{self.jobs}"], check=True)

    # -----------------------
    # CMake
    # -----------------------
    def _build_cmake(self, srcdir: Path, builddir: Path) -> None:
        log_info("Usando CMake")
        safe_run(["cmake", "-B", str(builddir), "-S", str(srcdir), "-DCMAKE_INSTALL_PREFIX=/usr"], check=True)
        safe_run(["cmake", "--build", str(builddir), f"-j{self.jobs}"], check=True)

    # -----------------------
    # Rust (Cargo)
    # -----------------------
    def _build_rust(self, srcdir: Path) -> None:
        log_info("Usando Cargo (Rust)")
        safe_run(["cargo", "build", "--release"], cwd=str(srcdir), check=True)

    # -----------------------
    # Python
    # -----------------------
    def _build_python(self, srcdir: Path, builddir: Path) -> None:
        log_info("Usando Python setuptools")
        setup_py = srcdir / "setup.py"
        if setup_py.exists():
            safe_run(["python3", "setup.py", "build"], cwd=str(srcdir), check=True)
        else:
            log_info("setup.py não encontrado, tentando pip wheel")
            safe_run(["pip", "wheel", ".", "-w", str(builddir)], cwd=str(srcdir), check=True)

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
        builder = Builder(cfg)
        builder.build(pkg, src)
