# pkgtool/builder.py
"""
pkgtool.builder - responsável por compilar pacotes a partir de metadados YAML
Atualizado: agora integra com pkgtool.dependencies para resolver deps automaticamente.
"""

import os
import sys
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import yaml
except Exception:
    raise RuntimeError("PyYAML is required (pip install pyyaml)")

# dependências de outros módulos
from .config import load_config
from .logger import Logger
from . import dependencies as deps

class Builder:
    def __init__(self):
        self.cfg = load_config()
        self.log = Logger("builder")

    # ---------------- utilitários ----------------
    def find_meta(self, ident: str) -> Optional[Path]:
        """Procura meta pelo nome do pacote ou caminho"""
        ident = str(ident)
        if os.path.isfile(ident):
            return Path(ident)
        ports_dir = Path(self.cfg["ports_dir"])
        for meta in ports_dir.rglob("*.meta.yaml"):
            if meta.stem.startswith(ident):
                return meta
        return None

    def _apply_patches(self, srcdir: Path, patches: list):
        for patch in patches:
            self.log.info(f"Applying patch {patch}")
            subprocess.run(["patch", "-p1", "-i", str(patch)], cwd=srcdir, check=True)

    def _create_build_dir(self, name: str, version: str) -> Path:
        build_root = Path(self.cfg["build_root"])
        bdir = build_root / f"{name}-{version}"
        if bdir.exists():
            shutil.rmtree(bdir)
        bdir.mkdir(parents=True)
        return bdir

 def build(self, meta_ident: str, dry_run: bool=False, keep_build: bool=True, follow: bool=False):
        """
        Constrói pacote a partir do meta.
        Agora: resolve dependências via dependencies.build_deps_for_meta()
        """
        meta_path = self.find_meta(meta_ident)
        if not meta_path:
            return type("R",(object,),{"ok":False,"message":f"meta {meta_ident} não encontrado"})

        meta = yaml.safe_load(open(meta_path)) or {}
        name = meta.get("name") or meta_path.stem
        version = meta.get("version") or "unknown"
        self.log.info(f"==== Building {name}-{version} ====")

        # 1. Resolver e compilar dependências
        self.log.info("Checking dependencies...")
        dep_res = deps.build_deps_for_meta(meta_path, dry_run=dry_run, keep_build=True)
        if not dep_res.get("ok", True):
            self.log.error(f"dependency build failed: {dep_res}")
            return type("R",(object,),{"ok":False,"message":"dependency build failed"})

        # 2. Criar pasta de build
        bdir = self._create_build_dir(name, version)

        # 3. Hooks pré-build
        pre_hooks = meta.get("hooks",{}).get("pre_build",[])
        for cmd in pre_hooks:
            self.log.info(f"[hook pre_build] {cmd}")
            if not dry_run:
                subprocess.run(cmd, shell=True, cwd=bdir, check=True)

        # 4. Rodar sistema de build
        bs = meta.get("buildsystem","autotools")
        if bs == "autotools":
            cmds = ["./configure --prefix=/usr","make -j$(nproc)"]
        elif bs == "meson":
            cmds = ["meson setup builddir --prefix=/usr","ninja -C builddir"]
        elif bs == "rust":
            cmds = ["cargo build --release"]
        else:
            cmds = meta.get("build_commands",[])
        for cmd in cmds:
            self.log.info(f"[build] {cmd}")
            if not dry_run:
                subprocess.run(cmd, shell=True, cwd=bdir, check=True)

        # 5. Instalação fake-root + empacotamento
        pkgname = f"{name}-{version}.pkg.tar.xz"
        pkgpath = Path(self.cfg["package_store"]) / pkgname
        if not dry_run:
            destdir = bdir / "dest"
            destdir.mkdir(exist_ok=True)
            install_cmds = meta.get("install_commands",["make DESTDIR=$PWD/dest install"])
            for cmd in install_cmds:
                self.log.info(f"[install] {cmd}")
                subprocess.run(cmd, shell=True, cwd=bdir, check=True, env={**os.environ, "DESTDIR": str(destdir)})
            with tarfile.open(pkgpath,"w:xz") as tar:
                tar.add(destdir,".")
        self.log.success(f"Package built: {pkgpath}")

        # 6. Hooks pós-build
        post_hooks = meta.get("hooks",{}).get("post_build",[])
        for cmd in post_hooks:
            self.log.info(f"[hook post_build] {cmd}")
            if not dry_run:
                subprocess.run(cmd, shell=True, cwd=bdir, check=True)

        # 7. Limpar build-deps se configurado
        if not self.cfg.get("keep_build_deps", False):
            self.log.info("Cleaning build dependencies...")
            deps.clean_build_deps_for_meta(meta_path)

        return type("R",(object,),{"ok":True,"message":"build ok","package_path":pkgpath})
