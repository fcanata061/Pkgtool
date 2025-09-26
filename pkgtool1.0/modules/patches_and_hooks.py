#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patches_and_hooks.py
Responsável por aplicar patches e executar hooks dos pacotes.

Funcionalidades:
- Aplicar patches de .patch/.diff encontrados na pasta patches do pacote.
- Executar hooks definidos em meta.yaml (inline e scripts externos).
- Hooks suportados: pre_fetch, post_fetch, pre_patch, post_patch, pre_build, post_build,
  pre_package, post_package, pre_install, post_install, pre_remove, post_remove.
"""

from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import List, Dict
from utils import log_info, log_warn, log_success, log_error, safe_run, ensure_dir
from meta import MetaPackage
from config import Config

class PatchHookError(Exception):
    pass

class PatchHookManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    # -----------------------
    # Patches
    # -----------------------
    def apply_patches(self, pkg: MetaPackage, srcdir: Path) -> None:
        """
        Aplica patches da pasta 'patches' dentro do pacote.
        """
        patches_dir = pkg.path.parent / "patches"
        if not patches_dir.exists():
            log_info(f"{pkg.name}-{pkg.version}: sem patches para aplicar")
            return

        for patch_file in sorted(patches_dir.glob("*.patch")) + sorted(patches_dir.glob("*.diff")):
            log_info(f"Aplicando patch {patch_file.name}")
            try:
                with open(patch_file, "rb") as pf:
                    safe_run(["patch", "-p1", "-d", str(srcdir)], input=pf.read(), check=True)
                log_success(f"Patch aplicado: {patch_file.name}")
            except Exception as e:
                raise PatchHookError(f"Falha ao aplicar patch {patch_file}: {e}")

    # -----------------------
    # Hooks
    # -----------------------
    def run_hooks(self, pkg: MetaPackage, hook_name: str, cwd: Path) -> None:
        """
        Executa hooks de um pacote em determinada fase.
        - Inline: lista de comandos a serem executados diretamente.
        - Scripts: arquivos de script no diretório hooks.
        """
        hooks = pkg.hooks.get(hook_name)
        if not hooks:
            return

        log_info(f"Executando hooks {hook_name} para {pkg.name}-{pkg.version}")

        # Inline commands
        for cmd in hooks.get("inline", []):
            log_info(f"[hook-inline] {cmd}")
            try:
                safe_run(cmd, shell=True, cwd=str(cwd), check=True)
                log_success(f"[hook-inline OK] {cmd}")
            except Exception as e:
                raise PatchHookError(f"Hook inline falhou: {cmd} ({e})")

        # Script files
        scripts_dir = pkg.path.parent / "hooks"
        for script in hooks.get("scripts", []):
            script_path = scripts_dir / script
            if not script_path.exists():
                log_warn(f"Script de hook não encontrado: {script_path}")
                continue
            log_info(f"[hook-script] {script_path}")
            try:
                safe_run(["bash", str(script_path)], cwd=str(cwd), check=True)
                log_success(f"[hook-script OK] {script_path}")
            except Exception as e:
                raise PatchHookError(f"Hook script falhou: {script_path} ({e})")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    from meta import MetaIndex
    cfg = Config.load()
    idx = MetaIndex(cfg.repo_path)
    idx.load()
    mgr = PatchHookManager(cfg)

    # Teste com primeiro pacote encontrado
    pkgs = idx.all_packages()
    if pkgs:
        pkg = pkgs[0]
        src = Path(cfg.workdir) / "build" / f"{pkg.name}-{pkg.version}"
        mgr.apply_patches(pkg, src)
        mgr.run_hooks(pkg, "pre_build", src)
