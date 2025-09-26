#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner.py
Varredura do sistema para detectar problemas.

Funcionalidades:
- Detectar links quebrados
- Detectar pacotes órfãos
- Verificar arquivos faltando
- Verificar libs ausentes via ldd
- Gerar relatório scan_report.yaml
- Corrigir problemas se solicitado
"""

from __future__ import annotations
import os
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List
from utils import log_info, log_warn, log_success, log_error, safe_run
from config import Config

class ScannerError(Exception):
    pass

class SystemScanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.installdb = Path(cfg.pkgdir) / "installed_db.yaml"
        self.reportfile = Path(cfg.logdir) / "scan_report.yaml"

    def scan(self, fix: bool = False) -> Dict[str, List[str]]:
        """
        Executa varredura completa no sistema.
        """
        log_info("Iniciando varredura do sistema...")
        problems: Dict[str, List[str]] = {
            "broken_links": [],
            "orphans": [],
            "missing_files": [],
            "missing_libs": []
        }

        problems["broken_links"] = self._check_links(fix)
        problems["orphans"] = self._check_orphans(fix)
        problems["missing_files"] = self._check_files(fix)
        problems["missing_libs"] = self._check_libs(fix)

        self._write_report(problems)

        if any(problems.values()):
            log_warn("Problemas detectados! Veja scan_report.yaml")
        else:
            log_success("Nenhum problema encontrado!")

        return problems

    def _check_links(self, fix: bool) -> List[str]:
        """
        Detecta links simbólicos quebrados.
        """
        broken: List[str] = []
        for root, _, files in os.walk("/usr"):
            for f in files:
                path = Path(root) / f
                if path.is_symlink() and not path.exists():
                    broken.append(str(path))
                    log_warn(f"Link quebrado: {path}")
                    if fix:
                        path.unlink(missing_ok=True)
                        log_info(f"Removido link quebrado: {path}")
        return broken

    def _check_orphans(self, fix: bool) -> List[str]:
        """
        Detecta pacotes órfãos (sem registro no installed_db.yaml).
        """
        orphans: List[str] = []
        if not self.installdb.exists():
            return orphans
        db = yaml.safe_load(self.installdb.read_text(encoding="utf-8")) or {}
        installed_dirs = [Path(p["install_path"]) for p in db.values()]
        base = Path("/usr/ports/pkgtool")

        for pkgdir in base.iterdir():
            if pkgdir.is_dir() and not any(pkgdir.samefile(d) for d in installed_dirs):
                orphans.append(pkgdir.name)
                log_warn(f"Pacote órfão detectado: {pkgdir.name}")
                if fix:
                    subprocess.run(["rm", "-rf", str(pkgdir)])
                    log_info(f"Removido órfão {pkgdir.name}")
        return orphans

    def _check_files(self, fix: bool) -> List[str]:
        """
        Verifica arquivos faltando comparando com banco installed_db.yaml.
        """
        missing: List[str] = []
        if not self.installdb.exists():
            return missing
        db = yaml.safe_load(self.installdb.read_text(encoding="utf-8")) or {}
        for pkg, info in db.items():
            path = Path(info["install_path"])
            if not path.exists():
                missing.append(pkg)
                log_warn(f"Arquivos de {pkg} faltando em {path}")
                if fix:
                    log_info(f"Reinstale {pkg} para corrigir")
        return missing

    def _check_libs(self, fix: bool) -> List[str]:
        """
        Verifica libs ausentes via ldd.
        """
        missing: List[str] = []
        for root, _, files in os.walk("/usr/bin"):
            for f in files:
                path = Path(root) / f
                try:
                    output = subprocess.check_output(["ldd", str(path)], text=True)
                    for line in output.splitlines():
                        if "not found" in line:
                            missing.append(f"{path}: {line.strip()}")
                            log_warn(f"Biblioteca ausente: {path} -> {line.strip()}")
                            if fix:
                                log_info(f"Sugestão: reinstalar pacote que fornece {line.strip()}")
                except Exception:
                    continue
        return missing

    def _write_report(self, problems: Dict[str, List[str]]) -> None:
        """
        Escreve relatório em YAML com os problemas encontrados.
        """
        self.reportfile.write_text(yaml.safe_dump(problems, sort_keys=False, allow_unicode=True), encoding="utf-8")
        log_info(f"Relatório de varredura salvo em {self.reportfile}")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    scanner = SystemScanner(cfg)
    scanner.scan(fix=False)
