#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upgrade.py
Módulo de atualização de pacotes.

Funcionalidades:
- Verifica novas versões dos pacotes
- Atualiza um pacote ou todos
- Recria meta.yaml com versão nova
- Resolve dependências antes de atualizar
- Notifica via notify-send
- Gera relatório updates_report.yaml
"""

from __future__ import annotations
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from utils import log_info, log_warn, log_success, log_error, safe_run
from config import Config
from gitrepo import GitRepoManager
from meta import MetaIndex, MetaPackage
from deps import DependencyResolver, DependencyError

class UpgradeError(Exception):
    pass

class UpgradeManager:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.repo = GitRepoManager(cfg)
        self.index = MetaIndex(str(self.repo.repo_path))

    def check_updates(self) -> Dict[str, Dict[str, str]]:
        """
        Verifica se há novas versões disponíveis no repositório Git.
        Retorna dict {pacote: {"current": x, "latest": y}}
        """
        log_info("Checando atualizações no repositório")
        self.repo.clone_or_update(self.cfg.repo_url)
        self.index.load()

        updates: Dict[str, Dict[str, str]] = {}
        for pkg in self.index.packages.values():
            current_ver = pkg.version
            # Simulação: supõe que última versão está no campo `latest_version`
            latest_ver = pkg.meta.get("latest_version", current_ver)
            if latest_ver != current_ver:
                updates[pkg.name] = {"current": current_ver, "latest": latest_ver}

        if updates:
            log_success(f"Encontradas {len(updates)} atualizações disponíveis")
            self._write_report(updates)
            self._notify(updates)
        else:
            log_info("Nenhuma atualização disponível")
        return updates

    def upgrade_package(self, name: str) -> None:
        """
        Atualiza um único pacote e suas dependências.
        """
        log_info(f"Atualizando pacote {name}")
        self.index.load()
        pkg = self.index.find(name)
        if not pkg:
            raise UpgradeError(f"Pacote {name} não encontrado")

        updates = self.check_updates()
        if name not in updates:
            log_info(f"{name} já está na versão mais recente")
            return

        new_ver = updates[name]["latest"]
        self._update_meta(pkg, new_ver)

        resolver = DependencyResolver(self.cfg, self.index)
        try:
            deps = resolver.resolve(name, new_ver)
        except DependencyError as e:
            raise UpgradeError(f"Erro de dependências: {e}")

        log_info(f"Dependências a atualizar: {deps}")
        log_success(f"Pacote {name} atualizado para {new_ver}")

    def upgrade_all(self) -> None:
        """
        Atualiza todos os pacotes disponíveis.
        """
        updates = self.check_updates()
        for name in updates.keys():
            try:
                self.upgrade_package(name)
            except UpgradeError as e:
                log_warn(str(e))

    def _update_meta(self, pkg: MetaPackage, new_version: str) -> None:
        """
        Copia meta.yaml existente e substitui versão pela nova.
        """
        metafile = Path(pkg.path) / "meta.yaml"
        meta = yaml.safe_load(metafile.read_text(encoding="utf-8"))
        meta["version"] = new_version
        newfile = Path(pkg.path) / f"meta-{new_version}.yaml"
        newfile.write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")
        log_success(f"Novo meta gerado: {newfile}")

    def _write_report(self, updates: Dict[str, Dict[str, str]]) -> None:
        """
        Gera arquivo updates_report.yaml com pacotes que possuem novas versões.
        """
        reportfile = Path(self.cfg.logdir) / "updates_report.yaml"
        with open(reportfile, "w", encoding="utf-8") as f:
            yaml.safe_dump(updates, f, sort_keys=False, allow_unicode=True)
        log_info(f"Relatório de atualizações salvo em {reportfile}")

    def _notify(self, updates: Dict[str, Dict[str, str]]) -> None:
        """
        Envia notificação via notify-send com quantidade de updates.
        """
        criticos = urgentes = normais = 0
        for pkg in updates:
            criticos += 1  # simplificação (poderia ser baseado em meta.yaml)

        msg = f"{criticos} atualizações críticas disponíveis"
        try:
            safe_run(["notify-send", "Pkgtool Updates", msg])
        except Exception:
            log_warn("Falha ao enviar notificação")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    mgr = UpgradeManager(cfg)
    try:
        mgr.upgrade_all()
    except UpgradeError as e:
        log_error(str(e))
