#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notify.py
Gerenciamento centralizado de notificações para o pkgtool.

Funcionalidades:
- Enviar notificações via notify-send
- Registrar histórico em YAML
- Contagem de updates por severidade
"""

from __future__ import annotations
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List
from utils import log_info, log_warn, log_success, safe_run
from config import Config

class NotifierError(Exception):
    pass

class Notifier:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.history_file = Path(cfg.logdir) / "notify_history.yaml"

    def notify(self, title: str, message: str, urgency: str = "normal") -> None:
        """
        Envia notificação simples com notify-send.
        """
        urgency_map = {"normal": "normal", "urgent": "critical", "critical": "critical"}
        level = urgency_map.get(urgency, "normal")
        try:
            safe_run(["notify-send", "-u", level, title, message])
            self._log_notification(title, message, urgency)
            log_success(f"Notificação enviada: {title} -> {message}")
        except Exception as e:
            log_warn(f"Falha ao enviar notificação: {e}")

    def summary_updates(self, updates: Dict[str, str], severity: Dict[str, int]) -> None:
        """
        Envia notificação com resumo de updates classificados por severidade.
        """
        total = sum(severity.values())
        counts = ", ".join([f"{v} {k}" for k, v in severity.items() if v > 0])
        msg = f"{total} atualizações disponíveis ({counts})"
        self.notify("Pkgtool Updates", msg, urgency="normal")

    def _log_notification(self, title: str, message: str, urgency: str) -> None:
        """
        Registra notificação no histórico YAML.
        """
        entry = {"title": title, "message": message, "urgency": urgency}
        history: List[Dict[str, str]] = []
        if self.history_file.exists():
            history = yaml.safe_load(self.history_file.read_text(encoding="utf-8")) or []
        history.append(entry)
        self.history_file.write_text(
            yaml.safe_dump(history, sort_keys=False, allow_unicode=True),
            encoding="utf-8"
        )
        log_info(f"Histórico de notificações atualizado em {self.history_file}")

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    notifier = Notifier(cfg)
    notifier.notify("Teste", "Notificação de teste", urgency="normal")
    notifier.summary_updates(
        {"pkg1": "1.0", "pkg2": "2.3"},
        {"criticas": 2, "urgentes": 1, "normais": 4}
    )
