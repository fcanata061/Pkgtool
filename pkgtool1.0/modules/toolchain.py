# pkgtool/toolchain.py
import os
import sys
import shutil
import subprocess
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

from .config import load_config
from .logger import LOGGER
from .builder import Builder
from .utils import safe_mkdir, safe_rmtree

CONFIG = load_config()

TOOLCHAIN_ROOT = Path(CONFIG["paths"]["toolchains"]).expanduser()
TOOLCHAIN_DB = TOOLCHAIN_ROOT / "toolchains.yaml"

def _load_db() -> Dict[str, Any]:
    if not TOOLCHAIN_DB.exists():
        return {"installed": {}, "active": None}
    return yaml.safe_load(TOOLCHAIN_DB.read_text()) or {"installed": {}, "active": None}

def _save_db(db: Dict[str, Any]) -> None:
    TOOLCHAIN_DB.parent.mkdir(parents=True, exist_ok=True)
    TOOLCHAIN_DB.write_text(yaml.safe_dump(db))

class ToolchainManager:
    def __init__(self):
        self.db = _load_db()
        self.builder = Builder()

    # ------------------------------------------------------------------
    # Basic operations
    # ------------------------------------------------------------------
    def list(self) -> Dict[str, Any]:
        return {
            "active": self.db.get("active"),
            "installed": list(self.db.get("installed", {}).keys())
        }

    def is_installed(self, name: str) -> bool:
        return name in self.db.get("installed", {})

    def active(self) -> Optional[str]:
        return self.db.get("active")

# ------------------------------------------------------------------
    # Install toolchain (build via meta)
    # ------------------------------------------------------------------
    def install(self, meta_name: str, dry_run: bool = False) -> Dict[str, Any]:
        if self.is_installed(meta_name):
            return {"ok": True, "detail": f"{meta_name} já instalado"}
        LOGGER.info(f"Instalando toolchain {meta_name}")
        meta_path = self.builder.find_meta(meta_name)
        if not meta_path:
            return {"ok": False, "detail": f"Meta {meta_name} não encontrado"}
        if dry_run:
            return {"ok": True, "detail": f"[dry-run] {meta_name} seria instalado"}
        res = self.builder.build(str(meta_path), dry_run=False, keep_build=False, follow=True)
        if not res.ok:
            return {"ok": False, "detail": f"Falha ao compilar {meta_name}: {res.message}"}
        self.db["installed"][meta_name] = {"path": str(meta_path)}
        _save_db(self.db)
        return {"ok": True, "detail": f"{meta_name} instalado"}

    # ------------------------------------------------------------------
    # Remove toolchain
    # ------------------------------------------------------------------
    def remove(self, meta_name: str) -> Dict[str, Any]:
        if not self.is_installed(meta_name):
            return {"ok": False, "detail": f"{meta_name} não instalado"}
        if self.active() == meta_name:
            return {"ok": False, "detail": f"{meta_name} está ativo, não pode remover"}
        LOGGER.info(f"Removendo toolchain {meta_name}")
        # TODO: aqui poderia limpar arquivos do prefixo
        del self.db["installed"][meta_name]
        _save_db(self.db)
        return {"ok": True, "detail": f"{meta_name} removido"}

    # ------------------------------------------------------------------
    # Select toolchain
    # ------------------------------------------------------------------
    def select(self, meta_name: str) -> Dict[str, Any]:
        if not self.is_installed(meta_name):
            return {"ok": False, "detail": f"{meta_name} não instalado"}
        LOGGER.info(f"Selecionando toolchain {meta_name}")
        self.db["active"] = meta_name
        _save_db(self.db)
        return {"ok": True, "detail": f"{meta_name} agora é ativo"}

# ------------------------------------------------------------------
    # Rebuild toolchain
    # ------------------------------------------------------------------
    def rebuild(self, meta_name: Optional[str] = None) -> Dict[str, Any]:
        target = meta_name or self.active()
        if not target:
            return {"ok": False, "detail": "Nenhum toolchain ativo"}
        if not self.is_installed(target):
            return {"ok": False, "detail": f"{target} não está instalado"}
        LOGGER.info(f"Reconstruindo toolchain {target}")
        meta_path = Path(self.db["installed"][target]["path"])
        res = self.builder.build(str(meta_path), dry_run=False, keep_build=False, follow=True)
        if not res.ok:
            return {"ok": False, "detail": f"Falha ao reconstruir {target}: {res.message}"}
        return {"ok": True, "detail": f"{target} reconstruído"}

    # ------------------------------------------------------------------
    # Verify toolchain consistency
    # ------------------------------------------------------------------
    def verify(self) -> Dict[str, Any]:
        active = self.active()
        if not active:
            return {"ok": False, "detail": "Nenhum toolchain ativo"}
        LOGGER.info(f"Verificando consistência do toolchain {active}")
        # Exemplo simples: checar se gcc existe
        gcc = shutil.which("gcc")
        if not gcc:
            return {"ok": False, "detail": "gcc não encontrado no PATH"}
        return {"ok": True, "detail": f"Toolchain {active} consistente"}

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------
    def run_hook(self, hook: str) -> None:
        hooks_dir = TOOLCHAIN_ROOT / "hooks"
        script = hooks_dir / f"{hook}.sh"
        if script.exists():
            LOGGER.info(f"Executando hook {hook}")
            subprocess.run(["bash", str(script)], check=False)

def cli():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-toolchain")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("list", help="Listar toolchains")
    p_install = sub.add_parser("install", help="Instalar toolchain")
    p_install.add_argument("meta")
    sub.add_parser("verify", help="Verificar consistência")
    p_remove = sub.add_parser("remove", help="Remover toolchain")
    p_remove.add_argument("meta")
    p_select = sub.add_parser("select", help="Selecionar toolchain ativo")
    p_select.add_argument("meta")
    sub.add_parser("rebuild", help="Reconstruir toolchain ativo")

    args = p.parse_args()
    mgr = ToolchainManager()

    if args.cmd == "list":
        print(mgr.list()); return
    if args.cmd == "install":
        print(mgr.install(args.meta)); return
    if args.cmd == "remove":
        print(mgr.remove(args.meta)); return
    if args.cmd == "select":
        print(mgr.select(args.meta)); return
    if args.cmd == "rebuild":
        print(mgr.rebuild()); return
    if args.cmd == "verify":
        print(mgr.verify()); return
    p.print_help()

if __name__ == "__main__":
    cli()
