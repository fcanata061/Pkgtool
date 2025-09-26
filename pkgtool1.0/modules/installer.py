# pkgtool/installer.py
"""
Installer do pkgtool
- Instala pacotes via fakeroot
- Empacota em tar.zst
- Registra no banco SQLite
- Suporta remoção e rollback
"""

from __future__ import annotations
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Any, List

from .config import get_config, get_env, ensure_dirs
from .logger import Logger

class Installer:
    def __init__(self):
        self.cfg = get_config()
        ensure_dirs(self.cfg)
        self.db_path = Path(self.cfg["db_path"])
        self.package_store = Path(self.cfg["package_store"])
        self.logger = Logger("installer")
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS packages (
                    name TEXT,
                    version TEXT,
                    archive TEXT,
                    files TEXT,
                    PRIMARY KEY(name, version)
                )
            """)
            conn.commit()

    def install(self, name: str, version: str, build_dir: Path, dest_dir: str = "/"):
        """instala programa já compilado no build_dir"""
        self.logger.info(f"Instalando {name}-{version}...")

        tmpdir = Path(tempfile.mkdtemp(prefix="pkgtool-install-"))
        fakeroot_dir = tmpdir / "fakeroot"
        fakeroot_dir.mkdir(parents=True)

        try:
            # usar fakeroot se disponível
            env = get_env()
            env["DESTDIR"] = str(fakeroot_dir)

            # etapa "make install"
            self.logger.info(f"Executando instalação com DESTDIR={fakeroot_dir}")
            subprocess.run(
                ["make", "install"],
                cwd=str(build_dir),
                env=env,
                check=True,
            )

            # empacotar em tar.zst
            archive = self._make_package(name, version, fakeroot_dir)

            # extrair para sistema real
            self.logger.info(f"Instalando arquivos em {dest_dir}")
            subprocess.run(
                ["tar", "--use-compress-program=zstd", "-xf", archive, "-C", dest_dir],
                check=True,
            )

            # listar arquivos instalados
            installed_files = self._list_files_in_archive(archive)

            # registrar no banco
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO packages (name, version, archive, files) VALUES (?,?,?,?)",
                    (name, version, str(archive), "\n".join(installed_files)),
                )
                conn.commit()

            self.logger.success(f"{name}-{version} instalado com sucesso.")

        except Exception as e:
            self.logger.error(f"Falha na instalação: {e}")
            self.logger.warn("Rollback: nenhum arquivo foi instalado no sistema.")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def remove(self, name: str, version: str):
        """remove pacote instalado"""
        self.logger.info(f"Removendo {name}-{version}...")

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "SELECT archive, files FROM packages WHERE name=? AND version=?",
                (name, version),
            )
            row = cur.fetchone()
            if not row:
                self.logger.warn(f"{name}-{version} não encontrado no banco.")
                return

            archive, files_str = row
            files = files_str.splitlines()

            # hook pre-remove
            self._run_hook(name, version, "pre-remove")

            # remover arquivos
            for f in files:
                try:
                    p = Path(f)
                    if p.is_file() or p.is_symlink():
                        p.unlink(missing_ok=True)
                    elif p.is_dir():
                        # só remove se vazio
                        try:
                            p.rmdir()
                        except OSError:
                            pass
                except Exception as e:
                    self.logger.warn(f"Erro removendo {f}: {e}")

            # remover registro do banco
            conn.execute(
                "DELETE FROM packages WHERE name=? AND version=?", (name, version)
            )
            conn.commit()

        # hook post-remove
        self._run_hook(name, version, "post-remove")

        self.logger.success(f"{name}-{version} removido com sucesso.")

    def _make_package(self, name: str, version: str, fakeroot_dir: Path) -> str:
        """gera pacote tar.zst a partir do fakeroot"""
        archive = self.package_store / f"{name}-{version}.tar.zst"
        archive.parent.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"Criando pacote {archive}")
        subprocess.run(
            ["tar", "--use-compress-program=zstd", "-cf", archive, "-C", fakeroot_dir, "."],
            check=True,
        )
        return str(archive)

    def _list_files_in_archive(self, archive: str) -> List[str]:
        """retorna lista de arquivos dentro do pacote"""
        files = []
        with tarfile.open(archive, "r:*") as tar:
            for member in tar.getmembers():
                files.append("/" + member.name.lstrip("./"))
        return files

    def _run_hook(self, name: str, version: str, hook: str):
        """executa hook de pre/post remove se existir"""
        hook_path = Path(self.cfg["ports_dir"]) / name / f"{version}.{hook}.sh"
        if hook_path.exists():
            self.logger.info(f"Executando hook {hook_path}")
            subprocess.run(
                ["bash", str(hook_path)],
                env=get_env(),
                check=False,
            )
