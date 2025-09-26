#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract.py
Responsável por descompactar os sources baixados (tar.gz, tar.xz, zip, etc.).

Funcionalidades:
- Suporte a múltiplos formatos (.tar.gz, .tar.bz2, .tar.xz, .zip, .tar.zst).
- Criação automática da pasta build.
- Retorna o caminho da pasta extraída para compilação.
"""

from __future__ import annotations
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional
from utils import log_info, log_warn, log_success, log_error, ensure_dir, safe_run
from config import Config

class ExtractError(Exception):
    pass

class Extractor:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.workdir = Path(cfg.workdir)

    def extract(self, archive: Path) -> Path:
        """
        Extrai o arquivo `archive` para dentro de workdir/build.
        Retorna o caminho da pasta extraída.
        """
        builddir = self.workdir / "build"
        if builddir.exists():
            log_warn(f"Limpando build antiga em {builddir}")
            shutil.rmtree(builddir)
        ensure_dir(builddir)

        log_info(f"Extraindo {archive} para {builddir}")
        try:
            if archive.suffixes[-2:] in [[".tar", ".gz"], [".tar", ".bz2"], [".tar", ".xz"]]:
                with tarfile.open(archive, "r:*") as tf:
                    tf.extractall(path=builddir)
            elif archive.suffix == ".zip":
                with zipfile.ZipFile(archive, "r") as zf:
                    zf.extractall(path=builddir)
            elif archive.suffixes[-2:] == [".tar", ".zst"]:
                # usar tar do sistema para .zst
                safe_run(["tar", "--use-compress-program=unzstd", "-xf", str(archive), "-C", str(builddir)], check=True)
            else:
                log_warn(f"Formato não reconhecido, tentando unpack_archive: {archive}")
                shutil.unpack_archive(str(archive), extract_dir=str(builddir))
        except Exception as e:
            raise ExtractError(f"Falha ao extrair {archive}: {e}")

        # detectar pasta raiz extraída
        subdirs = [p for p in builddir.iterdir() if p.is_dir()]
        if len(subdirs) == 1:
            final_dir = subdirs[0]
        else:
            final_dir = builddir

        log_success(f"Extração concluída em {final_dir}")
        return final_dir

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    ex = Extractor(cfg)
    # Exemplo: passar caminho para um tarball existente
    # src = Path("/tmp/hello-2.12.tar.gz")
    # out = ex.extract(src)
    # print("Extraído em:", out)
