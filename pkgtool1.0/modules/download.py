#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
download.py
Responsável por baixar os sources definidos em meta.yaml.

Suporta:
- HTTP/HTTPS/FTP (via urllib)
- Git (via subprocess)
- Rsync
- Cache local
- Verificação de checksum

Integração:
- Usa utils.safe_run para comandos
- Usa utils.verify_checksum
- Usa config.Config para cachedir e timeout/retry
"""

from __future__ import annotations
import os
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional
from config import Config
from utils import log_info, log_warn, log_error, log_success, safe_run, verify_checksum, ensure_dir

class DownloadError(Exception):
    pass

class Downloader:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.cachedir = Path(cfg.cachedir)
        ensure_dir(self.cachedir)

    def fetch(self, source: Dict[str, Any], dest: Path) -> Path:
        """
        Baixa uma fonte.
        `source` é dict de meta.yaml (url/git/rsync + checksum opcional).
        `dest` é diretório de destino onde salvar/extrair.
        Retorna caminho para arquivo ou pasta baixada.
        """
        if "url" in source:
            return self._fetch_url(source, dest)
        elif "git" in source:
            return self._fetch_git(source, dest)
        elif "rsync" in source:
            return self._fetch_rsync(source, dest)
        else:
            raise DownloadError(f"Fonte inválida no meta: {source}")

    # -----------------------
    # HTTP/HTTPS/FTP
    # -----------------------
    def _fetch_url(self, source: Dict[str, Any], dest: Path) -> Path:
        url = source["url"]
        filename = source.get("filename") or os.path.basename(url)
        checksum = source.get("sha256")

        cached_file = self.cachedir / filename
        if cached_file.exists():
            log_info(f"Usando cache para {url}")
        else:
            log_info(f"Baixando {url}")
            self._download_with_retry(url, cached_file)

        if checksum:
            if not verify_checksum(cached_file, checksum):
                raise DownloadError(f"Checksum inválido para {url}")

        final_path = dest / filename
        ensure_dir(dest)
        shutil.copy2(cached_file, final_path)
        log_success(f"Arquivo baixado: {final_path}")
        return final_path

    def _download_with_retry(self, url: str, outpath: Path) -> None:
        retries = int(self.cfg.get("fetch", "retry", default=3))
        timeout = int(self.cfg.get("fetch", "http_timeout", default=60))
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    with open(outpath, "wb") as f:
                        shutil.copyfileobj(resp, f)
                return
            except (urllib.error.URLError, Exception) as e:
                log_warn(f"Falha ao baixar {url} (tentativa {attempt}/{retries}): {e}")
                last_err = e
        raise DownloadError(f"Não foi possível baixar {url}: {last_err}")

    # -----------------------
    # Git
    # -----------------------
    def _fetch_git(self, source: Dict[str, Any], dest: Path) -> Path:
        repo = source["git"]
        branch = source.get("branch")
        rev = source.get("rev")
        depth = self.cfg.get("fetch", "git_depth", default=1)

        repo_dir = self.cachedir / (os.path.basename(repo).replace(".git", ""))
        if not repo_dir.exists():
            log_info(f"Clonando {repo}")
            cmd = ["git", "clone", "--depth", str(depth), repo, str(repo_dir)]
            if branch:
                cmd.extend(["-b", branch])
            safe_run(cmd, check=True)
        else:
            log_info(f"Atualizando {repo}")
            safe_run(["git", "-C", str(repo_dir), "fetch", "--all"], check=True)

        if rev:
            log_info(f"Checkout {rev}")
            safe_run(["git", "-C", str(repo_dir), "checkout", rev], check=True)

        # copia para destino
        ensure_dir(dest)
        target = dest / repo_dir.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(repo_dir, target)
        log_success(f"Git repo baixado em {target}")
        return target

    # -----------------------
    # Rsync
    # -----------------------
    def _fetch_rsync(self, source: Dict[str, Any], dest: Path) -> Path:
        rsync_url = source["rsync"]
        target = dest / os.path.basename(rsync_url.strip("/"))
        ensure_dir(dest)
        log_info(f"Baixando via rsync {rsync_url}")
        safe_run(["rsync", "-avz", rsync_url, str(target)], check=True)
        log_success(f"Rsync concluído: {target}")
        return target

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    from config import Config
    cfg = Config.load()
    dl = Downloader(cfg)
    # Exemplo de teste manual:
    # src = {"url": "https://ftp.gnu.org/gnu/hello/hello-2.12.tar.gz", "sha256": "..." }
    # out = Path(cfg.workdir)
    # dl.fetch(src, out)
