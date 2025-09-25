import os
import sys
import hashlib
import shutil
import subprocess
import time
import requests
import ftplib
from pathlib import Path
from datetime import datetime, timedelta
from tqdm import tqdm

from . import config, log

try:
    import gnupg
    GPG_AVAILABLE = True
except ImportError:
    GPG_AVAILABLE = False


CFG = config.load_config()
CACHE_DIR = Path(CFG.get("fetcher", {}).get("cache_dir", "/var/cache/pkgtool/distfiles"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------
# Utilidades de Hash
# ------------------------
def _hash_file(path, algo="sha256", chunk_size=8192):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def _check_checksum(path, checksum):
    """Valida checksum no formato algo:hash"""
    algo, expected = checksum.split(":", 1)
    digest = _hash_file(path, algo)
    return digest == expected, digest


def _check_gpg(path, sig_file):
    if not GPG_AVAILABLE:
        raise RuntimeError("python-gnupg não disponível para validação GPG.")
    gpg = gnupg.GPG()
    with open(sig_file, "rb") as sig, open(path, "rb") as f:
        verified = gpg.verify_file(sig, f.name)
        return verified.valid


# ------------------------
# Downloaders
# ------------------------
def _download_http(url, dest, resume=True):
    headers = {}
    mode = "wb"
    if resume and dest.exists():
        headers["Range"] = f"bytes={dest.stat().st_size}-"
        mode = "ab"

    with requests.get(url, stream=True, headers=headers, timeout=CFG["fetcher"].get("timeout", 60)) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0)) + dest.stat().st_size if resume else int(r.headers.get("Content-Length", 0))
        with open(dest, mode) as f, tqdm(
            total=total,
            initial=dest.stat().st_size if resume else 0,
            unit="B", unit_scale=True, desc=f"HTTP {url}"
        ) as bar:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    bar.update(len(chunk))


def _download_ftp(url, dest):
    from urllib.parse import urlparse
    u = urlparse(url)
    ftp = ftplib.FTP(u.hostname)
    ftp.login()
    ftp.cwd(os.path.dirname(u.path))
    with open(dest, "wb") as f:
        ftp.retrbinary(f"RETR {os.path.basename(u.path)}", f.write)


def _clone_git(url, dest, branch="master", commit=None, depth=1):
    if dest.exists():
        subprocess.run(["git", "-C", str(dest), "fetch"], check=True)
    else:
        subprocess.run(["git", "clone", "--branch", branch, "--depth", str(depth), url, str(dest)], check=True)
    if commit:
        subprocess.run(["git", "-C", str(dest), "checkout", commit], check=True)


# ------------------------
# Delta Downloads
# ------------------------
def _try_delta_download(url, dest, old_file):
    """
    Tenta delta download via zsync ou rsync.
    """
    zsync_url = url + ".zsync"
    tmp_dest = dest.with_suffix(".partial")

    try:
        log.info(f"Tentando delta download via zsync: {zsync_url}")
        subprocess.run(["zsync", "-i", str(old_file), "-o", str(tmp_dest), zsync_url], check=True)
        shutil.move(tmp_dest, dest)
        return True
    except Exception as e:
        log.warn(f"Delta download falhou: {e}")
        return False


# ------------------------
# API Principal
# ------------------------
def fetch(url, checksum=None, mirrors=None, gpg_sig=None):
    filename = os.path.basename(url)
    dest = CACHE_DIR / filename

    if dest.exists() and checksum:
        ok, _ = _check_checksum(dest, checksum)
        if ok:
            log.info(f"Arquivo já presente em cache: {filename}")
            return dest

    urls = [url]
    if mirrors:
        urls.extend(mirrors)

    for u in urls:
        try:
            log.info(f"Baixando {u} → {dest}")
            if u.startswith("http"):
                if dest.exists():
                    if _try_delta_download(u, dest, dest):
                        break
                _download_http(u, dest)
            elif u.startswith("ftp"):
                _download_ftp(u, dest)
            elif u.startswith("git"):
                _clone_git(u, dest.with_suffix(".git"))
                return dest.with_suffix(".git")
            elif u.startswith("file://"):
                shutil.copy(u[7:], dest)
            else:
                raise ValueError(f"Protocolo não suportado: {u}")
            break
        except Exception as e:
            log.error(f"Falha em {u}: {e}")
            continue
    else:
        raise RuntimeError(f"Não foi possível baixar {filename}")

    if checksum:
        ok, digest = _check_checksum(dest, checksum)
        if not ok:
            raise RuntimeError(f"Checksum incorreto: {digest} esperado {checksum}")

    if gpg_sig:
        if not _check_gpg(dest, gpg_sig):
            raise RuntimeError(f"Assinatura GPG inválida para {filename}")

    return dest


def fetch_git(url, branch="master", commit=None, depth=1):
    dest = CACHE_DIR / (os.path.basename(url.rstrip("/")) + ".git")
    _clone_git(url, dest, branch, commit, depth)
    return dest


def list_cache():
    return [f for f in CACHE_DIR.iterdir() if f.is_file()]


def clean_cache(days=None):
    now = datetime.now()
    for f in list_cache():
        if not days:
            f.unlink()
        else:
            age = now - datetime.fromtimestamp(f.stat().st_mtime)
            if age > timedelta(days=days):
                f.unlink()


def verify_file(path, checksum=None, gpg_sig=None):
    if checksum:
        ok, digest = _check_checksum(path, checksum)
        if not ok:
            raise RuntimeError(f"Checksum inválido para {path}, obtido {digest}")
    if gpg_sig:
        if not _check_gpg(path, gpg_sig):
            raise RuntimeError(f"GPG inválido para {path}")
    return True


def test_mirrors():
    mirrors = CFG.get("fetcher", {}).get("mirrors", [])
    results = {}
    for m in mirrors:
        start = time.time()
        try:
            r = requests.head(m, timeout=5)
            elapsed = time.time() - start
            results[m] = {"status": r.status_code, "time": elapsed}
        except Exception as e:
            results[m] = {"status": "fail", "error": str(e)}
    return results


# ------------------------
# CLI
# ------------------------
def cli_main(argv):
    import argparse
    parser = argparse.ArgumentParser(prog="pkgtool-fetcher")
    sub = parser.add_subparsers(dest="cmd")

    g = sub.add_parser("get")
    g.add_argument("url")
    g.add_argument("--checksum")
    g.add_argument("--gpg-sig")

    v = sub.add_parser("verify")
    v.add_argument("file")
    v.add_argument("--checksum")
    v.add_argument("--gpg-sig")

    sub.add_parser("list-cache")

    c = sub.add_parser("clean")
    c.add_argument("--older-than", type=int)

    sub.add_parser("mirrors-test")

    args = parser.parse_args(argv)

    if args.cmd == "get":
        fetch(args.url, checksum=args.checksum, gpg_sig=args.gpg_sig)
    elif args.cmd == "verify":
        verify_file(args.file, args.checksum, args.gpg_sig)
    elif args.cmd == "list-cache":
        for f in list_cache():
            print(f)
    elif args.cmd == "clean":
        clean_cache(days=args.older_than)
    elif args.cmd == "mirrors-test":
        print(test_mirrors())
    else:
        parser.print_help()
