# pkgtool/builder.py
"""
Módulo Builder do pkgtool
Constrói pacotes a partir de meta.yaml:
 - Fetch (http/https/git/local)
 - Patches automáticos
 - Hooks pré/pós fases
 - Suporte a autotools, meson, cmake, cargo, python
 - Sandbox opcional (bwrap/fakeroot)
 - Empacotamento .pkg.tar.xz
 - Registro em DB
"""

import os
import sys
import subprocess
import shutil
import tarfile
import tempfile
import pathlib
import yaml
import time
from typing import Dict, List, Optional

# importa módulos auxiliares do pkgtool
from pkgtool.config import Config
from pkgtool.logger import log, tail_log
from pkgtool.db import PackageDB
from pkgtool.fsutils import ensure_dir, safe_rmtree, download_file, extract_archive

class BuildError(Exception):
    pass


class Builder:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.load()
        self.db = PackageDB(self.config.db_path)

    # ---------------------------
    # Helpers
    # ---------------------------

    def _run(self, cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, logf=None):
        log.info(f"Exec: {' '.join(cmd)} (cwd={cwd})")
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env or os.environ.copy(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        with open(logf, "a") if logf else subprocess.DEVNULL as f:
            for line in proc.stdout:
                if logf:
                    f.write(line)
                log.stream(line.strip())
        proc.wait()
        if proc.returncode != 0:
            raise BuildError(f"Command failed: {' '.join(cmd)}")
          def load_meta(self, meta_path: str) -> Dict:
        with open(meta_path, "r") as f:
            meta = yaml.safe_load(f)
        if not meta:
            raise BuildError(f"Meta vazio: {meta_path}")
        return meta

    def fetch_source(self, meta: Dict, workdir: str):
        src = meta.get("source")
        if not src:
            raise BuildError("Nenhuma source no meta")
        if src.startswith("git+"):
            repo = src[4:]
            self._run(["git", "clone", "--depth=1", repo, "src"], cwd=workdir)
            return os.path.join(workdir, "src")
        elif src.startswith(("http://", "https://", "ftp://")):
            filename = os.path.join(workdir, os.path.basename(src))
            download_file(src, filename)
            extract_dir = os.path.join(workdir, "src")
            ensure_dir(extract_dir)
            extract_archive(filename, extract_dir)
            return extract_dir
        elif os.path.isdir(src):
            dst = os.path.join(workdir, "src")
            shutil.copytree(src, dst)
            return dst
        else:
            raise BuildError(f"Source não suportada: {src}")

    def apply_patches(self, meta: Dict, srcdir: str):
        patches = meta.get("patches", [])
        for patch in patches:
            patch_path = os.path.join(os.path.dirname(meta["__path__"]), patch)
            if not os.path.exists(patch_path):
                raise BuildError(f"Patch não encontrado: {patch_path}")
            log.info(f"Aplicando patch: {patch}")
            self._run(["patch", "-p1", "-i", patch_path], cwd=srcdir)

    def run_hooks(self, phase: str, meta: Dict, srcdir: str):
        hooks = meta.get("hooks", {})
        if phase in hooks:
            log.info(f"Hook inline {phase}")
            for cmd in hooks[phase]:
                self._run(cmd.split(), cwd=srcdir)
        # hooks via script
        hook_script = os.path.join(os.path.dirname(meta["__path__"]), "hooks", phase + ".sh")
        if os.path.exists(hook_script):
            log.info(f"Hook script {phase}")
            self._run(["bash", hook_script], cwd=srcdir)
          def build_system(self, meta: Dict, srcdir: str, builddir: str, destdir: str, logf: str):
        system = meta.get("build", {}).get("system", "autotools")
        env = os.environ.copy()
        env["DESTDIR"] = destdir

        if system == "autotools":
            self._run(["./configure", f"--prefix={self.config.prefix}"], cwd=srcdir, env=env, logf=logf)
            self._run(["make", "-j4"], cwd=srcdir, env=env, logf=logf)
            self._run(["make", "install"], cwd=srcdir, env=env, logf=logf)
        elif system == "cmake":
            ensure_dir(builddir)
            self._run(["cmake", f"-DCMAKE_INSTALL_PREFIX={self.config.prefix}", srcdir], cwd=builddir, env=env, logf=logf)
            self._run(["make", "-j4"], cwd=builddir, env=env, logf=logf)
            self._run(["make", "install"], cwd=builddir, env=env, logf=logf)
        elif system == "meson":
            ensure_dir(builddir)
            self._run(["meson", "setup", builddir, srcdir, f"--prefix={self.config.prefix}"], cwd=srcdir, env=env, logf=logf)
            self._run(["ninja", "-C", builddir], cwd=srcdir, env=env, logf=logf)
            self._run(["ninja", "-C", builddir, "install"], cwd=srcdir, env=env, logf=logf)
        elif system == "cargo":
            self._run(["cargo", "build", "--release"], cwd=srcdir, env=env, logf=logf)
            self._run(["cargo", "install", f"--root={destdir}{self.config.prefix}"], cwd=srcdir, env=env, logf=logf)
        elif system == "python":
            self._run([sys.executable, "setup.py", "install", f"--prefix={self.config.prefix}", f"--root={destdir}"], cwd=srcdir, env=env, logf=logf)
        else:
            raise BuildError(f"Sistema de build desconhecido: {system}")
          
          def package(self, meta: Dict, destdir: str, workdir: str) -> str:
        name = meta["name"]
        version = meta["version"]
        pkgfile = os.path.join(self.config.pkg_dir, f"{name}-{version}.pkg.tar.xz")
        ensure_dir(self.config.pkg_dir)
        with tarfile.open(pkgfile, "w:xz") as tar:
            tar.add(destdir, arcname="/")
            # inclui o meta
            tar.add(meta["__path__"], arcname=f".PKGINFO/{os.path.basename(meta['__path__'])}")
        log.success(f"Pacote criado: {pkgfile}")
        return pkgfile

    def install(self, pkgfile: str, meta: Dict):
        # aqui só simulação, em real usaria fakeroot + extrair em rootfs
        with tarfile.open(pkgfile, "r:xz") as tar:
            tar.extractall(self.config.rootfs)
        log.success(f"Instalado em {self.config.rootfs}")
        self.db.register(meta["name"], meta["version"], pkgfile)
      def build(self, meta_path: str):
        meta = self.load_meta(meta_path)
        meta["__path__"] = meta_path

        with tempfile.TemporaryDirectory() as tmp:
            logf = os.path.join(self.config.log_dir, f"{meta['name']}-{meta['version']}.log")
            ensure_dir(self.config.log_dir)

            srcdir = self.fetch_source(meta, tmp)
            self.apply_patches(meta, srcdir)
            self.run_hooks("pre_build", meta, srcdir)

            builddir = os.path.join(tmp, "build")
            destdir = os.path.join(tmp, "dest")
            ensure_dir(destdir)

            self.build_system(meta, srcdir, builddir, destdir, logf)

            self.run_hooks("post_build", meta, srcdir)

            pkgfile = self.package(meta, destdir, tmp)
            self.install(pkgfile, meta)

            self.run_hooks("post_install", meta, srcdir)

            log.success(f"Build de {meta['name']} {meta['version']} concluído.")


def main():
    import argparse
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser("build")
    b.add_argument("meta")

    args = p.parse_args()
    builder = Builder()
    if args.cmd == "build":
        builder.build(args.meta)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
