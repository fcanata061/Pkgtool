# pkgtool/builder.py
"""
pkgtool.builder - builder robusto com hooks e sandbox

Funcionalidades principais:
 - Carrega meta YAML do port (procura em ports_dir)
 - Fases com hooks: pre_fetch, post_fetch, pre_patch, post_patch, pre_configure,
   post_configure, pre_build, post_build, pre_install, post_install, pre_package, post_package
 - Fetch: tarballs (http/https/ftp), git (with rev), local dirs
 - Patches: aplica patches (patch -pN), tenta git apply --3way como fallback
 - Autodetect de buildsystem: autotools, cmake, meson, cargo, python, make
 - Sandbox: usa bubblewrap (bwrap) quando disponível, fallback para execução direta com env controlado
 - Streaming de logs em tempo real, armazenamento em log_dir
 - Empacota destdir em .pkg.tar.xz (inclui .meta.yaml dentro do pacote)
 - CLI: build <meta|identifier> [--dry-run] [--keep-build] [--follow]
"""

from __future__ import annotations
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# YAML required
try:
    import yaml
except Exception as e:
    raise RuntimeError("PyYAML required (pip install pyyaml)") from e

# try to use rich for pretty console output (optional)
try:
    from rich.console import Console
    RICH = True
    CONSOLE = Console()
except Exception:
    RICH = False
    CONSOLE = None

# Try to import helper modules; if not present provide small fallbacks
def _fallback_load_config():
    return {
        "ports_dir": "/usr/ports/pkgtool",
        "build_root": "/var/tmp/pkgtool/builds",
        "destdir_root": "/var/tmp/pkgtool/dest",
        "package_store": "/var/pkgtool/packages",
        "cache_dir": "/var/cache/pkgtool",
        "log_dir": "/var/log/pkgtool",
        "default_jobs": 4,
        "prefix": "/usr",
        "toolchain_dir": "/opt/pkgtool/toolchains",
    }

try:
    from pkgtool.config import load_config, get_env
    from pkgtool.env import which, build_env, find_program
    from pkgtool.fsutils import download_url, ensure_dir, safe_rmtree, atomic_move
    from pkgtool.db import ToolDB
    from pkgtool.logger import Logger
    CFG = load_config()
    LOGGER = Logger("builder")
except Exception:
    CFG = _fallback_load_config()
    def which(n): return shutil.which(n)
    def find_program(n): return shutil.which(n)
    def build_env(extra=None):
        e = os.environ.copy()
        if extra:
            e.update(extra)
        return e
    def download_url(url, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, str(dest))
        return dest
    def ensure_dir(p: Path):
        p.mkdir(parents=True, exist_ok=True)
    def safe_rmtree(p: Path):
        try:
            if p.exists():
                shutil.rmtree(str(p))
        except Exception:
            pass
    def atomic_move(src: Path, dest: Path):
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.parent / (".pkgtool_tmp_move_" + str(int(time.time()*1000)))
        shutil.move(str(src), str(tmp))
        os.replace(str(tmp), str(dest))
    class ToolDB:
        def __init__(self, path=None):
            self.path = path or "/var/lib/pkgtool/pkgtool.db"
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            conn = self._conn(); cur = conn.cursor()
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS packages (id INTEGER PRIMARY KEY, name TEXT, version TEXT, pkg_path TEXT, meta_path TEXT, installed_at REAL);
            """); conn.commit(); conn.close()
        def _conn(self):
            import sqlite3
            return sqlite3.connect(self.path)
        def register_package(self, name, version, pkg_path, meta_path=None):
            conn = self._conn(); cur = conn.cursor()
            cur.execute("INSERT INTO packages (name,version,pkg_path,meta_path,installed_at) VALUES (?,?,?,?,?)",
                        (name, version, str(pkg_path), str(meta_path), time.time()))
            conn.commit(); conn.close()
    class Logger:
        def __init__(self, name="pkgtool"):
            self.name = name
            self.log_dir = Path(CFG.get("log_dir", "/var/log/pkgtool"))
            self.log_dir.mkdir(parents=True, exist_ok=True)
        def info(self,msg): print("[INFO]", msg)
        def warn(self,msg): print("[WARN]", msg)
        def error(self,msg): print("[ERROR]", msg)
        def success(self,msg): print("[OK]", msg)
    LOGGER = Logger("builder")

# constants from config
PORTS_DIR = Path(CFG.get("ports_dir", "/usr/ports/pkgtool"))
BUILD_ROOT = Path(CFG.get("build_root", "/var/tmp/pkgtool/builds"))
DESTDIR_ROOT = Path(CFG.get("destdir_root", "/var/tmp/pkgtool/dest"))
PACKAGE_STORE = Path(CFG.get("package_store", "/var/pkgtool/packages"))
CACHE_DIR = Path(CFG.get("cache_dir", "/var/cache/pkgtool"))
LOG_DIR = Path(CFG.get("log_dir", "/var/log/pkgtool"))
DEFAULT_JOBS = int(CFG.get("default_jobs", 4))
PREFIX = CFG.get("prefix", "/usr")
TOOLCHAIN_DIR = Path(CFG.get("toolchain_dir", "/opt/pkgtool/toolchains"))

for d in (BUILD_ROOT, DESTDIR_ROOT, PACKAGE_STORE, CACHE_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

@dataclass
class BuildResult:
    ok: bool
    message: str
    package_path: Optional[Path] = None
    log_path: Optional[Path] = None

class Builder:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.cfg = config or CFG
        self.ports_dir = Path(self.cfg.get("ports_dir", PORTS_DIR))
        self.build_root = Path(self.cfg.get("build_root", BUILD_ROOT))
        self.destdir_root = Path(self.cfg.get("destdir_root", DESTDIR_ROOT))
        self.package_store = Path(self.cfg.get("package_store", PACKAGE_STORE))
        self.cache_dir = Path(self.cfg.get("cache_dir", CACHE_DIR))
        self.log_dir = Path(self.cfg.get("log_dir", LOG_DIR))
        for p in (self.build_root, self.destdir_root, self.package_store, self.cache_dir, self.log_dir):
            p.mkdir(parents=True, exist_ok=True)
        self.db = ToolDB(self.cfg.get("db_path", None))
        self.bwrap = which("bwrap") is not None
        LOGGER.info(f"Builder ready. bwrap={'yes' if self.bwrap else 'no'}")

    # ---------------- meta helpers ----------------
    def find_meta(self, ident: str) -> Optional[Path]:
        p = Path(ident)
        if p.exists():
            return p
        # search under ports_dir for files matching *ident*.meta.yaml
        for f in self.ports_dir.rglob(f"*{ident}*.meta.yaml"):
            return f
        # try to find component dir
        cand = self.ports_dir / ident
        if cand.exists():
            for f in cand.rglob("*.meta.yaml"):
                return f
        return None

    def load_meta(self, meta_path: Path) -> Dict[str, Any]:
        data = yaml.safe_load(meta_path.read_text())
        if not isinstance(data, dict):
            raise RuntimeError("meta invalid")
        data.setdefault("build", {})
        data.setdefault("hooks", {})
        data.setdefault("patches", [])
        data["__meta_path"] = str(meta_path)
        return data

    # ---------------- fetch ----------------
    def _download_extract(self, url: str, dest: Path) -> Path:
        fname = url.split("/")[-1]
        cache = self.cache_dir / fname
        if not cache.exists():
            LOGGER.info(f"downloading {url} -> {cache}")
            download_url(url, cache)
        dest.mkdir(parents=True, exist_ok=True)
        LOGGER.info(f"extracting {cache} -> {dest}")
        with tarfile.open(str(cache), "r:*") as tf:
            tf.extractall(path=str(dest))
        # return single top dir if exists
        entries = [p for p in dest.iterdir() if p.is_dir()]
        if len(entries) == 1:
            return entries[0]
        return dest

    def fetch_source(self, meta: Dict[str, Any], workspace: Path) -> Path:
        src = meta.get("source")
        if not src:
            raise RuntimeError("meta.source missing")
        stype = src.get("type", "tar")
        if stype in ("tar", "archive", None):
            url = src.get("url")
            if not url:
                raise RuntimeError("source.url missing")
            return self._download_extract(url, workspace / "src")
        if stype == "git":
            url = src.get("url")
            rev = src.get("rev") or src.get("commit") or "HEAD"
            if not url:
                raise RuntimeError("source.url missing for git")
            dst = workspace / "src"
            LOGGER.info(f"git clone {url} -> {dst}")
            subprocess.check_call(["git", "clone", "--depth", "1", url, str(dst)])
            if rev and rev != "HEAD":
                subprocess.check_call(["git", "-C", str(dst), "fetch", "--all"])
                subprocess.check_call(["git", "-C", str(dst), "checkout", rev])
            return dst
        if stype in ("local", "directory"):
            path = Path(src.get("path"))
            if not path.exists():
                raise RuntimeError(f"local source path not found: {path}")
            dst = workspace / "src"
            shutil.copytree(str(path), str(dst))
            return dst
        raise RuntimeError(f"unsupported source.type: {stype}")

    # ---------------- patches ----------------
    def _apply_patch(self, srcdir: Path, patch_file: Path, strip: int = 1):
        if not patch_file.exists():
            raise RuntimeError(f"patch not found: {patch_file}")
        cmd = f"patch -p{strip} < '{patch_file}'"
        LOGGER.info(f"applying patch {patch_file} (strip={strip})")
        subprocess.check_call(cmd, shell=True, cwd=str(srcdir))

    def _git_apply_3way(self, srcdir: Path, patch_file: Path) -> bool:
        try:
            subprocess.check_call(["git", "-C", str(srcdir), "apply", "--index", "--3way", str(patch_file)])
            return True
        except subprocess.CalledProcessError:
            return False

    def apply_patches(self, meta: Dict[str, Any], srcdir: Path):
        patches = meta.get("patches", []) or []
        port_dir = Path(meta["__meta_path"]).parent
        for p in patches:
            strip = 1
            pfile = None
            if isinstance(p, str):
                pfile = p
            elif isinstance(p, dict):
                pfile = p.get("file")
                strip = p.get("strip", 1)
            else:
                raise RuntimeError("invalid patch entry")
            ppath = Path(pfile)
            if not ppath.exists():
                # try relative to port dir
                cand = port_dir / pfile
                if cand.exists():
                    ppath = cand
                else:
                    found = list(self.ports_dir.rglob(pfile))
                    if found:
                        ppath = found[0]
            if not ppath.exists():
                raise RuntimeError(f"patch file not found: {pfile}")
            # try git apply 3way if repo present
            if (srcdir / ".git").exists():
                ok = self._git_apply_3way(srcdir, ppath)
                if ok:
                    LOGGER.info(f"patched via git 3way: {ppath}")
                    continue
            # otherwise normal patch
            self._apply_patch(srcdir, ppath, strip)

    # ---------------- hooks ----------------
    def run_hook(self, meta: Dict[str, Any], hook: str, cwd: Path, env: Dict[str, str]):
        hooks = meta.get("hooks", {}) or {}
        inline = hooks.get(hook, [])
        for cmd in inline:
            LOGGER.info(f"[hook:{hook}] {cmd}")
            subprocess.check_call(cmd, shell=True, cwd=str(cwd), env=env)
        # script files in port dir
        port_dir = Path(meta["__meta_path"]).parent
        script1 = port_dir / "hooks" / hook
        script2 = port_dir / "scripts" / f"{hook}.sh"
        for s in (script1, script2):
            if s.exists() and os.access(str(s), os.X_OK):
                LOGGER.info(f"[hook:{hook}] running script {s}")
                subprocess.check_call([str(s)], cwd=str(cwd), env=env)

    # ---------------- buildsystem flows ----------------
    def _detect(self, srcdir: Path) -> str:
        if (srcdir / "meson.build").exists(): return "meson"
        if (srcdir / "CMakeLists.txt").exists(): return "cmake"
        if (srcdir / "configure").exists() or (srcdir / "autogen.sh").exists() or (srcdir / "configure.ac").exists(): return "autotools"
        if (srcdir / "Cargo.toml").exists(): return "cargo"
        if (srcdir / "pyproject.toml").exists() or (srcdir / "setup.py").exists(): return "python"
        if (srcdir / "Makefile").exists(): return "make"
        return "unknown"

    def _stream_cmd(self, cmd: List[str], cwd: Path, env: Dict[str,str], logfh):
        logfh.write("$ " + " ".join(cmd) + "\n"); logfh.flush()
        proc = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout
        for line in proc.stdout:
            logfh.write(line); logfh.flush()
            if RICH and CONSOLE:
                CONSOLE.print(line.rstrip())
            else:
                print(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)

    def _run_autotools(self, srcdir: Path, destdir: Path, meta: Dict[str,Any], env: Dict[str,str], logfh):
        if not (srcdir / "configure").exists():
            if (srcdir / "autogen.sh").exists():
                self._stream_cmd(["/bin/sh", "autogen.sh"], srcdir, env, logfh)
            else:
                raise RuntimeError("no configure/autogen found for autotools")
        cfg_flags = meta.get("build", {}).get("configure_flags", [])
        prefix = self.cfg.get("prefix", PREFIX)
        cmd = ["sh", "-c", f"./configure --prefix={prefix} {' '.join(cfg_flags)}"]
        self._stream_cmd(cmd, srcdir, env, logfh)
        jobs = str(self.cfg.get("default_jobs", DEFAULT_JOBS))
        self._stream_cmd(["make", f"-j{jobs}"], srcdir, env, logfh)
        self._stream_cmd(["make", "DESTDIR="+str(destdir), "install"], srcdir, env, logfh)

    def _run_cmake(self, srcdir: Path, destdir: Path, meta: Dict[str,Any], env: Dict[str,str], logfh):
        builddir = srcdir / "build"; builddir.mkdir(exist_ok=True)
        prefix = self.cfg.get("prefix", PREFIX)
        cmake_flags = meta.get("build", {}).get("cmake_flags", [])
        self._stream_cmd(["cmake", str(srcdir), f"-DCMAKE_INSTALL_PREFIX={prefix}"] + cmake_flags, builddir, env, logfh)
        jobs = str(self.cfg.get("default_jobs", DEFAULT_JOBS))
        self._stream_cmd(["cmake", "--build", ".", f"-j{jobs}"], builddir, env, logfh)
        env2 = dict(env); env2["DESTDIR"] = str(destdir)
        self._stream_cmd(["cmake", "--install", "."], builddir, env2, logfh)

    def _run_meson(self, srcdir: Path, destdir: Path, meta: Dict[str,Any], env: Dict[str,str], logfh):
        builddir = srcdir / "build"; builddir.mkdir(exist_ok=True)
        prefix = self.cfg.get("prefix", PREFIX)
        meson_opts = meta.get("build", {}).get("meson_options", [])
        self._stream_cmd(["meson", "setup", str(builddir), str(srcdir), f"--prefix={prefix}"] + meson_opts, srcdir, env, logfh)
        jobs = str(self.cfg.get("default_jobs", DEFAULT_JOBS))
        self._stream_cmd(["ninja", "-C", str(builddir), f"-j{jobs}"], srcdir, env, logfh)
        # meson install with DESTDIR
        self._stream_cmd(["ninja", "-C", str(builddir), "install", f"DESTDIR={str(destdir)}"], srcdir, env, logfh)

    def _run_cargo(self, srcdir: Path, destdir: Path, meta: Dict[str,Any], env: Dict[str,str], logfh):
        self._stream_cmd(["cargo", "build", "--release"], srcdir, env, logfh)
        target = srcdir / "target" / "release"
        bin_dir = destdir / "usr" / "bin"; bin_dir.mkdir(parents=True, exist_ok=True)
        if target.exists():
            for f in target.iterdir():
                if f.is_file() and os.access(str(f), os.X_OK):
                    shutil.copy2(str(f), str(bin_dir))

    def _run_python(self, srcdir: Path, destdir: Path, meta: Dict[str,Any], env: Dict[str,str], logfh):
        py = env.get("PYTHON", sys.executable)
        self._stream_cmd([py, "-m", "pip", "install", "--prefix", self.cfg.get("prefix", PREFIX), "--root", str(destdir), str(srcdir)], srcdir, env, logfh)

    def _run_make(self, srcdir: Path, destdir: Path, env: Dict[str,str], logfh):
        jobs = str(self.cfg.get("default_jobs", DEFAULT_JOBS))
        self._stream_cmd(["make", f"-j{jobs}"], srcdir, env, logfh)
        self._stream_cmd(["make", "DESTDIR="+str(destdir), "install"], srcdir, env, logfh)

    # ---------------- sandbox execution (used for shell steps) ----------------
    def _bwrap_cmd(self, shell_cmd: str) -> List[str]:
        cmd = ["bwrap", "--dev", "--proc", "/proc", "--unshare-pid"]
        # bind root readonly
        cmd += ["--ro-bind", "/", "/hostroot"]
        # bind tmp
        cmd += ["--bind", "/tmp", "/tmp"]
        # bind toolchain current if exists
        tc = Path(self.cfg.get("toolchain_dir", TOOLCHAIN_DIR)) / "current"
        if tc.exists():
            cmd += ["--bind", str(tc), "/toolchain/current"]
        cmd += ["/bin/sh", "-lc", shell_cmd]
        return cmd

    def _run_shell(self, shell_cmd: str, cwd: Path, env: Dict[str,str], logfh):
        if self.bwrap:
            cmd = self._bwrap_cmd(shell_cmd)
            proc = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        else:
            proc = subprocess.Popen(shell_cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True)
        assert proc.stdout
        for line in proc.stdout:
            logfh.write(line); logfh.flush()
            if RICH and CONSOLE:
                CONSOLE.print(line.rstrip())
            else:
                print(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, shell_cmd)

    # ---------------- packaging ----------------
    def package_destdir(self, destdir: Path, meta: Dict[str,Any]) -> Path:
        name = meta.get("name") or meta.get("package") or "pkg"
        version = str(meta.get("version", "0"))
        out = self.package_store / f"{name}-{version}.pkg.tar.xz"
        tmp = out.with_suffix(".tmp")
        ensure_dir(self.package_store)
        with tarfile.open(str(tmp), "w:xz") as tf:
            # include meta
            meta_bytes = yaml.safe_dump({k:v for k,v in meta.items() if k != "__meta_path"}).encode("utf-8")
            ti = tarfile.TarInfo(name=".meta.yaml"); ti.size = len(meta_bytes)
            tf.addfile(ti, io.BytesIO(meta_bytes))
            # files
            for p in destdir.rglob("*"):
                if p.is_file():
                    arc = str(p.relative_to(destdir))
                    tf.add(str(p), arcname=arc)
        atomic_move(tmp, out)
        LOGGER.info(f"package created: {out}")
        return out

    # ---------------- top-level build ----------------
    def build(self, meta_ident: str, dry_run: bool = False, keep_build: bool = True, follow: bool = False) -> BuildResult:
        meta_path = self.find_meta(meta_ident)
        if not meta_path:
            return BuildResult(False, f"meta not found for {meta_ident}")
        meta = self.load_meta(meta_path)
        name = meta.get("name") or meta.get("package") or meta_path.stem
        version = str(meta.get("version", "0"))
        ts = int(time.time())
        logpath = self.log_dir / f"build-{name}-{version}-{ts}.log"
        tmpdir = Path(tempfile.mkdtemp(prefix=f"pkgtool-build-{name}-{version}-", dir=str(self.build_root)))
        src_workspace = tmpdir / "src"
        destdir = tmpdir / "destdir"
        builddir = tmpdir / "build"
        for p in (src_workspace, destdir, builddir):
            p.mkdir(parents=True, exist_ok=True)
        logfh = open(str(logpath), "w", encoding="utf-8")
        try:
            LOGGER.info(f"Build start: {name} {version} workspace={tmpdir}")
            # FETCH
            try:
                self.run_hook(meta, "pre_fetch", tmpdir, build_env())
                srcdir = self.fetch_source(meta, tmpdir)
                self.run_hook(meta, "post_fetch", tmpdir, build_env())
            except Exception as e:
                LOGGER.error(f"fetch failed: {e}"); return BuildResult(False, f"fetch failed: {e}", log_path=logpath)

            # PATCHES
            try:
                self.run_hook(meta, "pre_patch", srcdir, build_env())
                self.apply_patches(meta, srcdir)
                self.run_hook(meta, "post_patch", srcdir, build_env())
            except Exception as e:
                LOGGER.error(f"patch failed: {e}"); return BuildResult(False, f"patch failed: {e}", log_path=logpath)

            # PRE CONFIGURE
            try:
                self.run_hook(meta, "pre_configure", srcdir, build_env())
            except Exception as e:
                LOGGER.warn(f"pre_configure hooks failed: {e}")

            # BUILD
            try:
                build_system = meta.get("build", {}).get("system") or self._detect(srcdir)
                LOGGER.info(f"Detected build system: {build_system}")
                env = build_env()
                # ensure DESTDIR env for steps that use it
                env["DESTDIR"] = str(destdir)
                if build_system == "autotools":
                    self._run_autotools(srcdir, destdir, meta, env, logfh)
                elif build_system == "cmake":
                    self._run_cmake(srcdir, destdir, meta, env, logfh)
                elif build_system == "meson":
                    self._run_meson(srcdir, destdir, meta, env, logfh)
                elif build_system == "cargo":
                    self._run_cargo(srcdir, destdir, meta, env, logfh)
                elif build_system == "python":
                    self._run_python(srcdir, destdir, meta, env, logfh)
                elif build_system == "make":
                    self._run_make(srcdir, destdir, env, logfh)
                else:
                    # custom steps possible
                    steps = meta.get("build", {}).get("steps", [])
                    if steps:
                        for s in steps:
                            self._run_shell(s, srcdir, env, logfh)
                    else:
                        raise RuntimeError("unknown build system and no steps provided")
            except subprocess.CalledProcessError as e:
                LOGGER.error(f"build failed: {e}"); return BuildResult(False, f"build failed: {e}", log_path=logpath)
            except Exception as e:
                LOGGER.error(f"build exception: {e}"); return BuildResult(False, f"build exception: {e}", log_path=logpath)

            # POST BUILD
            try:
                self.run_hook(meta, "post_build", srcdir, build_env())
            except Exception as e:
                LOGGER.warn(f"post_build hooks failed: {e}")

            # PACKAGE
            try:
                self.run_hook(meta, "pre_package", srcdir, build_env())
                pkg = self.package_destdir(destdir, meta)
                self.run_hook(meta, "post_package", srcdir, build_env())
            except Exception as e:
                LOGGER.error(f"package failed: {e}"); return BuildResult(False, f"package failed: {e}", log_path=logpath)

            # register
            try:
                self.db.register_package(name, version, str(pkg), str(meta_path))
            except Exception:
                pass

            LOGGER.success(f"Build OK: {name} {version}")
            if follow:
                # stream log file
                logfh.close()
                try:
                    with open(str(logpath), "r", encoding="utf-8") as f:
                        f.seek(0, os.SEEK_END)
                        try:
                            while True:
                                line = f.readline()
                                if not line:
                                    time.sleep(0.3); continue
                                print(line.rstrip())
                        except KeyboardInterrupt:
                            pass
                except Exception:
                    pass
            return BuildResult(True, "ok", package_path=pkg, log_path=logpath)
        finally:
            logfh.close()
            if not keep_build:
                safe_rmtree(tmpdir)
            else:
                LOGGER.info(f"workspace kept at {tmpdir}")

# CLI
def _cli():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-builder")
    p.add_argument("meta", help="meta path or identifier")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--keep-build", action="store_true")
    p.add_argument("--follow", action="store_true", help="follow log after build")
    args = p.parse_args()
    b = Builder()
    res = b.build(args.meta, dry_run=args.dry_run, keep_build=args.keep_build, follow=args.follow)
    if res.ok:
        print("BUILD OK:", res.message)
        if res.package_path: print("Package:", res.package_path)
        if res.log_path: print("Log:", res.log_path)
        sys.exit(0)
    else:
        print("BUILD FAILED:", res.message)
        if res.log_path: print("Log:", res.log_path)
        sys.exit(2)

if __name__ == "__main__":
    _cli()

# continuação de pkgtool/builder.py

    def _apply_patches(self, name: str, version: str, src_dir: Path, meta: Dict[str, Any]):
        """aplica patches listados no meta"""
        patches = meta.get("patches", [])
        for patch in patches:
            patch_path = Path(self.cfg["ports_dir"]) / name / version / patch
            if patch_path.exists():
                self.logger.info(f"Aplicando patch {patch_path}")
                subprocess.run(["patch", "-p1", "-i", str(patch_path)], cwd=src_dir, check=True)
            else:
                self.logger.warn(f"Patch {patch_path} não encontrado")

    def _run_hook(self, hook_type: str, name: str, version: str, cwd: Path, meta: Dict[str, Any]):
        """executa hook inline (meta) ou script externo"""
        # hook inline no YAML
        inline_cmds = meta.get("hooks", {}).get(hook_type, [])
        for cmd in inline_cmds:
            self.logger.info(f"Hook inline {hook_type}: {cmd}")
            subprocess.run(cmd, cwd=cwd, env=get_env(), shell=True, check=False)

        # hook script externo
        script = Path(self.cfg["ports_dir"]) / name / version / f"{hook_type}.sh"
        if script.exists():
            self.logger.info(f"Executando hook {script}")
            subprocess.run(["bash", str(script)], cwd=cwd, env=get_env(), check=False)

    def _build_with_system(self, system: str, src_dir: Path, build_dir: Path):
        """executa build dependendo do sistema"""
        env = get_env()
        if system == "autotools":
            subprocess.run(["./configure", f"--prefix=/usr"], cwd=src_dir, env=env, check=True)
            subprocess.run(["make", f"-j{self.cfg['default_jobs']}"], cwd=src_dir, env=env, check=True)
        elif system == "meson":
            subprocess.run(["meson", "setup", str(build_dir)], cwd=src_dir, env=env, check=True)
            subprocess.run(["ninja", "-C", str(build_dir)], cwd=src_dir, env=env, check=True)
        elif system == "cmake":
            subprocess.run(["cmake", "-B", str(build_dir), "-DCMAKE_INSTALL_PREFIX=/usr"], cwd=src_dir, env=env, check=True)
            subprocess.run(["cmake", "--build", str(build_dir), f"-j{self.cfg['default_jobs']}"], cwd=src_dir, env=env, check=True)
        elif system == "cargo":
            subprocess.run(["cargo", "build", "--release"], cwd=src_dir, env=env, check=True)
        else:
            self.logger.warn(f"Sistema de build '{system}' não suportado")

    def build(self, name: str, version: str, meta: Dict[str, Any]):
        """pipeline de construção completa"""
        src_url = meta.get("source")
        system = meta.get("buildsystem", "autotools")

        # criar dirs
        build_root = Path(self.cfg["build_root"]) / name / version
        src_dir = build_root / "src"
        build_dir = build_root / "build"
        build_root.mkdir(parents=True, exist_ok=True)
        src_dir.mkdir(parents=True, exist_ok=True)
        build_dir.mkdir(parents=True, exist_ok=True)

        # fetch + unpack
        self._fetch_source(src_url, src_dir)
        self._unpack_source(src_dir, build_root)

        # aplicar patches
        self._apply_patches(name, version, src_dir, meta)

        # hooks pre-build
        self._run_hook("pre-build", name, version, src_dir, meta)

        # build
        self._build_with_system(system, src_dir, build_dir)

        # hooks post-build
        self._run_hook("post-build", name, version, build_dir, meta)

        # instalação (fakeroot + pacote)
        self._run_hook("pre-install", name, version, build_dir, meta)
        installer = Installer()
        installer.install(name, version, build_dir)
        self._run_hook("post-install", name, version, build_dir, meta)

        self.logger.success(f"{name}-{version} construído e instalado com sucesso")

 # -------------------- PART C: Dep solver, rebuild-all, cleanup, CLI extras --------------------
# Cole a seguir dentro do mesmo arquivo pkgtool/builder.py (após a definição da classe Builder)
# e certifique-se de que a classe Builder acima contenha os métodos usados aqui:
#   find_meta, load_meta, build, package_destdir, db.register_package, run_hook, apply_patches, fetch_source

from collections import defaultdict, deque

# ---------- Dependency resolver (na classe Builder) ----------
def _normalize_dep_entry(raw):
    """Normaliza entradas de dependência:
       - strings -> name (ex: 'zlib' or 'zlib>=1.2')
       - dicts -> dict with keys name/version/ops
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        # keep raw string; separate version if present (very simple)
        if any(op in raw for op in [">=", "<=", "==", "~=", ">","<"]):
            # naive split: name followed by version constraint
            parts = raw.split()
            name = parts[0]
            ver = " ".join(parts[1:]) if len(parts) > 1 else "*"
            return {"name": name, "version": ver}
        return {"name": raw, "version": "*"}
    if isinstance(raw, dict):
        return {"name": raw.get("name"), "version": raw.get("version", "*")}
    return None

def _collect_all_metas(ports_dir: Path) -> Dict[str, List[Path]]:
    """Retorna um mapeamento name -> [meta_paths] encontradas sob ports_dir/base"""
    out = defaultdict(list)
    base = ports_dir / "base"
    if not base.exists():
        return out
    for meta_file in base.rglob("*.meta.yaml"):
        try:
            m = yaml.safe_load(meta_file.read_text()) or {}
            name = m.get("name") or m.get("package") or meta_file.stem
            out[name].append(meta_file)
        except Exception:
            continue
    return out

# Adiciona ao Builder como método
def resolve_build_deps(self, meta: Dict[str,Any], include_runtime: bool = False) -> List[Dict[str,str]]:
    """
    Retorna lista ordenada (nome,version) das dependências de build necessárias para este meta.
    - meta: dic carregado do meta.yaml
    - include_runtime: se True, inclui depends.run também
    NOTA: esta resolução é simples: usa metas encontradas em ports_dir/base
    e ignora constraints complexas (pega qualquer versão disponível).
    """
    deps_raw = []
    if meta.get("depends"):
        deps_raw.extend(meta.get("depends").get("build", []) or [])
        if include_runtime:
            deps_raw.extend(meta.get("depends").get("run", []) or [])
    # normalize
    deps = []
    for d in deps_raw:
        nde = _normalize_dep_entry(d)
        if nde:
            deps.append(nde)
    # map of available metas
    name_map = _collect_all_metas(self.ports_dir)
    resolved = []
    for d in deps:
        name = d.get("name")
        if not name:
            continue
        choices = name_map.get(name, [])
        if not choices:
            # not present in ports tree -> skip but warn
            LOGGER.warn(f"build-dep {name} not found in ports tree; skipping (you may need to provide it)")
            continue
        # choose first available meta (could be improved later to pick versioned)
        chosen_meta = choices[0]
        # load version from meta
        try:
            md = yaml.safe_load(chosen_meta.read_text()) or {}
            ver = str(md.get("version", "*"))
        except Exception:
            ver = "*"
        resolved.append({"name": name, "version": ver, "meta": str(chosen_meta)})
    # remove dupes preserving order
    seen = set(); uniq = []
    for r in resolved:
        key = (r["name"], r["version"])
        if key in seen:
            continue
        seen.add(key); uniq.append(r)
    return uniq

# Attach to Builder
setattr(Builder, "resolve_build_deps", _normalize_dep_entry)  # temporary pattern to place attribute before assignment
# now correctly assign actual function
setattr(Builder, "resolve_build_deps", resolve_build_deps)

# ---------- Ensure and build dependencies ----------
def ensure_build_deps(self, meta: Dict[str,Any], dry_run: bool = False, built: Optional[set] = None) -> Tuple[bool, List[Dict[str,str]]]:
    """
    Resolve and build dependencies recursively.
    Returns (ok, list of built items (dicts with name/version/meta)).
    Avoid rebuild of already-built items using 'built' set.
    """
    built = built or set()
    deps = self.resolve_build_deps(meta)
    built_list = []
    for dep in deps:
        key = f\"{dep['name']}@{dep['version']}\"
        if key in built:
            continue
        # attempt to build this dependency
        meta_path = Path(dep["meta"])
        try:
            submeta = self.load_meta(meta_path)
        except Exception as e:
            LOGGER.warn(f\"Failed to load meta for dep {dep['name']}: {e}\"); return (False, built_list)
        LOGGER.info(f\"Building dependency {dep['name']} {dep['version']}\")
        if dry_run:
            built.add(key); built_list.append(dep); continue
        # build recursively dependencies first
        ok, subbuilt = self.ensure_build_deps(submeta, dry_run=dry_run, built=built)
        if not ok:
            return (False, built_list)
        # call build; uses existing build() method
        try:
            res = self.build(str(meta_path), dry_run=dry_run, keep_build=True, follow=False)
            if not res.ok:
                LOGGER.error(f\"Failed to build dependency {dep['name']}: {res.message}\"); return (False, built_list)
            # register package if needed (builder already does)
            built.add(key); built_list.append(dep)
        except Exception as e:
            LOGGER.error(f\"Exception building dep {dep['name']}: {e}\"); return (False, built_list)
    return (True, built_list)

setattr(Builder, "ensure_build_deps", ensure_build_deps)

# ---------- Topological plan for full repo rebuild ----------
def plan_rebuild_all(self) -> Dict[str,Any]:
    """
    Scan ports/base and produce a naive topological order based on depends.build.
    Returns {'ok':True, 'plan': {'order':[name@ver,...], 'count':N}}
    """
    nodes = {}  # key->meta_path
    deps_map = {}
    base = self.ports_dir / "base"
    if not base.exists():
        return {"ok": False, "detail": f"ports base not found: {base}"}
    for meta_file in base.rglob("*.meta.yaml"):
        try:
            m = yaml.safe_load(meta_file.read_text()) or {}
            name = m.get("name") or m.get("package") or meta_file.stem
            ver = str(m.get("version","*"))
            key = f\"{name}@{ver}\"
            nodes[key] = meta_file
            deps = []
            for d in (m.get("depends",{}) or {}).get("build", []):
                nde = _normalize_dep_entry(d)
                if nde and nde.get("name"):
                    deps.append(nde["name"])
            deps_map[key] = deps
        except Exception:
            continue
    # build simple graph where edges from dep -> node
    in_deg = {k: 0 for k in nodes}
    graph = {k: set() for k in nodes}
    for k, deps in deps_map.items():
        for dep in deps:
            for cand in nodes:
                if cand.split("@")[0] == dep:
                    graph[cand].add(k)
                    in_deg[k] += 1
    queue = deque([k for k,v in in_deg.items() if v==0])
    order = []
    while queue:
        n = queue.popleft()
        order.append(n)
        for m in graph.get(n, []):
            in_deg[m] -= 1
            if in_deg[m] == 0:
                queue.append(m)
    remaining = [k for k,v in in_deg.items() if v>0]
    order.extend(remaining)
    return {"ok": True, "plan": {"order": order, "count": len(order)}}

setattr(Builder, "plan_rebuild_all", plan_rebuild_all)

# ---------- Execute rebuild plan ----------
def execute_rebuild_all(self, plan: Dict[str,Any], dry_run: bool = True, parallel: int = 1) -> Dict[str,Any]:
    """
    Execute the plan (order list of name@ver). Calls build for each item; if dry_run -> only report.
    """
    order = plan.get("order", [])
    results = []
    for key in order:
        name, _, ver = key.partition("@")
        # locate meta
        meta_path = self.find_meta(f\"{name}-{ver}\") or self.find_meta(name)
        if not meta_path:
            results.append({"pkg": key, "status": "missing-meta"}); continue
        if dry_run:
            results.append({"pkg": key, "status": "dry-run"})
            continue
        LOGGER.info(f\"Rebuilding {key}\")
        res = self.build(str(meta_path), dry_run=False, keep_build=False, follow=False)
        results.append({"pkg": key, "status": "ok" if res.ok else "failed", "detail": res.message})
        if not res.ok:
            LOGGER.error(f\"Failed rebuilding {key}: {res.message}\"); return {"ok": False, "results": results}
    return {"ok": True, "results": results}

setattr(Builder, "execute_rebuild_all", execute_rebuild_all)

# ---------- Cleanup helpers ----------
def clean_workspaces(self, older_than_hours: int = 24) -> Dict[str,Any]:
    """
    Remove build workspaces under build_root older than 'older_than_hours'.
    """
    cutoff = time.time() - older_than_hours * 3600
    removed = []
    for wd in self.build_root.iterdir():
        try:
            mtime = wd.stat().st_mtime
            if mtime < cutoff:
                safe_rmtree(wd)
                removed.append(str(wd))
        except Exception:
            continue
    return {"ok": True, "removed": removed}

setattr(Builder, "clean_workspaces", clean_workspaces)

def clean_cache(self) -> Dict[str,Any]:
    removed = []
    for f in self.cache_dir.iterdir():
        try:
            if f.is_file():
                f.unlink()
                removed.append(str(f))
            elif f.is_dir():
                safe_rmtree(f); removed.append(str(f))
        except Exception:
            continue
    return {"ok": True, "removed": removed}

setattr(Builder, "clean_cache", clean_cache)

# ---------- CLI: extend the existing CLI to include rebuild-all and clean ----------
# If the file already had a _cli() at bottom, you can replace/extend it — below is a safe extension:
def cli_extended():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-builder")
    sub = p.add_subparsers(dest="cmd")
    p_build = sub.add_parser("build", help="build a single meta or identifier")
    p_build.add_argument("meta")
    p_build.add_argument("--dry-run", action="store_true")
    p_build.add_argument("--keep-build", action="store_true")
    p_build.add_argument("--follow", action="store_true")
    p_deps = sub.add_parser("deps", help="resolve and optionally build build-deps for a meta")
    p_deps.add_argument("meta")
    p_deps.add_argument("--build", action="store_true", help="actually build deps")
    p_rebuild = sub.add_parser("rebuild-all", help="plan and rebuild entire ports base")
    p_rebuild.add_argument("--dry-run", action="store_true")
    p_rebuild.add_argument("--parallel", type=int, default=1)
    p_clean = sub.add_parser("clean", help="clean workspaces older than N hours")
    p_clean.add_argument("--hours", type=int, default=24)
    p_cache = sub.add_parser("clean-cache", help="remove cached tarballs")
    args = p.parse_args()
    b = Builder()
    if args.cmd == "build":
        res = b.build(args.meta, dry_run=args.dry_run, keep_build=args.keep_build, follow=args.follow)
        print(res)
        return
    if args.cmd == "deps":
        meta_path = b.find_meta(args.meta)
        if not meta_path:
            print("meta not found"); return
        meta = b.load_meta(meta_path)
        deps = b.resolve_build_deps(meta)
        print("Build deps:", deps)
        if args.build:
            ok, built = b.ensure_build_deps(meta, dry_run=False)
            print("built:", built)
        return
    if args.cmd == "rebuild-all":
        plan = b.plan_rebuild_all()["plan"]
        print("Plan count:", plan.get("count"))
        if args.dry_run:
            print("Dry-run plan, not executing"); return
        r = b.execute_rebuild_all(plan, dry_run=False, parallel=args.parallel)
        print(r); return
    if args.cmd == "clean":
        r = b.clean_workspaces(older_than_hours=args.hours)
        print(r); return
    if args.cmd == "clean-cache":
        r = b.clean_cache(); print(r); return
    p.print_help()

# Export cli_extended as entrypoint if desired
if __name__ == "__main__" and 'cli_extended_called' not in globals():
    cli_extended()
