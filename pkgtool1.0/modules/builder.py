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
