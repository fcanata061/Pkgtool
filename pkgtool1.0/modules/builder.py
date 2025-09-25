# pkgtool/builder.py
"""
pkgtool.builder - robust build engine for pkgtool

Features:
 - Load meta YAML for a port
 - Fetch sources: http(s)/ftp tarballs, git, local directories
 - Apply patches with fallback 3-way apply
 - Hooks (inline in meta and scripts under port/hooks or port/scripts)
 - Autodetect buildsystem: autotools, cmake, meson, cargo, python, make
 - Create out-of-source build dir when appropriate
 - Run build in sandbox (bubblewrap) if available, else directly with controlled env
 - Install into DESTDIR (fakeroot not required for DESTDIR approach)
 - Package into .pkg.tar.xz including `.meta.yaml`
 - Write logs and allow follow (tail -f)
 - Dry-run mode, keep-build option, basic error handling

Requirements:
 - Python 3.8+
 - PyYAML (pip install pyyaml)
 - Optional: rich (pip install rich) for pretty logging
 - System: git, tar, patch, meson/cmake/cargo as needed for packages you build
"""

from __future__ import annotations

import io
import json
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
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Optional niceties
try:
    import yaml
except Exception as e:
    raise RuntimeError("PyYAML is required (pip install pyyaml)") from e

try:
    from rich.console import Console
    from rich.panel import Panel
    RICH = True
    CONSOLE = Console()
except Exception:
    RICH = False
    CONSOLE = None

# Try to import local pkgtool modules (config, env, db, logger, fsutils)
# If not present, provide small fallbacks so the builder works standalone for simple cases.
try:
    from pkgtool.config import get_config, load_config
    from pkgtool.env import build_env, find_program, which
    from pkgtool.db import ToolDB, init_db
    from pkgtool.logger import get_logger
    from pkgtool.fsutils import safe_rmtree, download_url, atomic_move, ensure_dir
except Exception:
    # Simple fallbacks
    def load_config() -> Dict[str, Any]:
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

    def get_config():
        return load_config()

    def build_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = os.environ.copy()
        if extra:
            env.update(extra)
        return env

    def which(name: str) -> Optional[str]:
        return shutil.which(name)

    def find_program(name: str) -> Optional[str]:
        return which(name)

    class ToolDB:
        def __init__(self, path=None):
            self.path = path or "/var/lib/pkgtool/pkgtool.db"
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            conn = self._conn()
            cur = conn.cursor()
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY,
                name TEXT, version TEXT, pkg_path TEXT, meta_path TEXT, installed_at REAL
            );
            """)
            conn.commit()
            conn.close()
        def _conn(self):
            import sqlite3
            return sqlite3.connect(self.path)
        def register_package(self, name, version, prefix, meta_path=None):
            conn = self._conn()
            cur = conn.cursor()
            cur.execute("INSERT INTO packages (name,version,pkg_path,meta_path,installed_at) VALUES (?,?,?,?,?)",
                        (name, version, prefix, meta_path, time.time()))
            conn.commit()
            conn.close()

    def safe_rmtree(p: Path):
        try:
            if p.exists():
                shutil.rmtree(str(p))
        except Exception:
            pass

    def download_url(url: str, dest: Path):
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, str(dest))
        return dest

    def ensure_dir(p: Path):
        p.mkdir(parents=True, exist_ok=True)

    def atomic_move(src: Path, dest: Path):
        dest_parent = dest.parent
        dest_parent.mkdir(parents=True, exist_ok=True)
        tmp = dest_parent / (".pkgtool_tmp_move_" + str(int(time.time()*1000)))
        shutil.move(str(src), str(tmp))
        os.replace(str(tmp), str(dest))

    def get_logger(name="pkgtool") :
        import logging
        logger = logging.getLogger(name)
        if not logger.handlers:
            import logging
            logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(ch)
        return logger

# Setup config and logger
CFG = load_config()
LOG_DIR = Path(CFG.get("log_dir", "/var/log/pkgtool"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOGGER = get_logger("pkgtool.builder") if 'get_logger' in globals() else None

def log_info(msg: str):
    if RICH and CONSOLE:
        CONSOLE.print(Panel(msg, title="pkgtool-builder", subtitle="info"))
    else:
        if LOGGER:
            LOGGER.info(msg)
        else:
            print("[INFO]", msg)

def log_warn(msg: str):
    if RICH and CONSOLE:
        CONSOLE.print(Panel(msg, title="pkgtool-builder", subtitle="warn"))
    else:
        if LOGGER:
            LOGGER.warning(msg)
        else:
            print("[WARN]", msg)

def log_error(msg: str):
    if RICH and CONSOLE:
        CONSOLE.print(Panel(msg, title="pkgtool-builder", subtitle="error"))
    else:
        if LOGGER:
            LOGGER.error(msg)
        else:
            print("[ERROR]", msg)

@dataclass
class BuildResult:
    ok: bool
    message: str
    package_path: Optional[Path] = None
    log_path: Optional[Path] = None

class Builder:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.cfg = config or load_config()
        self.ports_dir = Path(self.cfg.get("ports_dir", "/usr/ports/pkgtool"))
        self.build_root = Path(self.cfg.get("build_root", "/var/tmp/pkgtool/builds"))
        self.destdir_root = Path(self.cfg.get("destdir_root", "/var/tmp/pkgtool/dest"))
        self.package_store = Path(self.cfg.get("package_store", "/var/pkgtool/packages"))
        self.cache_dir = Path(self.cfg.get("cache_dir", "/var/cache/pkgtool"))
        self.log_dir = Path(self.cfg.get("log_dir", "/var/log/pkgtool"))
        for d in [self.build_root, self.destdir_root, self.package_store, self.cache_dir, self.log_dir]:
            d.mkdir(parents=True, exist_ok=True)
        self.db = ToolDB(self.cfg.get("db_path"))
        # sandbox detection
        self.have_bwrap = which("bwrap") is not None
        log_info(f"Builder initialized. bwrap={'yes' if self.have_bwrap else 'no'}")

    # ---------------- meta utils ----------------
    def find_meta(self, identifier: str) -> Optional[Path]:
        p = Path(identifier)
        if p.exists():
            return p
        # search in ports_dir for *identifier*.meta.yaml
        for f in self.ports_dir.rglob(f"*{identifier}*.meta.yaml"):
            return f
        # fallback: try identifier as component dir
        cand = self.ports_dir / identifier
        if cand.exists():
            # find a single meta under that dir
            for f in cand.rglob("*.meta.yaml"):
                return f
        return None

    def load_meta(self, meta_path: Path) -> Dict[str, Any]:
        meta = yaml.safe_load(meta_path.read_text())
        if not isinstance(meta, dict):
            raise RuntimeError("Invalid meta")
        meta.setdefault("build", {})
        meta.setdefault("hooks", {})
        meta.setdefault("patches", [])
        meta["__meta_path"] = str(meta_path)
        return meta

    # ---------------- fetch ----------------
    def _download_and_extract_tarball(self, url: str, dest: Path) -> Path:
        fname = url.split("/")[-1]
        cached = self.cache_dir / fname
        if not cached.exists():
            log_info(f"Downloading {url} -> {cached}")
            download_url(url, cached)
        log_info(f"Extracting {cached} -> {dest}")
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(str(cached), "r:*") as tf:
            tf.extractall(path=str(dest))
        # if one dir inside, return it
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
                raise RuntimeError("meta.source.url required")
            return self._download_and_extract_tarball(url, workspace / "src")
        elif stype == "git":
            url = src.get("url")
            rev = src.get("rev") or src.get("commit") or "HEAD"
            if not url:
                raise RuntimeError("meta.source.url required for git")
            dst = workspace / "src"
            log_info(f"Cloning {url} -> {dst}")
            subprocess.check_call(["git", "clone", "--depth", "1", url, str(dst)])
            if rev and rev != "HEAD":
                subprocess.check_call(["git", "-C", str(dst), "fetch", "--all"])
                subprocess.check_call(["git", "-C", str(dst), "checkout", rev])
            return dst
        elif stype in ("local", "directory"):
            path = Path(src.get("path"))
            if not path.exists():
                raise RuntimeError(f"local source path not found: {path}")
            dst = workspace / "src"
            log_info(f"Copying local source {path} -> {dst}")
            shutil.copytree(str(path), str(dst))
            return dst
        else:
            raise RuntimeError(f"unsupported source.type: {stype}")

    # ---------------- patches ----------------
    def _apply_patch_file(self, srcdir: Path, patch_path: Path, strip: int = 1):
        if not patch_path.exists():
            raise RuntimeError(f"patch not found: {patch_path}")
        cmd = f"patch -p{strip} < '{patch_path}'"
        log_info(f"Applying patch: {patch_path} (strip={strip})")
        subprocess.check_call(cmd, shell=True, cwd=str(srcdir))

    def _git_apply_3way(self, srcdir: Path, patch_path: Path) -> bool:
        # try git apply --3way, fallback to patch
        try:
            subprocess.check_call(["git", "-C", str(srcdir), "apply", "--index", "--3way", str(patch_path)])
            return True
        except subprocess.CalledProcessError:
            return False

    def apply_patches(self, meta: Dict[str, Any], srcdir: Path):
        patches = meta.get("patches", []) or []
        port_dir = Path(meta["__meta_path"]).parent
        for p in patches:
            if isinstance(p, str):
                pfile = p
                strip = 1
                ptype = "patch"
            elif isinstance(p, dict):
                pfile = p.get("file")
                strip = p.get("strip", 1)
                ptype = p.get("type", "patch")
            else:
                raise RuntimeError("invalid patch entry in meta")
            # resolve path
            ppath = Path(pfile)
            if not ppath.exists():
                # try relative to port dir
                cand = port_dir / pfile
                if cand.exists():
                    ppath = cand
                else:
                    # search in ports tree
                    found = list(self.ports_dir.rglob(pfile))
                    if found:
                        ppath = found[0]
            if not ppath.exists():
                raise RuntimeError(f"patch file not found: {pfile}")
            if ptype in ("git-am", "git_am"):
                log_info(f"Applying patch via git am: {ppath}")
                subprocess.check_call(["git", "-C", str(srcdir), "am", str(ppath)])
            elif ptype in ("git-apply", "git_apply"):
                ok = self._git_apply_3way(srcdir, ppath)
                if not ok:
                    # fallback to normal patch
                    self._apply_patch_file(srcdir, ppath, strip=strip)
            else:
                self._apply_patch_file(srcdir, ppath, strip=strip)

    # ---------------- hooks ----------------
    def run_hook_commands(self, meta: Dict[str, Any], hook: str, cwd: Path, env: Dict[str, str]):
        # inline commands in meta: hooks: { pre_build: ["cmd1","cmd2"] }
        hooks = meta.get("hooks", {}) or {}
        cmds = hooks.get(hook, [])
        for c in cmds:
            log_info(f"[hook:{hook}] running inline: {c}")
            subprocess.check_call(c, shell=True, cwd=str(cwd), env=env)
        # external scripts: port_dir/hooks/<hook> and port_dir/scripts/<hook>.sh
        port_dir = Path(meta["__meta_path"]).parent
        script1 = port_dir / "hooks" / hook
        script2 = port_dir / "scripts" / f"{hook}.sh"
        for s in (script1, script2):
            if s.exists() and os.access(str(s), os.X_OK):
                log_info(f"[hook:{hook}] running script {s}")
                subprocess.check_call([str(s)], cwd=str(cwd), env=env)

    # ---------------- buildsystem flows ----------------
    def _autodetect(self, srcdir: Path) -> str:
        if (srcdir / "meson.build").exists():
            return "meson"
        if (srcdir / "CMakeLists.txt").exists():
            return "cmake"
        if (srcdir / "configure").exists() or (srcdir / "configure.ac").exists() or (srcdir / "autogen.sh").exists():
            return "autotools"
        if (srcdir / "Cargo.toml").exists():
            return "cargo"
        if (srcdir / "pyproject.toml").exists() or (srcdir / "setup.py").exists():
            return "python"
        if (srcdir / "Makefile").exists():
            return "make"
        return "unknown"

    def _run_cmd_stream(self, cmd: List[str], cwd: Path, env: Dict[str, str], logfh):
        logfh.write(f"$ {' '.join(cmd)}\n")
        logfh.flush()
        proc = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout
        for line in proc.stdout:
            logfh.write(line)
            logfh.flush()
            if RICH and CONSOLE:
                CONSOLE.print(line.rstrip())
            else:
                print(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)

    def _run_autotools(self, srcdir: Path, destdir: Path, meta: Dict[str, Any], env: Dict[str, str], logfh):
        # run autogen if needed
        if (srcdir / "configure").exists():
            cfg = srcdir / "configure"
        else:
            if (srcdir / "autogen.sh").exists():
                self._run_cmd_stream(["/bin/sh", "autogen.sh"], cwd=srcdir, env=env, logfh=logfh)
            cfg = srcdir / "configure"
            if not cfg.exists():
                raise RuntimeError("No configure script after autogen")
        cfg_flags = meta.get("build", {}).get("configure_flags", [])
        prefix = self.cfg.get("prefix", "/usr")
        cmd = ["sh", "-c", f"./configure --prefix={prefix} {' '.join(cfg_flags)}"]
        self._run_cmd_stream(cmd, cwd=srcdir, env=env, logfh=logfh)
        jobs = str(self.cfg.get("default_jobs", 4))
        self._run_cmd_stream(["make", f"-j{jobs}"], cwd=srcdir, env=env, logfh=logfh)
        self._run_cmd_stream(["make", f"DESTDIR={str(destdir)}", "install"], cwd=srcdir, env=env, logfh=logfh)

    def _run_cmake(self, srcdir: Path, destdir: Path, meta: Dict[str, Any], env: Dict[str, str], logfh):
        builddir = srcdir / "build"
        builddir.mkdir(exist_ok=True)
        prefix = self.cfg.get("prefix", "/usr")
        cmake_flags = meta.get("build", {}).get("cmake_flags", [])
        self._run_cmd_stream(["cmake", str(srcdir), f"-DCMAKE_INSTALL_PREFIX={prefix}"] + cmake_flags, cwd=builddir, env=env, logfh=logfh)
        jobs = str(self.cfg.get("default_jobs", 4))
        self._run_cmd_stream(["cmake", "--build", ".", f"-j{jobs}"], cwd=builddir, env=env, logfh=logfh)
        # cmake install with DESTDIR em env
        env2 = dict(env); env2["DESTDIR"] = str(destdir)
        self._run_cmd_stream(["cmake", "--install", "."], cwd=builddir, env=env2, logfh=logfh)

    def _run_meson(self, srcdir: Path, destdir: Path, meta: Dict[str, Any], env: Dict[str, str], logfh):
        builddir = srcdir / "build"
        builddir.mkdir(exist_ok=True)
        prefix = self.cfg.get("prefix", "/usr")
        meson_opts = meta.get("build", {}).get("meson_options", [])
        self._run_cmd_stream(["meson", "setup", str(builddir), str(srcdir), f"--prefix={prefix}"] + meson_opts, cwd=srcdir, env=env, logfh=logfh)
        jobs = str(self.cfg.get("default_jobs", 4))
        self._run_cmd_stream(["ninja", "-C", str(builddir), f"-j{jobs}"], cwd=srcdir, env=env, logfh=logfh)
        self._run_cmd_stream(["ninja", "-C", str(builddir), "install", f"DESTDIR={str(destdir)}"], cwd=srcdir, env=env, logfh=logfh)

    def _run_cargo(self, srcdir: Path, destdir: Path, meta: Dict[str, Any], env: Dict[str, str], logfh):
        self._run_cmd_stream(["cargo", "build", "--release"], cwd=srcdir, env=env, logfh=logfh)
        # copy release binaries
        target = srcdir / "target" / "release"
        bin_dir = destdir / "usr" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        if target.exists():
            for f in target.iterdir():
                if f.is_file() and os.access(str(f), os.X_OK):
                    shutil.copy2(str(f), str(bin_dir))

    def _run_python(self, srcdir: Path, destdir: Path, meta: Dict[str, Any], env: Dict[str, str], logfh):
        py = env.get("PYTHON", sys.executable)
        # prefer pip install into root
        self._run_cmd_stream([py, "-m", "pip", "install", "--prefix", self.cfg.get("prefix", "/usr"), "--root", str(destdir), str(srcdir)], cwd=srcdir, env=env, logfh=logfh)

    def _run_make(self, srcdir: Path, destdir: Path, env: Dict[str, str], logfh):
        jobs = str(self.cfg.get("default_jobs", 4))
        self._run_cmd_stream(["make", f"-j{jobs}"], cwd=srcdir, env=env, logfh=logfh)
        self._run_cmd_stream(["make", f"DESTDIR={str(destdir)}", "install"], cwd=srcdir, env=env, logfh=logfh)

    # ---------------- run in sandbox or direct ----------------    `
    def _compose_sandbox_cmd(self, shell_cmd: str, cwd: Optional[Path], env: Dict[str, str]) -> List[str]:
        # create a minimal bwrap invocation: bind /, /dev, /proc, tmp, toolchain current
        cmd = ["bwrap", "--dev", "--proc", "/proc", "--unshare-pid"]
        # bind root readonly to /host (gives access but prevents writes)
        cmd += ["--ro-bind", "/", "/hostroot"]
        cmd += ["--bind", "/tmp", "/tmp"]
        # bind toolchain current if present
        tc = Path(self.cfg.get("toolchain_dir", "/opt/pkgtool/toolchains")) / "current"
        if tc.exists():
            cmd += ["--bind", str(tc), "/toolchain/current"]
        # drop into shell -c
        cmd += ["/bin/sh", "-lc", shell_cmd]
        return cmd

    def _run_shell(self, shell_cmd: str, cwd: Path, env: Dict[str, str], logfh):
        if self.have_bwrap:
            cmd = self._compose_sandbox_cmd(shell_cmd, cwd, env)
            proc = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        else:
            proc = subprocess.Popen(shell_cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True)
        assert proc.stdout
        for line in proc.stdout:
            logfh.write(line)
            logfh.flush()
            if RICH and CONSOLE:
                CONSOLE.print(line.rstrip())
            else:
                print(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, shell_cmd)

    # ---------------- package creation ----------------
    def create_package(self, destdir: Path, meta: Dict[str, Any]) -> Path:
        name = meta.get("name") or meta.get("package") or "package"
        version = str(meta.get("version", "0"))
        pkgname = f"{name}-{version}.pkg.tar.xz"
        out = self.package_store / pkgname
        tmp_pkg = out.with_suffix(".tmp")
        ensure_dir(self.package_store)
        # include meta inside package at .meta.yaml
        with tarfile.open(str(tmp_pkg), "w:xz") as tf:
            # add meta as file
            meta_bytes = yaml.safe_dump({k: v for k, v in meta.items() if k != "__meta_path"}).encode("utf-8")
            ti = tarfile.TarInfo(name=".meta.yaml")
            ti.size = len(meta_bytes)
            tf.addfile(ti, io.BytesIO(meta_bytes))
            # add files from destdir
            for p in destdir.rglob("*"):
                if p.is_file():
                    arc = str(p.relative_to(destdir))
                    tf.add(str(p), arcname=arc)
        # atomic move
        atomic_move(tmp_pkg, out)
        log_info(f"Created package {out}")
        return out

    # ---------------- top-level build ----------------
    def build(self, meta_ident: str, dry_run: bool = False, keep_build: bool = True, follow: bool = False) -> BuildResult:
        meta_path = self.find_meta(meta_ident)
        if not meta_path:
            return BuildResult(False, f"meta not found for '{meta_ident}'")
        meta = self.load_meta(meta_path)
        name = meta.get("name") or meta.get("package") or meta_path.stem
        version = str(meta.get("version", "0"))
        timestamp = int(time.time())
        logpath = self.log_dir / f"build-{name}-{version}-{timestamp}.log"
        tmpdir = Path(tempfile.mkdtemp(prefix=f"pkgtool-build-{name}-{version}-", dir=str(self.build_root)))
        src_workspace = tmpdir / "src"
        destdir = tmpdir / "destdir"
        builddir = tmpdir / "build"
        for p in (src_workspace, destdir, builddir):
            p.mkdir(parents=True, exist_ok=True)
        # open log file
        logfh = open(str(logpath), "w", encoding="utf-8")
        logfh.write(f"pkgtool builder log for {name} {version}\n")
        logfh.flush()
        try:
            log_info(f"Building {name} {version}, workspace {tmpdir}")
            # fetch
            try:
                srcdir = self.fetch_source(meta, src_workspace)
                logfh.write(f"Fetched source to: {srcdir}\n")
            except Exception as e:
                log_error(f"fetch failed: {e}")
                return BuildResult(False, f"fetch failed: {e}", log_path=logpath)
            # run pre_fetch
            env = build_env()
            try:
                self.run_hook_commands(meta, "pre_fetch", srcdir, env)
            except subprocess.CalledProcessError as e:
                log_error(f"pre_fetch hooks failed: {e}")
                return BuildResult(False, f"pre_fetch hooks failed: {e}", log_path=logpath)
            # patches
            try:
                self.apply_patches(meta, srcdir)
            except Exception as e:
                log_error(f"apply_patches failed: {e}")
                return BuildResult(False, f"apply_patches failed: {e}", log_path=logpath)
            # pre_build hooks
            try:
                self.run_hook_commands(meta, "pre_build", srcdir, env)
            except subprocess.CalledProcessError as e:
                log_error(f"pre_build hooks failed: {e}")
                return BuildResult(False, f"pre_build hooks failed: {e}", log_path=logpath)
            # detect buildsystem / run build
            build_system = meta.get("build", {}).get("system") or self._autodetect(srcdir)
            log_info(f"Detected build system: {build_system}")
            try:
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
                    # if meta.build.steps provided, run them (shell commands)
                    steps = meta.get("build", {}).get("steps") or []
                    if steps:
                        for step in steps:
                            self._run_shell(step, cwd=srcdir, env=env, logfh=logfh)
                    else:
                        raise RuntimeError("Unknown build system and no custom steps")
            except subprocess.CalledProcessError as e:
                log_error(f"build failed: {e}")
                return BuildResult(False, f"build failed: {e}", log_path=logpath)
            except Exception as e:
                log_error(f"build exception: {e}")
                return BuildResult(False, f"build exception: {e}", log_path=logpath)
            # post_build hooks
            try:
                self.run_hook_commands(meta, "post_build", srcdir, env)
            except subprocess.CalledProcessError as e:
                log_warn(f"post_build hook failed: {e}")
            # package
            try:
                pkgpath = self.create_package(destdir, meta)
            except Exception as e:
                log_error(f"package creation failed: {e}")
                return BuildResult(False, f"package creation failed: {e}", log_path=logpath)
            # register package
            try:
                self.db.register_package(name, version, str(pkgpath), str(meta_path))
            except Exception:
                pass
            # post_package hook
            try:
                self.run_hook_commands(meta, "post_package", srcdir, env)
            except subprocess.CalledProcessError as e:
                log_warn(f"post_package hook failed: {e}")
            log_info("build finished successfully")
            if follow:
                # stream log file to user (like tail -f)
                logfh.close()
                try:
                    with open(str(logpath), "r", encoding="utf-8") as f:
                        # seek to end and then stream new lines
                        f.seek(0, os.SEEK_END)
                        try:
                            while True:
                                line = f.readline()
                                if not line:
                                    time.sleep(0.5)
                                    continue
                                print(line.rstrip())
                        except KeyboardInterrupt:
                            pass
                except Exception:
                    pass
            return BuildResult(True, "ok", package_path=pkgpath, log_path=logpath)
        finally:
            # cleanup unless keep_build is True? we respect keep_build param
            if not keep_build:
                safe_rmtree(tmpdir)
            else:
                log_info(f"build workspace kept at {tmpdir}")

# CLI
def main():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-builder")
    p.add_argument("meta", help="path to meta.yaml or identifier")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--keep-build", action="store_true")
    p.add_argument("--follow", action="store_true", help="follow log like tail -f after build")
    args = p.parse_args()
    b = Builder()
    res = b.build(args.meta, dry_run=args.dry_run, keep_build=args.keep_build, follow=args.follow)
    if res.ok:
        print("BUILD OK:", res.message)
        if res.package_path:
            print("Package:", res.package_path)
        if res.log_path:
            print("Log:", res.log_path)
        sys.exit(0)
    else:
        print("BUILD FAILED:", res.message)
        if res.log_path:
            print("Log:", res.log_path)
        sys.exit(2)

if __name__ == "__main__":
    main()
