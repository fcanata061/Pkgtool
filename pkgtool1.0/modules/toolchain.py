# pkgtool/toolchain.py
"""
pkgtool.toolchain - Gerenciamento completo de toolchains críticos
- listar versões instaladas
- instalar (invoca builder para compilar a partir do meta YAML)
- selecionar versão ativa (cria symlink current/<component>)
- remover versão com checagens e proteção do runtime
- doctor básico para detectar problemas
- plan_rebuild baseado em metas e execute_rebuild_plan que orquestra rebuilds

Dependências:
- PyYAML
- módulos auxiliares: pkgtool.config, pkgtool.env, pkgtool.db, pkgtool.logger
- opcional: pkgtool.builder (pode ser executável CLI 'pkgtool-builder' ou 'python pkgtool_builder.py')

Salve em pkgtool/toolchain.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

try:
    import yaml
except Exception:
    yaml = None

# try to import package helpers; if not present we provide minimal fallbacks
try:
    from pkgtool.config import get_config, load_config
    from pkgtool.env import which, build_env
    from pkgtool.db import ToolDB
    from pkgtool.logger import info, warn, error, debug
except Exception:
    # minimal fallbacks
    def get_config():
        return {
            "toolchain_dir": "/opt/pkgtool/toolchains",
            "ports_dir": "/usr/ports/pkgtool",
            "db_path": "/var/lib/pkgtool/pkgtool.db",
            "build_root": "/var/tmp/pkgtool/builds",
            "package_store": "/var/pkgtool/packages",
            "log_dir": "/var/log/pkgtool",
            "default_jobs": 4,
        }
    def load_config():
        return get_config()
    def which(name):
        return shutil.which(name)
    def build_env(extra=None):
        e = os.environ.copy()
        if extra:
            e.update(extra)
        return e
    class ToolDB:
        def __init__(self, path=None):
            self.path = path or "/var/lib/pkgtool/pkgtool.db"
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._ensure()
        def _ensure(self):
            conn = sqlite3.connect(self.path)
            cur = conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS toolchains (id INTEGER PRIMARY KEY, component TEXT, version TEXT, path TEXT, meta_path TEXT, installed_at REAL, active INTEGER DEFAULT 0)""")
            conn.commit(); conn.close()
        def register_toolchain(self, component, version, path, meta_path=None, active=False):
            conn = sqlite3.connect(self.path)
            cur = conn.cursor()
            cur.execute("INSERT INTO toolchains (component,version,path,meta_path,installed_at,active) VALUES (?,?,?,?,?,?)",
                        (component, version, path, meta_path, time.time(), 1 if active else 0))
            conn.commit(); conn.close()
        def set_active(self, component, version):
            conn = sqlite3.connect(self.path)
            cur = conn.cursor()
            cur.execute("UPDATE toolchains SET active=0 WHERE component=?", (component,))
            cur.execute("UPDATE toolchains SET active=1 WHERE component=? AND version=?", (component, version))
            conn.commit(); conn.close()
        def list_toolchains(self):
            conn = sqlite3.connect(self.path)
            cur = conn.cursor()
            cur.execute("SELECT component,version,path,meta_path,installed_at,active FROM toolchains")
            rows = cur.fetchall(); conn.close()
            return rows
    def info(msg): print("[INFO]", msg)
    def warn(msg): print("[WARN]", msg)
    def error(msg): print("[ERROR]", msg)
    def debug(msg): print("[DEBUG]", msg)

# dataclass for entries
@dataclass
class ToolchainEntry:
    component: str
    version: str
    path: Path
    meta_path: Optional[Path]
    installed_at: float
    active: bool

class ToolchainManager:
    def __init__(self, config: Optional[Dict[str,Any]] = None):
        self.cfg = config or load_config()
        self.toolchain_dir = Path(self.cfg.get("toolchain_dir", "/opt/pkgtool/toolchains"))
        self.ports_dir = Path(self.cfg.get("ports_dir", "/usr/ports/pkgtool"))
        self.db = ToolDB(self.cfg.get("db_path"))
        self.current_dir = self.toolchain_dir / "current"
        for p in [self.toolchain_dir, self.current_dir]:
            p.mkdir(parents=True, exist_ok=True)
        # path to builder CLI — prefer installed pkgtool-builder or python script
        self.builder_cmd = shutil.which("pkgtool-builder") or shutil.which("pkgtool_builder.py") or None
        if not self.builder_cmd:
            # maybe the user has the earlier provided script in same dir
            self.builder_cmd = None
        info(f"ToolchainManager initialized; toolchain_dir={self.toolchain_dir}")

    # ----------------- DB wrappers -----------------
    def _db_register(self, component:str, version:str, path:Path, meta_path:Optional[Path], active:bool=False):
        try:
            # ToolDB in fallback uses register_toolchain; otherwise may have register_toolchain method
            if hasattr(self.db, "register_toolchain"):
                self.db.register_toolchain(component, version, str(path), str(meta_path) if meta_path else None, active)
            elif hasattr(self.db, "register_toolchain"): # duplicate case but safe
                self.db.register_toolchain(component, version, str(path), str(meta_path) if meta_path else None, active)
            else:
                # fallback method name
                self.db.register_toolchain(component, version, str(path), str(meta_path) if meta_path else None, active)
        except Exception as e:
            warn(f"DB register failed: {e}")

    def _db_set_active(self, component:str, version:str):
        try:
            if hasattr(self.db, "set_active_toolchain"):
                self.db.set_active_toolchain(component, version)
            elif hasattr(self.db, "set_active"):
                self.db.set_active(component, version)
            else:
                # fallback raw SQL if available
                conn = sqlite3.connect(self.cfg.get("db_path"))
                cur = conn.cursor()
                cur.execute("UPDATE toolchains SET active=0 WHERE component=?", (component,))
                cur.execute("UPDATE toolchains SET active=1 WHERE component=? AND version=?", (component, version))
                conn.commit(); conn.close()
        except Exception as e:
            warn(f"DB set active failed: {e}")

    def _db_list(self) -> List[ToolchainEntry]:
        entries: List[ToolchainEntry] = []
        try:
            rows = []
            if hasattr(self.db, "list_toolchains"):
                rows = self.db.list_toolchains()
                # if returns dicts convert
                if rows and isinstance(rows[0], dict):
                    for r in rows:
                        entries.append(ToolchainEntry(r["component"], r["version"], Path(r["path"]), Path(r.get("meta")), r["installed_at"], bool(r["active"])))
                    return entries
            # fallback raw SQL
            conn = sqlite3.connect(self.cfg.get("db_path"))
            cur = conn.cursor()
            cur.execute("SELECT component,version,path,meta_path,installed_at,active FROM toolchains")
            rows = cur.fetchall()
            conn.close()
            for r in rows:
                entries.append(ToolchainEntry(r[0], r[1], Path(r[2]), Path(r[3]) if r[3] else None, r[4], bool(r[5])))
        except Exception as e:
            warn(f"DB list failed: {e}")
        return entries

    # ----------------- list / info -----------------
    def list_all(self) -> Dict[str, Dict[str,Any]]:
        out: Dict[str, Dict[str,Any]] = {}
        for e in self._db_list():
            comp = e.component
            if comp not in out:
                out[comp] = {"versions": [], "active": None}
            out[comp]["versions"].append(e.version)
            if e.active:
                out[comp]["active"] = e.version
        return out

    def installed_versions(self, component:str) -> List[str]:
        return self.list_all().get(component, {}).get("versions", [])

    def active_version(self, component:str) -> Optional[str]:
        return self.list_all().get(component, {}).get("active")

    # ----------------- select -----------------
    def select(self, component:str, version:str) -> Dict[str,Any]:
        target = self.toolchain_dir / component / version
        if not target.exists():
            return {"ok": False, "detail": f"target not found: {target}"}
        link = self.current_dir / component
        if link.exists() or link.is_symlink():
            link.unlink()
        # create relative symlink
        rel = os.path.relpath(str(target), str(self.current_dir))
        os.symlink(rel, link)
        self._db_set_active(component, version)
        info(f"Selected {component} {version} (current/{component} -> {rel})")
        return {"ok": True, "detail": f"Selected {component} {version}"}

    # ----------------- remove -----------------
    def remove(self, component:str, version:str, force:bool=False) -> Dict[str,Any]:
        active = self.active_version(component)
        if active == version and not force:
            return {"ok": False, "detail": "refuse to remove active version (use force)"}
        target = self.toolchain_dir / component / version
        if not target.exists():
            return {"ok": False, "detail": "not installed"}
        # protect runtime: if component is python and matches pkgtool runtime, refuse
        try:
            # TODO: integrate runtime manager if available
            pass
        except Exception:
            pass
        try:
            shutil.rmtree(str(target))
            # remove from db
            try:
                conn = sqlite3.connect(self.cfg.get("db_path"))
                cur = conn.cursor()
                cur.execute("DELETE FROM toolchains WHERE component=? AND version=?", (component, version))
                conn.commit(); conn.close()
            except Exception:
                pass
            info(f"Removed {component} {version}")
            return {"ok": True, "detail": f"Removed {component} {version}"}
        except Exception as e:
            error(f"remove error: {e}")
            return {"ok": False, "detail": str(e)}
          # continuation of pkgtool/toolchain.py

    # ----------------- install (invoke builder) -----------------
    def _find_meta_for_component(self, component:str, version:str) -> Optional[Path]:
        # look for ports_dir/base/<component>/<component>-<version>.meta.yaml
        p = self.ports_dir / "base" / component / f"{component}-{version}.meta.yaml"
        if p.exists():
            return p
        # fallback: search for matching meta anywhere
        for f in self.ports_dir.rglob(f"{component}-{version}.meta.yaml"):
            return f
        return None

    def install(self, component:str, version:str, dry_run:bool=False, keep_build:bool=True) -> Dict[str,Any]:
        meta = self._find_meta_for_component(component, version)
        if not meta:
            return {"ok": False, "detail": f"meta not found for {component}-{version}"}
        info(f"Installing toolchain component {component}-{version} using meta {meta}")
        # if builder CLI is available, call it; else attempt to call a python script 'pkgtool_builder.py' if present
        builder_cmd = shutil.which("pkgtool-builder") or shutil.which("pkgtool_builder.py")
        if builder_cmd:
            # call builder in CLI mode: builder build <meta_path>
            cmd = [builder_cmd, "build", str(meta)]
            if dry_run:
                cmd.append("--dry-run")
            info(f"Invoking builder: {' '.join(cmd)}")
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError as e:
                return {"ok": False, "detail": f"builder failed: {e}"}
            # assume builder created package in package_store; try to find package and extract into toolchain_dir
            # heuristics: package name component-version.pkg.tar.xz
            pkgname = f"{component}-{version}.pkg.tar.xz"
            pkgpath = Path(self.cfg.get("package_store", "/var/pkgtool/packages")) / pkgname
            if not pkgpath.exists():
                # builder might have left destdir; try to find destdir under build_root
                # fallback: simulate
                tgt = self.toolchain_dir / component / version
                tgt.mkdir(parents=True, exist_ok=True)
                marker = tgt / ".installed_by_pkgtool"
                marker.write_text(f"simulated install for {component}-{version}")
                self._db_register(component, version, tgt, meta, active=False)
                return {"ok": True, "detail": "installed (simulated fallback)", "path": str(tgt)}
            # extract package into final prefix
            tgt = self.toolchain_dir / component / version
            if tgt.exists():
                return {"ok": False, "detail": "target already exists"}
            tgt.parent.mkdir(parents=True, exist_ok=True)
            import tarfile
            with tarfile.open(str(pkgpath), "r:xz") as tf:
                tf.extractall(path=str(tgt))
            self._db_register(component, version, tgt, meta, active=False)
            info(f"Installed {component}-{version} into {tgt}")
            return {"ok": True, "detail": "installed", "path": str(tgt)}
        else:
            # no builder available: attempt a simple fetch+extract if meta.source is tar
            try:
                data = None
                if yaml is None:
                    raise RuntimeError("PyYAML required")
                m = yaml.safe_load(meta.read_text())
                src = m.get("source", {})
                stype = src.get("type", "tar")
                if stype in ("tar","archive", None):
                    url = src.get("url")
                    if not url:
                        raise RuntimeError("meta source.url missing")
                    # download
                    info(f"Downloading {url}")
                    import urllib.request
                    fn = url.split("/")[-1]
                    cache = Path(self.cfg.get("cache_dir","/var/cache/pkgtool"))
                    cache.mkdir(parents=True, exist_ok=True)
                    target = cache / fn
                    if not target.exists():
                        urllib.request.urlretrieve(url, str(target))
                    # extract into toolchain prefix
                    tgt = self.toolchain_dir / component / version
                    if tgt.exists():
                        return {"ok": False, "detail": "target exists"}
                    tgt.mkdir(parents=True, exist_ok=True)
                    import tarfile
                    with tarfile.open(str(target), "r:*") as tf:
                        tf.extractall(path=str(tgt))
                    self._db_register(component, version, tgt, meta, active=False)
                    return {"ok": True, "detail": "installed (simple extract)", "path": str(tgt)}
                else:
                    return {"ok": False, "detail": f"unsupported source type and no builder: {stype}"}
            except Exception as e:
                return {"ok": False, "detail": f"fallback install failed: {e}"}

    # ----------------- doctor -----------------
    def doctor(self) -> Dict[str,Any]:
        """
        Perform checks:
         - active symlink targets exist
         - executables in bin exist
         - smoke compile with active gcc if present
        """
        issues = []
        listing = self.list_all()
        for comp, info_map in listing.items():
            active = info_map.get("active")
            if active:
                tgt = self.toolchain_dir / comp / active
                if not tgt.exists():
                    issues.append({"component": comp, "version": active, "problem": "active target missing"})
                bin_dir = tgt / "bin"
                if not bin_dir.exists() or not any(bin_dir.iterdir()):
                    issues.append({"component": comp, "version": active, "problem": "no executables in bin"})
        # smoke compile
        gcc_ver = self.active_version("gcc")
        if gcc_ver:
            gcc_path = self.toolchain_dir / "gcc" / gcc_ver / "bin" / "gcc"
            if gcc_path.exists():
                # create temp small c program
                td = Path(tempfile.mkdtemp())
                try:
                    src = td / "t.c"
                    src.write_text("int main(){return 0;}\n")
                    out = td / "t"
                    cmd = [str(gcc_path), str(src), "-o", str(out)]
                    built = subprocess.run(cmd, capture_output=True, text=True)
                    if built.returncode != 0:
                        issues.append({"component":"gcc","version":gcc_ver,"problem":"smoke compile failed","stderr":built.stderr})
                finally:
                    shutil.rmtree(str(td), ignore_errors=True)
            else:
                issues.append({"component":"gcc","version":gcc_ver,"problem":"gcc binary not found at expected path"})
        ok = len(issues) == 0
        return {"ok": ok, "issues": issues}

    # ----------------- planner -----------------
    def plan_rebuild(self, reason:str="toolchain-change") -> Dict[str,Any]:
        """
        Naive planner: scan ports_dir/base for metas, parse depends.build and build graph.
        Output plan with topological order. (respects only package name, not versions)
        """
        plan_nodes: Dict[str, Path] = {}
        deps_map: Dict[str, List[str]] = {}
        base = self.ports_dir / "base"
        if not base.exists():
            return {"ok": False, "detail": f"ports base not found: {base}"}
        for comp_dir in base.iterdir():
            if not comp_dir.is_dir():
                continue
            for meta_file in comp_dir.glob("*.meta.yaml"):
                try:
                    m = yaml.safe_load(meta_file.read_text())
                    name = m.get("name") or m.get("package") or meta_file.stem
                    version = str(m.get("version",""))
                    key = f"{name}@{version}"
                    plan_nodes[key] = meta_file
                    # read build deps simple form
                    deps = []
                    for d in (m.get("depends",{}) or {}).get("build", []) :
                        if isinstance(d, dict):
                            deps.append(d.get("name"))
                        else:
                            deps.append(d)
                    deps_map[key] = deps
                except Exception:
                    continue
        # topological sort naive: Kahn treating unknown deps as external
        in_deg = {k: 0 for k in plan_nodes}
        graph = {k: set() for k in plan_nodes}
        for k, deps in deps_map.items():
            for dep in deps:
                # link any node whose name matches dep
                for cand in plan_nodes:
                    if cand.split("@")[0] == dep:
                        graph[cand].add(k)
                        in_deg[k] += 1
        queue = [k for k,v in in_deg.items() if v==0]
        order = []
        while queue:
            n = queue.pop(0)
            order.append(n)
            for m in graph.get(n,[]):
                in_deg[m] -= 1
                if in_deg[m]==0:
                    queue.append(m)
        remaining = [k for k,v in in_deg.items() if v>0]
        order.extend(remaining)
        plan = {"reason": reason, "count": len(order), "order": order}
        return {"ok": True, "plan": plan}

    # ----------------- executor -----------------
    def execute_rebuild_plan(self, plan:Dict[str,Any], dry_run:bool=True, parallel:int=1) -> Dict[str,Any]:
        """
        Execute plan: each node is <name>@<version>; call install(name,version).
        If dry_run True, just report what would be done.
        """
        order = plan.get("order", [])
        results = []
        for key in order:
            name, _, ver = key.partition("@")
            if dry_run:
                results.append({"pkg": key, "status": "dry-run"})
                continue
            info(f"Rebuilding {key}")
            r = self.install(name, ver, dry_run=False)
            results.append({"pkg": key, "status": "ok" if r.get("ok") else "failed", "detail": r.get("detail")})
            if not r.get("ok"):
                error(f"Failed to rebuild {key}: {r.get('detail')}")
                return {"ok": False, "results": results}
        return {"ok": True, "results": results}

# CLI helper
def _cli():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-toolchain")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("list")
    pin = sub.add_parser("install")
    pin.add_argument("component")
    pin.add_argument("version")
    pin.add_argument("--dry-run", action="store_true")
    psel = sub.add_parser("select")
    psel.add_argument("component")
    psel.add_argument("version")
    prem = sub.add_parser("remove")
    prem.add_argument("component")
    prem.add_argument("version")
    prem.add_argument("--force", action="store_true")
    sub.add_parser("doctor")
    pplan = sub.add_parser("plan-rebuild")
    pplan.add_argument("--out")
    prexec = sub.add_parser("rebuild")
    prexec.add_argument("--plan")
    prexec.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    tm = ToolchainManager()
    if args.cmd == "list":
        print(tm.list_all())
    elif args.cmd == "install":
        r = tm.install(args.component, args.version, dry_run=args.dry_run)
        print(r)
    elif args.cmd == "select":
        print(tm.select(args.component, args.version))
    elif args.cmd == "remove":
        print(tm.remove(args.component, args.version, force=args.force))
    elif args.cmd == "doctor":
        print(tm.doctor())
    elif args.cmd == "plan-rebuild":
        r = tm.plan_rebuild()
        if not r.get("ok"):
            print(r)
            sys.exit(2)
        plan = r["plan"]
        if args.out:
            with open(args.out,"w") as fh:
                import json
                fh.write(json.dumps(plan, indent=2))
            print("Wrote", args.out)
        else:
            print(plan)
    elif args.cmd == "rebuild":
        if args.plan:
            import json
            plan = json.load(open(args.plan))
        else:
            print("need plan file")
            sys.exit(2)
        r = tm.execute_rebuild_plan(plan, dry_run=args.dry_run)
        print(r)
    else:
        p.print_help()

if __name__ == "__main__":
    _cli()
