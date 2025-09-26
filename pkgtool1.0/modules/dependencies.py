# pkgtool/dependencies.py
"""
pkgtool.dependencies v2 - Resolver e orquestrar dependências integrado
- Integra com pkgtool.builder.Builder e pkgtool.toolchain.ToolchainManager
- Guarda estado em deps_state (JSON)
- Resolve build/run deps, detecta ciclos, topological order
- Constrói dependências chamando Builder, e garante toolchains via ToolchainManager
"""

from __future__ import annotations
import os
import sys
import json
import time
import shutil
import tempfile
from collections import deque, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    import yaml
except Exception:
    raise RuntimeError("PyYAML is required (pip install pyyaml)")

# try import other pkgtool modules
try:
    from .config import load_config, get_config
    from .builder import Builder
    from .toolchain import ToolchainManager
    from .logger import Logger
except Exception:
    # minimal fallbacks so file is self-contained for testing
    def load_config():
        return {
            "ports_dir": "/usr/ports/pkgtool",
            "build_root": "/var/tmp/pkgtool/builds",
            "package_store": "/var/pkgtool/packages",
            "cache_dir": "/var/cache/pkgtool",
            "log_dir": "/var/log/pkgtool",
            "deps_state": "/var/lib/pkgtool/deps_state.json",
            "default_jobs": 4,
            "toolchain_dir": "/opt/pkgtool/toolchains",
            "keep_build_deps": False,
        }
    def get_config():
        return load_config()
    class Builder:
        def __init__(self): pass
        def find_meta(self, ident): return None
        def build(self, meta_ident, dry_run=False, keep_build=True, follow=False):
            return type("R",(object,),{"ok":False,"message":"no builder present"})
    class ToolchainManager:
        def __init__(self): pass
        def is_installed(self, name): return False
        def install(self,name,version=None,dry_run=False): return {"ok":False}
        def select(self,name): return {"ok":False}
    class Logger:
        def __init__(self,name="pkgtool"): pass
        def info(self,m): print("[INFO]",m)
        def warn(self,m): print("[WARN]",m)
        def error(self,m): print("[ERROR]",m)
        def success(self,m): print("[OK]",m)

CFG = load_config()
LOG = Logger("deps")
BUILDER = Builder()
TCM = ToolchainManager()

# state file (JSON) to track installed/resolved deps and last-plan
STATE_FILE = Path(CFG.get("deps_state", "/var/lib/pkgtool/deps_state.json"))
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

# helper dataclass
@dataclass
class DepNode:
    name: str
    version: str
    meta: Optional[Path] = None

# ------------------ scanning / metas / normalization ------------------

PORTS_BASE = Path(CFG.get("ports_dir", "/usr/ports/pkgtool")) / "base"

def _safe_load_meta(p: Path) -> Optional[Dict[str,Any]]:
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception as e:
        LOG.warn(f"failed to load meta {p}: {e}")
        return None

def collect_metas(ports_base: Optional[Path] = None) -> Dict[str, List[DepNode]]:
    """scan ports/base for *.meta.yaml and return name -> [DepNode...]"""
    pb = ports_base or PORTS_BASE
    out: Dict[str, List[DepNode]] = {}
    if not pb.exists():
        LOG.warn(f"ports base not found: {pb}")
        return out
    for meta_file in pb.rglob("*.meta.yaml"):
        m = _safe_load_meta(meta_file)
        if not isinstance(m, dict):
            continue
        name = m.get("name") or m.get("package") or meta_file.stem
        version = str(m.get("version","*"))
        out.setdefault(name, []).append(DepNode(name=name, version=version, meta=meta_file))
    return out

def _normalize_dep_entry(raw: Any) -> Optional[Dict[str,str]]:
    """
    Normalize a dependency entry.
    Accepts: "pkg", "pkg >=1.2", {"name": "...", "version": "..."}
    Returns: {"name":name, "version":constraint_or_*}
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        tokens = raw.split()
        name = tokens[0]
        version = " ".join(tokens[1:]) if len(tokens) > 1 else "*"
        return {"name": name, "version": version}
    if isinstance(raw, dict):
        return {"name": raw.get("name"), "version": str(raw.get("version","*"))}
    return None

# ------------------ build a dependency graph ------------------

def build_full_graph(name_map: Dict[str, List[DepNode]]) -> Tuple[Dict[str,Set[str]], Dict[str,DepNode]]:
    """
    Build graph where nodes are 'name@version' using first-found meta for each name.
    Returns (graph, node_map)
    """
    node_map: Dict[str,DepNode] = {}
    for name, nodes in name_map.items():
        node_map[f"{nodes[0].name}@{nodes[0].version}"] = nodes[0]
    graph: Dict[str,Set[str]] = {k:set() for k in node_map}
    for key, node in list(node_map.items()):
        meta = _safe_load_meta(node.meta) if node.meta else {}
        deps = (meta.get("depends",{}) or {})
        build_deps = deps.get("build", []) or []
        # include build deps only for graph edges (runtime deps handled separately)
        for raw in build_deps:
            nde = _normalize_dep_entry(raw)
            if not nde: continue
            dname = nde["name"]
            if dname in name_map:
                cand = name_map[dname][0]
                dep_key = f"{cand.name}@{cand.version}"
                if dep_key in graph:
                    graph[key].add(dep_key)
    return graph, node_map

# ------------------ cycles detection and topo sort ------------------

def detect_cycles(graph: Dict[str,Set[str]]) -> List[List[str]]:
    """detect cycles with DFS, return list of cycles"""
    temp=set(); perm=set(); cycles=[]; stack=[]
    def visit(n):
        if n in perm: return
        if n in temp:
            if n in stack:
                i=stack.index(n); cycles.append(stack[i:]+[n])
            return
        temp.add(n); stack.append(n)
        for m in graph.get(n, []):
            visit(m)
        stack.pop(); temp.remove(n); perm.add(n)
    for n in list(graph.keys()):
        if n not in perm: visit(n)
    return cycles

def topo_sort(graph: Dict[str,Set[str]]) -> Tuple[bool, List[str]]:
    """Kahn algorithm, return (ok, order). ok False if cycle present (order partial)"""
    in_deg = {n:0 for n in graph}
    for n, deps in graph.items():
        for d in deps:
            in_deg[d] = in_deg.get(d,0) + 1
    q = deque([n for n,d in in_deg.items() if d==0])
    order=[]
    while q:
        n=q.popleft(); order.append(n)
        for m in list(graph.get(n, [])):
            in_deg[m]-=1
            if in_deg[m]==0: q.append(m)
    if any(v>0 for v in in_deg.values()):
        return False, order
    return True, order

# ------------------ state persistence ------------------

def load_state() -> Dict[str,Any]:
    if not STATE_FILE.exists():
        return {"installed": {}, "last_plan": None, "timestamp": time.time()}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"installed": {}, "last_plan": None, "timestamp": time.time()}

def save_state(state: Dict[str,Any]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(str(tmp), str(STATE_FILE))

# ------------------ helpers for toolchain integration ------------------

def extract_toolchain_deps_from_meta(meta_path: Path) -> List[str]:
    """
    Read meta and return list of toolchain components required (strings like 'gcc', 'binutils', 'glibc').
    It inspects 'depends.build' and looks for well-known toolchain names. This is heuristic.
    """
    m = _safe_load_meta(meta_path)
    if not m:
        return []
    deps = (m.get("depends",{}) or {})
    build_deps = deps.get("build",[]) or []
    names = []
    for raw in build_deps:
        nde = _normalize_dep_entry(raw)
        if not nde: continue
        nm = nde["name"]
        if nm in ("gcc","binutils","glibc","linux-headers","kernel-headers"):
            names.append(nm)
    return names

# ------------------ resolve and plan for a single meta ------------------

def resolve_deps_for_meta(meta_path: Path, include_run: bool=False) -> List[DepNode]:
    """
    Return ordered list of DepNode representing transitive build (and optionally run) dependencies.
    Uses the 'name_map' selection heuristic (first meta found).
    """
    name_map = collect_metas()
    meta = _safe_load_meta(meta_path)
    if not meta:
        return []
    raw_build = list((meta.get("depends",{}) or {}).get("build",[]) or [])
    if include_run:
        raw_build += list((meta.get("depends",{}) or {}).get("run",[]) or [])
    # normalize to names preserving order
    names=[]
    seen=set()
    for r in raw_build:
        nde=_normalize_dep_entry(r)
        if not nde: continue
        name=nde["name"]
        if name in seen: continue
        seen.add(name); names.append(name)
    # map names->metarefs
    resolved_initial=[]
    for nm in names:
        metas = name_map.get(nm)
        if not metas:
            LOG.warn(f"dep {nm} not found in ports tree")
            continue
        resolved_initial.append(metas[0])
    # build global graph and compute transitive closure for these nodes
    graph, node_map = build_full_graph(name_map)
    # get keys corresponding to initial resolved items
    start_keys = [f"{n.name}@{n.version}" for n in resolved_initial]
    # collect transitive nodes reachable from these start_keys (we need those and their deps)
    needed=set()
    stack=list(start_keys)
    while stack:
        cur=stack.pop()
        if cur in needed: continue
        needed.add(cur)
        for d in graph.get(cur, []):
            stack.append(d)
    # restrict subgraph
    subgraph = {k:(graph.get(k, set()) & needed) for k in needed}
    ok, order = topo_sort(subgraph)
    # order currently is nodes with no deps first -> that is correct order to build deps
    out=[]
    for key in order:
        dn = node_map.get(key)
        if dn:
            out.append(dn)
    return out

# ------------------ ensure toolchains (call ToolchainManager) ------------------

def ensure_toolchains_for_meta(meta_path: Path, dry_run: bool=False) -> Dict[str,Any]:
    """
    Ensure toolchain components required by meta exist (calls ToolchainManager.install/select).
    Returns dict with results per component.
    """
    results = {}
    need = extract_toolchain_deps_from_meta(meta_path)
    if not need:
        return {"ok": True, "detail": "no toolchain deps"}
    for comp in need:
        # check installed
        try:
            if hasattr(TCM, "is_installed") and TCM.is_installed(comp):
                results[comp] = {"ok": True, "detail": "already installed"}
                continue
            # try install using toolchain manager
            if dry_run:
                results[comp] = {"ok": True, "detail": "[dry-run] would install"}
                continue
            res = TCM.install(comp, None)
            results[comp] = res
            # optionally select
            if res.get("ok"):
                try:
                    TCM.select(comp)
                except Exception:
                    pass
        except Exception as e:
            results[comp] = {"ok": False, "detail": str(e)}
    # return overall summary
    ok = all(v.get("ok", False) for v in results.values())
    return {"ok": ok, "results": results}

# ------------------ build dependencies using Builder, integrated flow ------------------

def build_deps_for_meta(meta_path: Path, dry_run: bool=False, keep_build: bool=True) -> Dict[str,Any]:
    """
    Resolve build dependencies for meta, ensure toolchains, then build them in order using Builder.
    Saves plan in state file.
    """
    LOG.info(f"Resolving deps for {meta_path}")
    # ensure toolchains first (so builder will use proper tools)
    tc_res = ensure_toolchains_for_meta(meta_path, dry_run=dry_run)
    if not tc_res.get("ok", True):
        LOG.warn(f"toolchain ensure returned: {tc_res}")
    plan_nodes = resolve_deps_for_meta(meta_path, include_run=False)
    if not plan_nodes:
        return {"ok": True, "results": [], "detail": "no build deps"}
    results=[]
    state = load_state()
    # persist last_plan
    state["last_plan"] = [f"{n.name}@{n.version}" for n in plan_nodes]
    state["timestamp"] = time.time()
    save_state(state)
    for dn in plan_nodes:
        key = f"{dn.name}@{dn.version}"
        LOG.info(f"Building dependency {key}")
        if dry_run:
            results.append({"name":dn.name,"version":dn.version,"status":"dry-run"})
            continue
        # attempt build via builder (meta path)
        if dn.meta is None:
            results.append({"name":dn.name,"version":dn.version,"status":"missing-meta"})
            return {"ok": False, "results": results}
        try:
            res = BUILDER.build(str(dn.meta), dry_run=False, keep_build=keep_build, follow=False)
            if not res.ok:
                results.append({"name":dn.name,"version":dn.version,"status":"failed","detail":res.message})
                return {"ok": False, "results": results}
            results.append({"name":dn.name,"version":dn.version,"status":"ok","pkg": str(res.package_path)})
            # mark installed in state
            state["installed"].setdefault(dn.name, []).append({"version": dn.version, "meta": str(dn.meta), "installed_at": time.time()})
            save_state(state)
        except Exception as e:
            LOG.error(f"builder exception for {dn.name}: {e}")
            return {"ok": False, "results": results, "error": str(e)}
    return {"ok": True, "results": results}

# ------------------ cleaning build-only deps and artifacts ------------------

def clean_build_deps_for_meta(meta_path: Path) -> Dict[str,Any]:
    """
    Remove build directories and packages for deps of meta (based on state or plan).
    Caution: destructive.
    """
    cfg = load_config()
    build_root = Path(cfg.get("build_root", "/var/tmp/pkgtool/builds"))
    package_store = Path(cfg.get("package_store", "/var/pkgtool/packages"))
    plan = resolve_deps_for_meta(meta_path, include_run=False)
    removed = {"build_dirs": [], "packages": []}
    for dn in plan:
        bd = build_root / dn.name / dn.version
        if bd.exists():
            try:
                shutil.rmtree(str(bd))
                removed["build_dirs"].append(str(bd))
            except Exception as e:
                LOG.warn(f"failed remove build dir {bd}: {e}")
        pkg = package_store / f"{dn.name}-{dn.version}.pkg.tar.xz"
        if pkg.exists():
            try:
                pkg.unlink()
                removed["packages"].append(str(pkg))
            except Exception as e:
                LOG.warn(f"failed remove pkg {pkg}: {e}")
    return {"ok": True, "removed": removed}

# ------------------ query helpers ------------------

def get_installed_from_state() -> Dict[str,Any]:
    st = load_state()
    return st.get("installed", {})

# ------------------ CLI ------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-deps", description="pkgtool dependency resolver")
    sub = p.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="List collected metas")
    p_list.add_argument("--name", help="filter by name", default=None)

    p_res = sub.add_parser("resolve", help="Resolve deps for meta")
    p_res.add_argument("meta")

    p_build = sub.add_parser("build-deps", help="Build build-deps for meta")
    p_build.add_argument("meta")
    p_build.add_argument("--dry-run", action="store_true")
    p_build.add_argument("--keep-build", action="store_true")

    p_clean = sub.add_parser("clean-build", help="Clean build deps/artifacts for meta")
    p_clean.add_argument("meta")

    p_state = sub.add_parser("state", help="Show deps state stored")
    args = p.parse_args()

    if args.cmd == "list":
        metas = collect_metas()
        if args.name:
            print(json.dumps({k:[m.meta.as_posix() for m in v] for k,v in metas.items() if k==args.name}, indent=2))
        else:
            print(json.dumps({k:[m.meta.as_posix() for m in v] for k,v in metas.items()}, indent=2))
        return

    if args.cmd == "resolve":
        mp = Path(args.meta)
        if not mp.exists():
            metas = collect_metas(); cand = metas.get(args.meta)
            if not cand: print("meta not found"); return
            mp = cand[0].meta
        plan = resolve_deps_for_meta(mp)
        print(json.dumps([{"name":n.name,"version":n.version,"meta":str(n.meta)} for n in plan], indent=2))
        return

    if args.cmd == "build-deps":
        mp = Path(args.meta)
        if not mp.exists():
            metas = collect_metas(); cand = metas.get(args.meta)
            if not cand: print("meta not found"); return
            mp = cand[0].meta
        r = build_deps_for_meta(mp, dry_run=args.dry_run, keep_build=args.keep_build)
        print(json.dumps(r, indent=2, default=str))
        return

    if args.cmd == "clean-build":
        mp = Path(args.meta)
        if not mp.exists():
            metas = collect_metas(); cand = metas.get(args.meta)
            if not cand: print("meta not found"); return
            mp = cand[0].meta
        r = clean_build_deps_for_meta(mp)
        print(json.dumps(r, indent=2))
        return

    if args.cmd == "state":
        print(json.dumps(load_state(), indent=2, default=str))
        return

    p.print_help()

if __name__ == "__main__":
    _cli()
