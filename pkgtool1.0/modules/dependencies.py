# pkgtool/dependencies.py
"""
Dependency manager for pkgtool

Features:
 - Scan ports/base for meta YAML files
 - Parse depends.build and depends.run (simple normalization)
 - Build a dependency graph (nodes = name@version)
 - Detect cycles and report them
 - Topological ordering (Kahn)
 - Resolve dependencies for a specific meta (returns ordered list)
 - Optionally invoke Builder to build dependencies in order
 - Remove build-only dependencies (clean-build)
 - CLI: list, graph, resolve, build, clean-build

Limitations:
 - Simple solver: selects the first matching meta for a package name.
 - Version constraints are not fully implemented; supports basic matching when exact meta exists.
"""

from __future__ import annotations
import os
import sys
import time
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    import yaml
except Exception:
    raise RuntimeError("PyYAML required (pip install pyyaml)")

# try to import pkgtool helpers; fallbacks if missing
try:
    from .config import load_config, get_config
    from .builder import Builder
    from .logger import Logger
except Exception:
    def load_config():
        return {
            "ports_dir": "/usr/ports/pkgtool",
            "build_root": "/var/tmp/pkgtool/builds",
            "default_jobs": 4
        }
    class Builder:
        def __init__(self): pass
        def find_meta(self, ident): return None
        def build(self, meta_ident, **kwargs): return type("R",(object,),{"ok":False,"message":"no builder"})
    class Logger:
        def __init__(self,name="pkgtool"): pass
        def info(self,m): print("[INFO]",m)
        def warn(self,m): print("[WARN]",m)
        def error(self,m): print("[ERROR]",m)
        def success(self,m): print("[OK]",m)

CFG = load_config()
PORTS_BASE = Path(CFG.get("ports_dir", "/usr/ports/pkgtool")) / "base"
LOG = Logger("deps")
BUILDER = Builder()

@dataclass
class MetaRef:
    name: str
    version: str
    path: Path

def _safe_load_meta(path: Path) -> Optional[Dict[str, Any]]:
    try:
        m = yaml.safe_load(path.read_text()) or {}
        return m
    except Exception as e:
        LOG.warn(f"failed to load meta {path}: {e}")
        return None

def collect_metas(ports_base: Optional[Path] = None) -> Dict[str, List[MetaRef]]:
    """
    Scan ports/base and return mapping: name -> [MetaRef,...]
    Picks up *.meta.yaml files.
    """
    ports_base = ports_base or PORTS_BASE
    out: Dict[str, List[MetaRef]] = {}
    if not ports_base.exists():
        LOG.warn(f"ports base not found: {ports_base}")
        return out
    for meta_file in ports_base.rglob("*.meta.yaml"):
        m = _safe_load_meta(meta_file)
        if not isinstance(m, dict):
            continue
        name = m.get("name") or m.get("package") or meta_file.stem
        version = str(m.get("version","*"))
        out.setdefault(name, []).append(MetaRef(name=name, version=version, path=meta_file))
    return out

def _normalize_dep(raw) -> Optional[str]:
    """
    Normalize dependency entry into a package name string.
    Accepts string like 'pkg' or 'pkg >=1.2' or dict {'name':..}
    Returns just the name (solver picks a meta for it).
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        # take first token as name
        return raw.split()[0]
    if isinstance(raw, dict):
        return raw.get("name")
    return None

def build_graph_from_metas(name_map: Dict[str, List[MetaRef]]) -> Tuple[Dict[str, Set[str]], Dict[str, MetaRef]]:
    """
    Builds a dependency graph using first-found meta for each name.
    Returns (graph, node_map) where graph: node -> set(dependency_node)
    Node keys are 'name@version'
    """
    node_map: Dict[str, MetaRef] = {}
    for name, metas in name_map.items():
        # choose first meta by default
        mref = metas[0]
        key = f"{mref.name}@{mref.version}"
        node_map[key] = mref

    graph: Dict[str, Set[str]] = {k: set() for k in node_map.keys()}

    # populate edges: node -> depends_on_node
    for key, mref in node_map.items():
        meta = _safe_load_meta(mref.path)
        if not meta:
            continue
        depends = meta.get("depends", {}) or {}
        build_deps = depends.get("build", []) or []
        run_deps = depends.get("run", []) or []
        # we include build deps by default; run deps optionally later
        for raw in build_deps:
            dep_name = _normalize_dep(raw)
            if not dep_name:
                continue
            # find candidate node
            if dep_name in name_map:
                cand = name_map[dep_name][0]  # pick first
                dep_key = f"{cand.name}@{cand.version}"
                if dep_key in graph:
                    graph[key].add(dep_key)
    return graph, node_map

def detect_cycles(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """
    Detect cycles using DFS. Return list of cycles (each as list of nodes).
    """
    temp_mark = set()
    perm_mark = set()
    cycles = []
    path_stack: List[str] = []

    def visit(n: str):
        if n in perm_mark:
            return
        if n in temp_mark:
            # cycle found: extract cycle from path_stack
            if n in path_stack:
                idx = path_stack.index(n)
                cycles.append(path_stack[idx:] + [n])
            return
        temp_mark.add(n)
        path_stack.append(n)
        for m in graph.get(n, []):
            visit(m)
        path_stack.pop()
        temp_mark.remove(n)
        perm_mark.add(n)

    for node in graph.keys():
        if node not in perm_mark:
            visit(node)
    return cycles

def topo_sort(graph: Dict[str, Set[str]]) -> Tuple[bool, List[str]]:
    """
    Kahn's algorithm. Return (ok, order). ok=False if cycle (order partial).
    """
    # compute in-degree
    in_deg: Dict[str, int] = {n: 0 for n in graph}
    for n, deps in graph.items():
        for d in deps:
            in_deg[d] = in_deg.get(d, 0) + 1
    queue = [n for n, deg in in_deg.items() if deg == 0]
    order: List[str] = []
    while queue:
        n = queue.pop(0)
        order.append(n)
        for m in list(graph.get(n, [])):
            in_deg[m] -= 1
            if in_deg[m] == 0:
                queue.append(m)
    # if any node has in_deg > 0 => cycle
    if any(deg > 0 for deg in in_deg.values()):
        return False, order
    return True, order
def resolve_deps_for_meta(meta_path: Path, include_run: bool = False) -> List[Dict[str,str]]:
    """
    Given a meta file, return ordered list of dependencies (name, version, meta_path)
    Build only build-deps by default. Uses first-found meta for names.
    """
    name_map = collect_metas()
    # load requested meta
    meta = _safe_load_meta(meta_path)
    if not meta:
        return []
    raw_build = (meta.get("depends", {}) or {}).get("build", []) or []
    if include_run:
        raw_build += (meta.get("depends", {}) or {}).get("run", []) or []
    # normalize list of names preserving order and unique
    names = []
    seen = set()
    for r in raw_build:
        nm = _normalize_dep(r)
        if not nm or nm in seen:
            continue
        seen.add(nm); names.append(nm)
    # now map names -> metarefs
    resolved = []
    for nm in names:
        metas = name_map.get(nm)
        if not metas:
            LOG.warn(f"Dependency {nm} not found in ports tree")
            continue
        mref = metas[0]
        resolved.append({"name": mref.name, "version": mref.version, "meta": str(mref.path)})
    # we need to order them respecting their internal graph: build a graph for the relevant subset
    # build a global graph and then filter to nodes we care about and their transitive deps
    full_name_map = name_map
    graph, node_map = build_graph_from_metas(full_name_map)
    # compute transitive closure required for these names
    target_nodes = set()
    # helper: find node key for a package name (first match)
    def key_for(name):
        metas = full_name_map.get(name)
        if not metas: return None
        return f"{metas[0].name}@{metas[0].version}"
    for r in resolved:
        k = key_for(r["name"])
        if not k: continue
        # DFS to collect deps
        stack = [k]
        while stack:
            cur = stack.pop()
            if cur in target_nodes: continue
            target_nodes.add(cur)
            for d in graph.get(cur, []):
                stack.append(d)
    # create subgraph
    subgraph = {n: (graph.get(n) & target_nodes) for n in target_nodes}
    ok, order = topo_sort(subgraph)
    # order currently is nodes with dependencies first; convert to resolved entries filtering by our name_map
    out = []
    for node in order:
        mr = node_map.get(node)
        if not mr:
            # maybe node not in node_map (shouldn't happen)
            continue
        out.append({"name": mr.name, "version": mr.version, "meta": str(mr.path)})
    # remove duplicates preserving order
    seen2 = set(); uniq = []
    for o in out:
        key = (o["name"], o["version"])
        if key in seen2: continue
        seen2.add(key); uniq.append(o)
    return uniq

def build_deps_for_meta(meta_path: Path, dry_run: bool = False, keep_build: bool = True) -> Dict[str, Any]:
    """
    Resolve build deps and build them in topo order using BUILDER.
    Returns dict with results.
    """
    plan = resolve_deps_for_meta(meta_path, include_run=False)
    results = []
    for item in plan:
        name = item["name"]; ver = item["version"]; meta = item["meta"]
        LOG.info(f"Dependency build step: {name}@{ver} -> meta={meta}")
        if dry_run:
            results.append({"name": name, "version": ver, "status": "dry-run"})
            continue
        # builder.build accepts meta path or identifier
        try:
            res = BUILDER.build(str(meta), dry_run=False, keep_build=keep_build, follow=False)
            if res.ok:
                results.append({"name": name, "version": ver, "status": "ok", "pkg": str(res.package_path)})
            else:
                results.append({"name": name, "version": ver, "status": "failed", "detail": res.message})
                return {"ok": False, "results": results}
        except Exception as e:
            LOG.error(f"builder exception for {name}: {e}")
            return {"ok": False, "results": results, "error": str(e)}
    return {"ok": True, "results": results}

def clean_build_artifacts_for_meta(meta_path: Path) -> Dict[str,Any]:
    """
    Remove build artifacts for the dependencies of a meta (and optionally their packages).
    It will scan build_root and package_store and remove packages that match name/version.
    BE CAREFUL: this deletes files.
    """
    cfg = load_config()
    build_root = Path(cfg.get("build_root", "/var/tmp/pkgtool/builds"))
    package_store = Path(cfg.get("package_store", "/var/pkgtool/packages"))
    plan = resolve_deps_for_meta(meta_path, include_run=False)
    removed = {"build_dirs": [], "packages": []}
    for item in plan:
        nm = item["name"]; ver = item["version"]
        # remove build dir
        br = build_root / nm / ver
        if br.exists():
            try:
                safe_rmtree(br)
                removed["build_dirs"].append(str(br))
            except Exception:
                pass
        # remove package
        pkgname = f"{nm}-{ver}.pkg.tar.xz"
        pkg = package_store / pkgname
        if pkg.exists():
            try:
                pkg.unlink()
                removed["packages"].append(str(pkg))
            except Exception:
                pass
    return {"ok": True, "removed": removed}
def graph_for_meta(meta_path: Path, include_run: bool = False) -> Dict[str,Any]:
    """
    Return a serializable graph (nodes, edges) for the meta's deps (transitive).
    """
    plan = resolve_deps_for_meta(meta_path, include_run=include_run)
    name_map = collect_metas()
    graph, node_map = build_graph_from_metas(name_map)
    nodes = []
    edges = []
    # convert node_map subset to nodes
    for item in plan:
        nkey = f"{item['name']}@{item['version']}"
        nodes.append(nkey)
        for dep in graph.get(nkey, []):
            if dep in nodes:
                edges.append((nkey, dep))
    return {"nodes": nodes, "edges": edges}

# CLI
def _cli():
    import argparse
    p = argparse.ArgumentParser(prog="pkgtool-deps")
    sub = p.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="List available metas")
    p_list.add_argument("--name", help="filter by name", default=None)

    p_res = sub.add_parser("resolve", help="Resolve dependencies for meta")
    p_res.add_argument("meta")

    p_graph = sub.add_parser("graph", help="Show dependency graph (json)")
    p_graph.add_argument("meta")
    p_graph.add_argument("--run", action="store_true")

    p_build = sub.add_parser("build-deps", help="Build build-deps for meta")
    p_build.add_argument("meta")
    p_build.add_argument("--dry-run", action="store_true")
    p_build.add_argument("--keep-build", action="store_true")

    p_clean = sub.add_parser("clean-build", help="Clean build artifacts for meta")
    p_clean.add_argument("meta")

    args = p.parse_args()
    if args.cmd == "list":
        metas = collect_metas()
        if args.name:
            print(json.dumps({k: [m.path.as_posix() for m in v] for k,v in metas.items() if k==args.name}, indent=2))
        else:
            print(json.dumps({k: [m.path.as_posix() for m in v] for k,v in metas.items()}, indent=2))
        return

    if args.cmd == "resolve":
        mp = Path(args.meta)
        if not mp.exists():
            # try find by name
            metas = collect_metas()
            cand = metas.get(args.meta)
            if not cand:
                print("meta not found"); return
            mp = cand[0].path
        resolved = resolve_deps_for_meta(mp)
        print(json.dumps(resolved, indent=2))
        return

    if args.cmd == "graph":
        mp = Path(args.meta)
        if not mp.exists():
            metas = collect_metas(); cand = metas.get(args.meta)
            if not cand: print("meta not found"); return
            mp = cand[0].path
        g = graph_for_meta(mp, include_run=args.run)
        print(json.dumps(g, indent=2))
        return

    if args.cmd == "build-deps":
        mp = Path(args.meta)
        if not mp.exists():
            metas = collect_metas(); cand = metas.get(args.meta)
            if not cand: print("meta not found"); return
            mp = cand[0].path
        r = build_deps_for_meta(mp, dry_run=args.dry_run, keep_build=args.keep_build)
        print(json.dumps(r, indent=2))
        return

    if args.cmd == "clean-build":
        mp = Path(args.meta)
        if not mp.exists():
            metas = collect_metas(); cand = metas.get(args.meta)
            if not cand: print("meta not found"); return
            mp = cand[0].path
        r = clean_build_artifacts_for_meta(mp)
        print(json.dumps(r, indent=2))
        return

    p.print_help()

if __name__ == "__main__":
    _cli()
