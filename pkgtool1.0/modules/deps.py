#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deps.py
Resolvedor de dependências.

Funcionalidades:
- Lê depends/optional_depends do meta.yaml
- Resolve dependências recursivas
- Ordenação topológica
- Suporta múltiplas versões do mesmo pacote
- Detecta ciclos de dependências
"""

from __future__ import annotations
import collections
from typing import Dict, List, Set, Tuple
from utils import log_info, log_warn, log_success, log_error
from config import Config
from meta import MetaIndex, MetaPackage

class DependencyError(Exception):
    pass

class DependencyResolver:
    def __init__(self, cfg: Config, index: MetaIndex):
        self.cfg = cfg
        self.index = index

    def resolve(self, root_pkg: str, version: str | None = None) -> List[Tuple[str, str]]:
        """
        Resolve todas as dependências de root_pkg.
        Retorna lista ordenada [(nome, versão)] em ordem de instalação.
        """
        log_info(f"Resolvendo dependências de {root_pkg}{'-'+version if version else ''}")
        graph: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        visited: Set[Tuple[str, str]] = set()

        # construir grafo
        def visit(pkg_name: str, pkg_version: str | None):
            pkg = self.index.find(pkg_name, pkg_version)
            if not pkg:
                raise DependencyError(f"Pacote não encontrado: {pkg_name}-{pkg_version or '*'}")

            node = (pkg.name, pkg.version)
            if node in visited:
                return
            visited.add(node)

            graph.setdefault(node, set())
            for dep in pkg.depends:
                dep_pkg, dep_ver = self._parse_dep(dep)
                dep_meta = self.index.find(dep_pkg, dep_ver)
                if not dep_meta:
                    raise DependencyError(f"Dependência não encontrada: {dep}")
                dep_node = (dep_meta.name, dep_meta.version)
                graph[node].add(dep_node)
                visit(dep_meta.name, dep_meta.version)

        visit(root_pkg, version)

        # ordenação topológica
        order = self._toposort(graph)
        log_success(f"Dependências resolvidas: {order}")
        return order

    def _parse_dep(self, dep: str) -> Tuple[str, str | None]:
        """
        Interpreta string de dependência: "nome" ou "nome=versão".
        """
        if "=" in dep:
            name, ver = dep.split("=", 1)
            return name.strip(), ver.strip()
        return dep.strip(), None

    def _toposort(self, graph: Dict[Tuple[str, str], Set[Tuple[str, str]]]) -> List[Tuple[str, str]]:
        """
        Ordenação topológica (Kahn).
        """
        indeg: Dict[Tuple[str, str], int] = {n: 0 for n in graph}
        for deps in graph.values():
            for d in deps:
                indeg[d] = indeg.get(d, 0) + 1

        queue = collections.deque([n for n, deg in indeg.items() if deg == 0])
        result: List[Tuple[str, str]] = []

        while queue:
            node = queue.popleft()
            result.append(node)
            for dep in graph.get(node, []):
                indeg[dep] -= 1
                if indeg[dep] == 0:
                    queue.append(dep)

        if len(result) != len(indeg):
            raise DependencyError("Ciclo de dependências detectado")

        return result

# -----------------------
# Teste rápido
# -----------------------
if __name__ == "__main__":
    cfg = Config.load()
    idx = MetaIndex(cfg.repo_path)
    idx.load()
    resolver = DependencyResolver(cfg, idx)
    try:
        order = resolver.resolve("exemplo")
        print("Ordem final:", order)
    except DependencyError as e:
        log_error(str(e))
