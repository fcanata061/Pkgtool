import os
import toml
import logging
from pkgtool.core import db, package_manager

log = logging.getLogger("pkgtool.dependency_manager")

def load_recipe(program: str) -> dict:
    """
    Carrega recipe TOML de um programa em /usr/ports/pkgtool/<categoria>/<programa>/<versao>.toml
    """
    recipe_path = db.find_recipe(program)
    if not os.path.exists(recipe_path):
        raise FileNotFoundError(f"Recipe não encontrada para {program}")
    
    recipe = toml.load(recipe_path)
    return recipe

def resolve(program: str) -> dict:
    """
    Retorna as dependências build/runtime de um programa
    """
    recipe = load_recipe(program)
    deps = {
        "build": recipe.get("dependencies", {}).get("build", []),
        "runtime": recipe.get("dependencies", {}).get("runtime", [])
    }
    log.info(f"[DEP] {program} build deps: {deps['build']}")
    log.info(f"[DEP] {program} runtime deps: {deps['runtime']}")
    return deps

def install_build_deps(program: str):
    deps = resolve(program)["build"]
    for dep in deps:
        if not db.is_installed(dep):
            log.info(f"[DEP] Installing build dep: {dep}")
            package_manager.install(dep, temporary=True)

def install_runtime_deps(program: str):
    deps = resolve(program)["runtime"]
    for dep in deps:
        if not db.is_installed(dep):
            log.info(f"[DEP] Installing runtime dep: {dep}")
            package_manager.install(dep, temporary=False)

def remove_build_deps(program: str):
    deps = resolve(program)["build"]
    for dep in deps:
        if db.is_installed(dep) and db.is_temporary(dep):
            log.info(f"[DEP] Removing build dep: {dep}")
            package_manager.remove(dep)

def audit():
    """
    Lista pacotes que podem ser removidos (build deps esquecidos + órfãos).
    """
    installed = db.list_installed()
    removable = []
    for pkg in installed:
        if db.is_temporary(pkg):
            removable.append(pkg)
        elif db.is_orphan(pkg):
            removable.append(pkg)
    return removable

def audit_fix():
    removable = audit()
    for pkg in removable:
        log.info(f"[AUDIT] Removing orphan/build dep: {pkg}")
        package_manager.remove(pkg)
