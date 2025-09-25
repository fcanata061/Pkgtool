import os
import subprocess
import shlex
import sys
import traceback
import json
from datetime import datetime
from pathlib import Path

from modules import config, log, db

# Eventos suportados
SUPPORTED_EVENTS = [
    "pre_patch", "post_patch",
    "pre_configure", "post_configure",
    "pre_build", "post_build",
    "pre_install", "post_install",
    "pre_remove", "post_remove",
]

# Hooks carregados em memória
GLOBAL_HOOKS = {}
PACKAGE_HOOKS = {}

# -----------------------------------------------------------------------------
# Funções internas
# -----------------------------------------------------------------------------

def _execute_command(command, context=None, sandbox=False):
    """
    Executa um comando de hook.
    Pode ser:
      - comando shell inline (ex.: "echo hello")
      - script externo (ex.: "scripts/fix.sh")
      - função Python (ex.: "python:hooks.custom.func")
    """
    try:
        env = os.environ.copy()
        if context:
            for k, v in context.items():
                env[f"PKG_{k.upper()}"] = str(v)

        if command.startswith("python:"):
            module_func = command.split(":", 1)[1]
            modname, funcname = module_func.rsplit(".", 1)
            mod = __import__(modname, fromlist=[funcname])
            func = getattr(mod, funcname)
            log.info(f"[HOOK] Executando função Python: {command}")
            return func(context or {})

        elif os.path.isfile(command) and os.access(command, os.X_OK):
            log.info(f"[HOOK] Executando script externo: {command}")
            result = subprocess.run([command], env=env, capture_output=True, text=True)
            if result.stdout:
                log.info(result.stdout.strip())
            if result.stderr:
                log.error(result.stderr.strip())
            return result.returncode == 0

        else:
            log.info(f"[HOOK] Executando comando inline: {command}")
            result = subprocess.run(shlex.split(command), env=env, capture_output=True, text=True)
            if result.stdout:
                log.info(result.stdout.strip())
            if result.stderr:
                log.error(result.stderr.strip())
            return result.returncode == 0

    except Exception as e:
        log.error(f"[HOOK] Falha ao executar hook '{command}': {e}")
        traceback.print_exc()
        return False


def _resolve_hooks(event, package=None):
    """Obtém hooks globais e específicos de pacote."""
    hooks = []
    hooks.extend(GLOBAL_HOOKS.get(event, []))
    if package and package in PACKAGE_HOOKS:
        hooks.extend(PACKAGE_HOOKS[package].get(event, []))
    return sorted(hooks, key=lambda x: x.get("priority", 0))


def _record_execution(event, package, command, result):
    """Salva no banco/log a execução do hook."""
    entry = {
        "event": event,
        "package": package,
        "command": command,
        "result": "success" if result else "fail",
        "timestamp": datetime.utcnow().isoformat(),
    }
    db.record_hook_execution(entry)
    log.info(f"[HOOK] Registro salvo: {json.dumps(entry)}")

# -----------------------------------------------------------------------------
# API Pública
# -----------------------------------------------------------------------------

def run(event, package=None, context=None, abort_on_fail=True):
    """Executa todos os hooks registrados para um evento."""
    if event not in SUPPORTED_EVENTS:
        log.warn(f"[HOOK] Evento '{event}' não suportado.")
        return True

    hooks = _resolve_hooks(event, package)
    if not hooks:
        log.debug(f"[HOOK] Nenhum hook para evento '{event}'.")
        return True

    log.info(f"[HOOK] Executando {len(hooks)} hook(s) para evento '{event}'")

    for hook in hooks:
        command = hook["command"]
        sandbox = hook.get("sandbox", False)
        result = _execute_command(command, context, sandbox)
        _record_execution(event, package, command, result)

        if not result and abort_on_fail:
            log.error(f"[HOOK] Falhou: {command}")
            return False

    return True


def add_hook(event, command, package=None, priority=0, sandbox=False):
    """Adiciona um hook global ou de pacote."""
    entry = {"command": command, "priority": priority, "sandbox": sandbox}
    if package:
        PACKAGE_HOOKS.setdefault(package, {}).setdefault(event, []).append(entry)
    else:
        GLOBAL_HOOKS.setdefault(event, []).append(entry)


def remove_hook(event, command, package=None):
    """Remove um hook."""
    hooks = GLOBAL_HOOKS.get(event, []) if not package else PACKAGE_HOOKS.get(package, {}).get(event, [])
    hooks[:] = [h for h in hooks if h["command"] != command]


def list_hooks(package=None):
    """Lista hooks globais e por pacote."""
    if package:
        return PACKAGE_HOOKS.get(package, {})
    return GLOBAL_HOOKS


def disable_hook(event, package=None):
    """Desabilita hooks para um evento."""
    if package:
        if package in PACKAGE_HOOKS and event in PACKAGE_HOOKS[package]:
            PACKAGE_HOOKS[package][event] = []
    else:
        GLOBAL_HOOKS[event] = []


def load_hooks_from_meta(meta_file, package_name):
    """Carrega hooks definidos em um arquivo .meta (TOML/JSON)."""
    import tomllib, json
    path = Path(meta_file)
    if not path.exists():
        return

    if path.suffix == ".toml":
        data = tomllib.loads(path.read_text())
    else:
        data = json.loads(path.read_text())

    if "hooks" in data:
        for event, cmds in data["hooks"].items():
            for cmd in cmds:
                add_hook(event, cmd, package=package_name)


def load_global_hooks(cfg):
    """Carrega hooks globais do config.toml"""
    hooks = cfg.get("global_hooks", {})
    for event, cmds in hooks.items():
        for cmd in cmds:
            add_hook(event, cmd)

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def cli_main(argv):
    import argparse

    parser = argparse.ArgumentParser(prog="pkgtool-hook", description="Gerenciador de hooks do pkgtool")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="Lista hooks")
    runp = sub.add_parser("run", help="Executa hooks manualmente")
    runp.add_argument("event", choices=SUPPORTED_EVENTS)
    runp.add_argument("--package")

    args = parser.parse_args(argv)

    if args.cmd == "list":
        print(json.dumps({"global": GLOBAL_HOOKS, "packages": PACKAGE_HOOKS}, indent=2))
    elif args.cmd == "run":
        run(args.event, args.package, context={"manual": True})
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_main(sys.argv[1:])
