# Pkgtool/pkgtool1.0/modules/masks.py
# -*- coding: utf-8 -*-
"""
masks.py - policy & masking subsystem for pkgtool

Features:
- hierarchical masks: global, profile, user (user > profile > global)
- conditional masks (arch, kernel, custom predicates)
- priorities: numeric priority decides conflicts
- wildcards, glob, regex for package names and version specs
- unstable handling (~)
- slot masks: mask by slot (e.g., dev-lang/python:3.8)
- audit log for decisions
- simulate() to display rule evaluation steps
- CLI 'pkgtool-mask' with list/check/add/remove/simulate/audit/export/import/apply-profile
- integration with modules.config (cfg) and modules.log (logger) when present
- persistence in TOML/JSON (auto-detect)
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fnmatch
import functools
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Try to import packaging.version for robust version compare
try:
    from packaging.version import Version, InvalidVersion
    _have_packaging = True
except Exception:
    _have_packaging = False

# TOML support (tomllib in 3.11 or toml fallback)
_try_tomllib = False
try:
    import tomllib  # type: ignore
    _try_tomllib = True
    def _load_toml_bytes(b: bytes) -> dict:
        return tomllib.loads(b.decode("utf-8")) if isinstance(b, (bytes, bytearray)) else tomllib.loads(b)
except Exception:
    try:
        import toml  # type: ignore
        _try_tomllib = True
        def _load_toml_bytes(b: bytes) -> dict:
            return toml.loads(b.decode("utf-8")) if isinstance(b, (bytes, bytearray)) else toml.loads(b)
    except Exception:
        _try_tomllib = False

# Try to import config and log if present
try:
    from modules.config import cfg  # type: ignore
except Exception:
    cfg = None

try:
    from modules import log as _logmod  # type: ignore
    _logger = _logmod.get_logger("pkgtool.masks")
except Exception:
    import logging as _logging
    _logger = _logging.getLogger("pkgtool.masks")
    if not _logger.handlers:
        _logger.addHandler(_logging.StreamHandler())
    _logger.setLevel(_logging.INFO)


# Lock helper (simple file lock)
_lock = threading.RLock()

# Default mask file locations (repo local + /etc)
_DEFAULT_MASK_PATHS = [
    Path.cwd() / "Pkgtool" / "pkgtool1.0" / "masks.toml",
    Path("/etc/pkgtool/masks.toml"),
    Path.cwd() / "masks.toml",
]

DEFAULT_MASK_SAMPLE = r"""
# masks.toml - sample
# Scopes: global, profile.<name>, user
# Each rule key is a package pattern (glob or regex if regex=true).
# Value can be:
#   - boolean "allow"/"deny" (true/false)
#   - string with version constraint, e.g "<1.2.0", ">=2.0", "=1.2.3", "~*"
#   - dict: { rule="...", slot="3.8", priority=50, regex=false, cond={arch="arm64"} }
#
[global]
"sys-libs/glibc" = "<2.30"
"dev-lang/python:3.8" = { rule = "*", priority = 80 }  # slot-specific rule

[profile.server]
"net-misc/openssl" = { rule = "~*", priority = 20 }

[user]
"dev-lang/python" = { rule = ">=3.11", priority = 200 }
"""

# Data structures

@dataclass
class MaskRule:
    """
    Representation of a single mask rule.
    Fields:
      pattern: package pattern (glob-like) OR regex if regex=True
      rule: rule string: "*", "~*", "<1.2.3", ">=1.0", "=1.0.0", etc.
      slot: Optional slot identifier (e.g., '3.8')
      scope: one of 'global', 'profile:<name>', 'user'
      priority: integer priority (higher wins)
      regex: whether pattern is a regex
      cond: optional dict of conditions (arch, kernel, env)
      created_by: optional origin (path/cli)
      created_at: iso timestamp
    """
    pattern: str
    rule: str = "*"
    slot: Optional[str] = None
    scope: str = "global"
    priority: int = 0
    regex: bool = False
    cond: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "rule": self.rule,
            "slot": self.slot,
            "scope": self.scope,
            "priority": self.priority,
            "regex": self.regex,
            "cond": self.cond,
            "created_by": self.created_by,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "MaskRule":
        return MaskRule(
            pattern=d["pattern"],
            rule=d.get("rule", "*"),
            slot=d.get("slot"),
            scope=d.get("scope", "global"),
            priority=int(d.get("priority", 0) or 0),
            regex=bool(d.get("regex", False)),
            cond=dict(d.get("cond", {})),
            created_by=d.get("created_by"),
            created_at=d.get("created_at", datetime.utcnow().isoformat() + "Z"),
        )

# Internal state
_state = {
    "rules": [],  # List[MaskRule]
    "loaded_from": None,  # Path
    "profiles": {},  # profile definitions (if any)
    "unstable": {"global": False, "accepted": []},  # basic unstable policy
    "audit_log": None,  # Path to audit log
}


# ----------------- Version comparison helpers -----------------

def _parse_version(v: str) -> Union[Version, Tuple[int, ...], str]:
    if _have_packaging:
        try:
            return Version(v)
        except Exception:
            return v
    # fallback: split numeric parts
    parts = []
    for p in re.split(r"[.+-]", v):
        if p.isdigit():
            parts.append(int(p))
        else:
            parts.append(p)
    return tuple(parts)

def _cmp_version(v1: str, v2: str) -> int:
    """
    Compare v1 to v2.
    Return -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
    Best-effort: uses packaging when available, else naive compare.
    """
    if v1 == v2:
        return 0
    p1 = _parse_version(v1)
    p2 = _parse_version(v2)
    try:
        if _have_packaging and isinstance(p1, Version) and isinstance(p2, Version):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
            else:
                return 0
        # fallback tuple compare
        if isinstance(p1, tuple) and isinstance(p2, tuple):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
            else:
                return 0
    except Exception:
        pass
    # as last resort compare strings
    if str(v1) < str(v2):
        return -1
    elif str(v1) > str(v2):
        return 1
    return 0

def _version_satisfies(spec: str, version: str) -> bool:
    """
    Check if version satisfies spec.
    spec examples:
      "*", "~*", "<1.2.0", "<=1.2", ">2.0", ">=1.2.3", "=1.2.3", "!=1.2.3", "=1.2.*" (glob)
    "~*" means unstable allowed wildcard
    """
    spec = spec.strip()
    if spec in ("*", ""):
        return True
    if spec == "~*":
        # define as always true for matching unstable allowance (handled separately)
        return True
    # handle glob style e.g. "1.2.*" or "=1.2.*"
    if spec.startswith("="):
        spec2 = spec[1:]
        if "*" in spec2:
            pattern = "^" + re.escape(spec2).replace(r"\*", ".*") + "$"
            return re.match(pattern, version) is not None
        return _cmp_version(version, spec2) == 0
    # inequality
    m = re.match(r"^(<=|>=|<|>|!=)\s*(.+)$", spec)
    if m:
        op, sval = m.group(1), m.group(2)
        c = _cmp_version(version, sval)
        if op == "<":
            return c == -1
        if op == "<=":
            return c in (-1, 0)
        if op == ">":
            return c == 1
        if op == ">=":
            return c in (1, 0)
        if op == "!=":
            return c != 0
    # plain glob or exact
    if "*" in spec:
        pattern = "^" + re.escape(spec).replace(r"\*", ".*") + "$"
        return re.match(pattern, version) is not None
    # exact
    return _cmp_version(version, spec) == 0

# ----------------- Rule parsing & matching -----------------

def _normalize_pattern(pat: str) -> str:
    return pat.strip()

def _pattern_matches(pattern: str, pkg_name: str, regex: bool = False) -> bool:
    if regex:
        try:
            return re.search(pattern, pkg_name) is not None
        except re.error:
            return False
    # allow glob matching (fnmatch) and also direct equality
    if pattern == pkg_name:
        return True
    # support '*' wildcard
    return fnmatch.fnmatch(pkg_name, pattern)

def _slot_matches(rule_slot: Optional[str], slot: Optional[str]) -> bool:
    if rule_slot is None:
        return True
    if slot is None:
        return False
    return str(rule_slot) == str(slot)

def _conditions_match(cond: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Evaluate simple conditions: arch, kernel, env, profile matches.
    cond keys could be 'arch', 'kernel_ge', 'kernel_lt', 'env.<NAME>' etc.
    """
    if not cond:
        return True
    # arch
    arch = context.get("arch")
    if "arch" in cond:
        if cond["arch"] != arch:
            return False
    # kernel comparisons (assume string versions)
    kernel = context.get("kernel_version")
    if kernel:
        if "kernel_ge" in cond:
            if _cmp_version(kernel, str(cond["kernel_ge"])) < 0:
                return False
        if "kernel_lt" in cond:
            if _cmp_version(kernel, str(cond["kernel_lt"])) >= 0:
                return False
    # env checks
    for k, v in cond.items():
        if k.startswith("env."):
            envk = k.split(".", 1)[1]
            if os.environ.get(envk) != str(v):
                return False
    return True

# ----------------- Core API -----------------

def load_masks(path: Optional[Union[str, Path]] = None, *, from_cfg: bool = True) -> None:
    """
    Load masks from file. If path is None and from_cfg is True, try cfg.get('masks.file').
    Otherwise search default locations.
    The file can be TOML or JSON. If multiple scope tables exist, they are flattened into MaskRule objects.
    """
    with _lock:
        target = None
        # try explicit path
        if path:
            target = Path(path)
        else:
            # if config given
            if from_cfg and cfg is not None:
                try:
                    mconf = cfg.get("masks") or {}
                    if isinstance(mconf, dict) and "file" in mconf:
                        candidate = Path(mconf["file"])
                        if candidate.exists():
                            target = candidate
                except Exception:
                    pass
            # find in default locations
            if target is None:
                for p in _DEFAULT_MASK_PATHS:
                    if p.exists():
                        target = p
                        break
        if target is None:
            _logger.info("No masks file found; using empty rule set.")
            _state["rules"] = []
            _state["loaded_from"] = None
            # configure audit default
            _state["audit_log"] = _state.get("audit_log") or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "masks.audit.log")
            return
        # read file
        try:
            raw = target.read_bytes()
            data = None
            if target.suffix.lower() in (".toml",):
                if not _try_tomllib:
                    raise RuntimeError("TOML not available; install toml library")
                data = _load_toml_bytes(raw)
            elif target.suffix.lower() in (".json",):
                data = json.loads(raw.decode("utf-8"))
            else:
                # try toml then json
                if _try_tomllib:
                    try:
                        data = _load_toml_bytes(raw)
                    except Exception:
                        data = json.loads(raw.decode("utf-8"))
                else:
                    data = json.loads(raw.decode("utf-8"))
            # parse into rules
            rules: List[MaskRule] = []
            # top-level keys may be scopes: global, profile.<name>, user
            for scope_k, block in (data.items() if isinstance(data, dict) else []):
                if scope_k == "profiles":
                    _state["profiles"] = dict(block or {})
                    continue
                if scope_k == "unstable":
                    _state["unstable"].update(block or {})
                    continue
                scope_name = scope_k
                # when block is mapping of patterns -> rule
                if isinstance(block, dict):
                    for patt, v in block.items():
                        # normalize value v
                        if isinstance(v, (str, int, float, bool)):
                            rule_str = str(v)
                            entry = {"pattern": patt, "rule": rule_str}
                        elif isinstance(v, dict):
                            entry = dict(v)
                            entry["pattern"] = patt
                        else:
                            # unsupported
                            continue
                        # extract slot if specified as part of pattern like "pkg:slot" or "pkg(slot=3.8)"
                        patt2, slot = _extract_slot_from_pattern(entry["pattern"])
                        entry["pattern"] = patt2
                        if "slot" not in entry and slot:
                            entry["slot"] = slot
                        # default fields
                        entry.setdefault("scope", scope_name)
                        entry.setdefault("priority", 0)
                        entry.setdefault("regex", False)
                        mr = MaskRule.from_dict(entry)
                        rules.append(mr)
                else:
                    # ignore non-dict blocks
                    continue
            _state["rules"] = sorted(rules, key=lambda r: r.priority, reverse=True)
            _state["loaded_from"] = target
            # audit log default location
            try:
                apr = Path(cfg.get("masks", {}).get("audit_log")) if cfg is not None else None
                if apr:
                    _state["audit_log"] = apr
                else:
                    _state["audit_log"] = target.parent / "masks.audit.log"
            except Exception:
                _state["audit_log"] = target.parent / "masks.audit.log"
            _logger.info("Loaded %d mask rules from %s", len(_state["rules"]), target)
        except Exception as e:
            _logger.exception("Failed to load masks from %s: %s", target, e)
            _state["rules"] = []
            _state["loaded_from"] = None

def _extract_slot_from_pattern(pattern: str) -> Tuple[str, Optional[str]]:
    """
    Support pattern encodings:
     - "dev-lang/python:3.8"
     - "dev-lang/python(slot=3.8)"
     - "dev-lang/python:3.8[slot]" (less common)
    Return (pattern_without_slot, slot_or_none)
    """
    p = pattern
    # pattern: "name:slot"
    m = re.match(r"^(.+?):([^:\/\s\[]+)$", p)
    if m:
        return m.group(1), m.group(2)
    # pattern: "name(slot=3.8)"
    m = re.match(r"^(.+?)\(\s*slot\s*=\s*['\"]?([^'\")]+)['\"]?\s*\)$", p)
    if m:
        return m.group(1), m.group(2)
    # fallback
    return p, None

def save_masks(path: Optional[Union[str, Path]] = None, *, format: str = "toml") -> None:
    """
    Persist current in-memory rules to file.
    If path omitted, prefer loaded_from or default repo location.
    """
    with _lock:
        target = Path(path) if path else ( _state.get("loaded_from") or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "masks.toml") )
        obj: Dict[str, Dict[str, Any]] = {}
        # group by scope
        for r in _state["rules"]:
            scope = r.scope
            obj.setdefault(scope, {})
            key = r.pattern
            val: Any
            # collapse to simple if possible
            if r.slot:
                # represent with dict
                val = {"rule": r.rule, "slot": r.slot, "priority": r.priority, "regex": r.regex, "cond": r.cond}
            elif r.priority != 0 or r.regex or r.cond:
                val = {"rule": r.rule, "priority": r.priority, "regex": r.regex, "cond": r.cond}
            else:
                # plain rule string
                val = r.rule
            obj[scope][key] = val
        # optionally include profiles/unstable
        meta = {"profiles": _state.get("profiles", {}), "unstable": _state.get("unstable", {})}
        # write toml if possible else json
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            if format == "toml" and _try_tomllib:
                # we have toml library or tomllib (but tomllib has no dumps) -> try 'toml' module if present
                if "toml" in sys.modules:
                    dumps = sys.modules["toml"].dumps  # type: ignore
                    content = dumps({**obj, **meta})
                    target.write_text(content, encoding="utf-8")
                else:
                    # fallback: write JSON into .toml if no dumps available
                    target.write_text(json.dumps({**obj, **meta}, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                # JSON
                target.write_text(json.dumps({**obj, **meta}, indent=2, ensure_ascii=False), encoding="utf-8")
            _state["loaded_from"] = target
            _logger.info("Masks saved to %s", target)
        except Exception:
            _logger.exception("Failed to save masks to %s", target)
            raise

# ---------------- Rule evaluation ----------------

@dataclass
class EvalStep:
    rule: Optional[MaskRule]
    matched: bool
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvalResult:
    allowed: bool
    by_rule: Optional[MaskRule]
    steps: List[EvalStep] = field(default_factory=list)
    message: Optional[str] = None

def _evaluate_single_rule(rule: MaskRule, pkg_name: str, version: str, slot: Optional[str], context: Dict[str, Any]) -> EvalStep:
    """
    Evaluate one MaskRule against package info. Return EvalStep describing decision for this rule.
    """
    # pattern match?
    matched_pattern = _pattern_matches(rule.pattern, pkg_name, regex=rule.regex)
    if not matched_pattern:
        return EvalStep(rule, False, "pattern_mismatch")
    # slot match
    if not _slot_matches(rule.slot, slot):
        return EvalStep(rule, False, "slot_mismatch", {"rule_slot": rule.slot, "slot": slot})
    # cond match
    if not _conditions_match(rule.cond, context):
        return EvalStep(rule, False, "cond_not_met", {"cond": rule.cond})
    # version rule
    r = rule.rule.strip()
    # rule bool forms
    if r.lower() in ("deny", "false", "no", "0"):
        return EvalStep(rule, True, "deny_exact")
    if r.lower() in ("allow", "true", "yes", "1"):
        return EvalStep(rule, True, "allow_exact")
    # unstable marker
    if r == "~*":
        # treat as allowing unstable; actual unstable acceptance logic outside
        return EvalStep(rule, True, "allow_unstable")
    # wildcard
    if r == "*" or r == "":
        return EvalStep(rule, True, "allow_wildcard")
    # version comparator
    try:
        if _version_satisfies(r, version):
            # if operator is of deny nature? we treat spec as mask => means masks block matching spec.
            # But we need convention: rules in masks are typically blocking (i.e., mask).
            # We'll interpret that if rule present in mask set, it *blocks* the versions that match.
            return EvalStep(rule, True, "mask_match_version", {"spec": r, "version": version})
        else:
            return EvalStep(rule, False, "version_not_match", {"spec": r, "version": version})
    except Exception as e:
        return EvalStep(rule, False, "eval_error", {"error": str(e)})

def evaluate(pkg_name: str, version: str, slot: Optional[str] = None, *,
             arch: Optional[str] = None, profile: Optional[str] = None, user_override: Optional[Dict[str, Any]] = None,
             kernel_version: Optional[str] = None, simulate: bool = False) -> EvalResult:
    """
    Evaluate masks for a given package name, version, and optional slot/arch/profile.
    Returns EvalResult with allowed True/False and steps explaining evaluation.
    Logic:
      - Order rules by priority desc; user scope rules first by priority.
      - For each rule that matches pattern/slot/cond, interpret rule:
          - If rule is deny/explicit mask -> mark blocked (allowed=False) and return with reason
          - If rule is allow -> allowed=True (but keep scanning to see if a higher priority deny exists)
      - If no matching rules -> allowed by default (True) unless unstable handling disallows.
    """
    with _lock:
        context = {"arch": arch, "profile": profile, "kernel_version": kernel_version}
        if user_override is None:
            user_override = {}
        steps: List[EvalStep] = []
        matched_rules: List[MaskRule] = []
        # sort rules: user overrides first, then profile, then global. Within same scope, priority desc.
        def scope_rank(s: str) -> int:
            if s.startswith("user"):
                return 3
            if profile and s == f"profile.{profile}":
                return 2
            if s.startswith("profile."):
                return 1
            return 0
        sorted_rules = sorted(_state["rules"], key=lambda r: (scope_rank(r.scope), r.priority), reverse=True)
        decision_allow = True
        triggered_rule = None
        for r in sorted_rules:
            step = _evaluate_single_rule(r, pkg_name, version, slot, context)
            steps.append(step)
            if not step.matched:
                continue
            # matched: step.reason explains match type
            matched_rules.append(r)
            # Interpret: rules in masks are typically *masks* => deny matching versions.
            # But if r.rule indicates allow (like "allow" or "*"), we may permissively allow.
            rule_str = r.rule.strip().lower()
            # If rule explicitly allow
            if rule_str in ("allow", "true", "yes", "1", "*"):
                # allow, but a higher-priority rule could still deny; since sorted by priority, first matching rule wins.
                decision_allow = True
                triggered_rule = r
                break
            if rule_str in ("deny", "false", "no", "0"):
                decision_allow = False
                triggered_rule = r
                break
            if rule_str == "~*":
                # allow unstable; but actual policy uses _state["unstable"] to determine acceptance
                # If global unstable is False and rule matched ~*, then treat as "allow only if package in accepted list"
                unstable_policy = _state.get("unstable", {}) or {}
                if unstable_policy.get("global", False):
                    decision_allow = True
                else:
                    # check accepted list
                    accepted = set(unstable_policy.get("accepted", []) or [])
                    if pkg_name in accepted:
                        decision_allow = True
                    else:
                        decision_allow = False
                triggered_rule = r
                break
            # else, treat spec as mask (deny) if match succeeded
            # If _version_satisfies returned true earlier, then step.matched True and reason 'mask_match_version'
            if step.reason.startswith("mask_match_version") or step.reason in ("allow_wildcard", "allow_unstable"):
                # interpret as deny - masks typically indicate blocked versions
                decision_allow = False
                triggered_rule = r
                break
        # if no triggered rule and no matches
        if triggered_rule is None:
            # default: allowed
            decision_allow = True
        # incorporate user_override boolean (explicit allow/deny)
        if "allow" in user_override:
            decision_allow = bool(user_override["allow"])
        # build result
        res = EvalResult(allowed=decision_allow, by_rule=triggered_rule, steps=steps,
                         message=(None if triggered_rule is None else f"Matched rule {triggered_rule.pattern} in {triggered_rule.scope}"))
        # audit decision
        try:
            _audit_decision(pkg_name, version, slot, arch, profile, decision_allow, triggered_rule, context)
        except Exception:
            _logger.debug("audit failed", exc_info=True)
        if simulate:
            return res
        return res

def is_allowed(pkg_name: str, version: str, slot: Optional[str] = None, *,
               arch: Optional[str] = None, profile: Optional[str] = None, user_override: Optional[Dict[str, Any]] = None,
               kernel_version: Optional[str] = None) -> bool:
    return evaluate(pkg_name, version, slot, arch=arch, profile=profile, user_override=user_override, kernel_version=kernel_version).allowed

def reason(pkg_name: str, version: str, slot: Optional[str] = None, *,
           arch: Optional[str] = None, profile: Optional[str] = None) -> str:
    r = evaluate(pkg_name, version, slot, arch=arch, profile=profile, simulate=True)
    if r.by_rule is None:
        return "no_mask_applies"
    return f"{'allowed' if r.allowed else 'blocked'} by {r.by_rule.scope} rule '{r.by_rule.pattern}' (priority={r.by_rule.priority})"

# ---------------- Audit ----------------

def _audit_decision(pkg_name: str, version: str, slot: Optional[str], arch: Optional[str], profile: Optional[str],
                    allowed: bool, rule: Optional[MaskRule], context: Dict[str, Any]) -> None:
    rec = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "package": pkg_name,
        "version": version,
        "slot": slot,
        "arch": arch,
        "profile": profile,
        "decision": "allowed" if allowed else "blocked",
        "rule": rule.to_dict() if rule else None,
        "context": context,
    }
    try:
        logp = _state.get("audit_log") or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "masks.audit.log")
        logp.parent.mkdir(parents=True, exist_ok=True)
        # append JSON line
        with open(logp, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        _logger.exception("Failed to write audit log")

def audit_tail(n: Optional[int] = 100) -> List[Dict[str, Any]]:
    """
    Read last n audit entries (JSON lines).
    """
    logp = _state.get("audit_log") or (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "masks.audit.log")
    if not logp.exists():
        return []
    out = []
    with open(logp, "r", encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
    return out[-n:]

# ---------------- Rule management ----------------

def add_rule(pattern: str, rule: str = "*", *, slot: Optional[str] = None, scope: str = "user",
             priority: int = 0, regex: bool = False, cond: Optional[Dict[str, Any]] = None,
             created_by: Optional[str] = None, persist: bool = True) -> MaskRule:
    """
    Add a mask rule into the in-memory list. scope default 'user'.
    Returns MaskRule object.
    """
    with _lock:
        patt, slot_from_pattern = _extract_slot_from_pattern(pattern)
        if slot is None:
            slot = slot_from_pattern
        mr = MaskRule(pattern=_normalize_pattern(patt), rule=rule, slot=slot, scope=scope,
                      priority=int(priority or 0), regex=bool(regex), cond=dict(cond or {}),
                      created_by=created_by or "cli")
        _state["rules"].append(mr)
        # keep rules sorted by priority desc
        _state["rules"].sort(key=lambda r: r.priority, reverse=True)
        if persist:
            try:
                save_masks(_state.get("loaded_from"))
            except Exception:
                _logger.debug("Failed to persist masks after add", exc_info=True)
        _logger.info("Added mask rule %s (scope=%s priority=%d)", mr.pattern, mr.scope, mr.priority)
        return mr

def remove_rule(pattern: str, scope: Optional[str] = None, slot: Optional[str] = None, persist: bool = True) -> int:
    """
    Remove rules matching pattern and optionally scope/slot. Returns number removed.
    """
    with _lock:
        patt, slot_from = _extract_slot_from_pattern(pattern)
        s = _normalize_pattern(patt)
        slot_q = slot or slot_from
        before = len(_state["rules"])
        newrules = []
        for r in _state["rules"]:
            if r.pattern == s and (scope is None or r.scope == scope) and (slot_q is None or r.slot == slot_q):
                # skip (remove)
                continue
            newrules.append(r)
        removed = before - len(newrules)
        _state["rules"] = newrules
        if persist:
            try:
                save_masks(_state.get("loaded_from"))
            except Exception:
                _logger.debug("Failed to persist masks after remove", exc_info=True)
        _logger.info("Removed %d mask rules for pattern %s", removed, s)
        return removed

def list_rules(scope: Optional[str] = None) -> List[MaskRule]:
    with _lock:
        if scope is None:
            return list(_state["rules"])
        return [r for r in _state["rules"] if r.scope == scope]

def export_rules(path: Optional[Union[str, Path]] = None, format: str = "json") -> Path:
    p = Path(path) if path else (Path.cwd() / "Pkgtool" / "pkgtool1.0" / "masks.export.json")
    obj = [r.to_dict() for r in _state["rules"]]
    p.parent.mkdir(parents=True, exist_ok=True)
    if format == "json":
        p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        # try to write toml-like if toml available
        if _try_tomllib:
            if "toml" in sys.modules:
                dumps = sys.modules["toml"].dumps  # type: ignore
                p.write_text(dumps({"rules": obj}), encoding="utf-8")
            else:
                p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return p

def import_rules(path: Union[str, Path], scope: Optional[str] = None, persist: bool = True) -> int:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    data = p.read_text(encoding="utf-8")
    arr = None
    if p.suffix.lower() in (".json",):
        arr = json.loads(data)
    else:
        # try toml or json
        if _try_tomllib:
            try:
                arr = _load_toml_bytes(data.encode("utf-8")).get("rules")
            except Exception:
                arr = json.loads(data)
        else:
            arr = json.loads(data)
    count = 0
    for item in arr:
        mr = MaskRule.from_dict(item)
        if scope:
            mr.scope = scope
        _state["rules"].append(mr)
        count += 1
    # resort
    _state["rules"].sort(key=lambda r: r.priority, reverse=True)
    if persist:
        save_masks(_state.get("loaded_from"))
    return count

# ---------------- Simulation / Debug ----------------

def simulate(pkg_spec: str, *, arch: Optional[str] = None, profile: Optional[str] = None, slot: Optional[str] = None,
             kernel_version: Optional[str] = None, show_steps: bool = True) -> EvalResult:
    """
    pkg_spec examples: "dev-lang/python-3.8.10", or "dev-lang/python", must include version to evaluate version masks.
    If version missing, uses '0' as placeholder and focuses on pattern/slot matches.
    """
    # try to extract name and version
    m = re.match(r"^([^/:\s]+(?:/[^/:\s]+)*?)(?:[ _:-]v?([0-9].*))?$", pkg_spec)
    if m:
        name = m.group(1)
        version = m.group(2) or "0"
    else:
        # fallback splitting last dash
        if "-" in pkg_spec:
            name, version = pkg_spec.rsplit("-", 1)
        else:
            name, version = pkg_spec, "0"
    return evaluate(name, version, slot, arch=arch, profile=profile, kernel_version=kernel_version, simulate=show_steps)

# ---------------- CLI ----------------

def _cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkgtool-mask", description="Masking / policy manager for pkgtool")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List mask rules (scope optionally set via --scope)").add_argument("--scope", "-s", help="Scope name", default=None)
    p_check = sub.add_parser("check", help="Check if a package is allowed (pkg-version or pkg) and explain")
    p_check.add_argument("pkg", help="pkg or pkg-version (e.g. dev-lang/python-3.8.10)")
    p_check.add_argument("--slot", help="slot (e.g. 3.8)")
    p_check.add_argument("--arch", help="arch")
    p_check.add_argument("--profile", help="profile")
    p_check.add_argument("--kernel", help="kernel version")

    p_add = sub.add_parser("add", help="Add mask rule")
    p_add.add_argument("pattern", help="package pattern (supports slot like pkg:3.8)")
    p_add.add_argument("rule", help="rule string (e.g. '<1.2.0' or '*', '~*', 'deny')")
    p_add.add_argument("--scope", "-s", default="user", help="scope ('user'|'global'|'profile.NAME')")
    p_add.add_argument("--slot", help="slot override")
    p_add.add_argument("--priority", type=int, default=0)
    p_add.add_argument("--regex", action="store_true")
    p_add.add_argument("--cond", help="conditions as JSON string (e.g. '{\"arch\":\"arm64\"}')")

    p_rm = sub.add_parser("remove", help="Remove mask rules by pattern")
    p_rm.add_argument("pattern")
    p_rm.add_argument("--scope", help="optional scope to restrict removal")

    p_sim = sub.add_parser("simulate", help="Simulate evaluation for a package")
    p_sim.add_argument("pkg")
    p_sim.add_argument("--slot")
    p_sim.add_argument("--arch")
    p_sim.add_argument("--profile")
    p_sim.add_argument("--kernel")

    p_audit = sub.add_parser("audit", help="Show audit decisions")
    p_audit.add_argument("--last", type=int, default=50)

    p_export = sub.add_parser("export", help="Export rules to file")
    p_export.add_argument("--out", "-o", help="output path", default=None)
    p_export.add_argument("--format", choices=["json", "toml"], default="json")

    p_import = sub.add_parser("import", help="Import rules from file")
    p_import.add_argument("path")
    p_import.add_argument("--scope", help="override scope for imported rules")

    p_apply = sub.add_parser("apply-profile", help="Apply a profile (copy its masks to user scope)")
    p_apply.add_argument("profile")

    return p

def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = _cli_parser()
    args = parser.parse_args(argv if argv is not None else None)
    try:
        # ensure masks loaded
        load_masks()
    except Exception:
        _logger.debug("load masks error", exc_info=True)

    try:
        if args.cmd == "list":
            rules = list_rules(scope=args.scope)
            for r in rules:
                print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
            return 0

        if args.cmd == "check":
            r = simulate(args.pkg, slot=getattr(args, "slot", None), arch=getattr(args, "arch", None),
                         profile=getattr(args, "profile", None), kernel_version=getattr(args, "kernel", None),
                         show_steps=True)
            print("ALLOWED:" if r.allowed else "BLOCKED:", r.message)
            for st in r.steps:
                print(f"- rule {st.rule.pattern if st.rule else '(none)'} matched={st.matched} reason={st.reason} details={st.details}")
            return 0

        if args.cmd == "add":
            cond = {}
            if getattr(args, "cond", None):
                try:
                    cond = json.loads(args.cond)
                except Exception:
                    print("Invalid cond JSON", file=sys.stderr)
                    return 2
            mr = add_rule(args.pattern, args.rule, slot=args.slot, scope=args.scope, priority=args.priority, regex=bool(args.regex), cond=cond, persist=True)
            print("Added:", mr.to_dict())
            return 0

        if args.cmd == "remove":
            removed = remove_rule(args.pattern, scope=getattr(args, "scope", None))
            print("Removed rules:", removed)
            return 0

        if args.cmd == "simulate":
            r = simulate(args.pkg, slot=getattr(args, "slot", None), arch=getattr(args, "arch", None),
                         profile=getattr(args, "profile", None), kernel_version=getattr(args, "kernel", None), show_steps=True)
            print("ALLOWED" if r.allowed else "BLOCKED", r.message)
            for i, st in enumerate(r.steps):
                print(f"{i+1}. [{st.reason}] {st.rule.pattern if st.rule else 'no-rule'} matched={st.matched} details={st.details}")
            return 0

        if args.cmd == "audit":
            last = getattr(args, "last", 50)
            entries = audit_tail(last)
            for e in entries:
                print(json.dumps(e, ensure_ascii=False))
            return 0

        if args.cmd == "export":
            p = export_rules(path=args.out, format=args.format)
            print("Exported to", p)
            return 0

        if args.cmd == "import":
            ct = import_rules(args.path, scope=getattr(args, "scope", None))
            print(f"Imported {ct} rules")
            return 0

        if args.cmd == "apply-profile":
            profile = args.profile
            prof_rules = _state.get("profiles", {}).get(profile)
            if not prof_rules:
                print("Profile not found or has no rules", file=sys.stderr)
                return 2
            # prof_rules expected as mapping pattern -> rule/dict
            count = 0
            for patt, val in prof_rules.items():
                if isinstance(val, (str, int, float, bool)):
                    rule = str(val)
                    add_rule(patt, rule, scope="user", persist=False)
                    count += 1
                elif isinstance(val, dict):
                    add_rule(patt, val.get("rule", "*"), slot=val.get("slot"), scope="user", priority=val.get("priority", 0), regex=val.get("regex", False), cond=val.get("cond"), persist=False)
                    count += 1
            # persist once
            save_masks(_state.get("loaded_from"))
            print("Applied profile to user scope:", count, "rules")
            return 0

    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        _logger.exception("Error in cli: %s", e)
        print("Error:", e, file=sys.stderr)
        return 2

    return 0

# ---------------- Auto-load on import if config provides file ----------------
try:
    load_masks()
except Exception:
    pass

# ---------------- Public API exposure ----------------
__all__ = [
    "MaskRule",
    "load_masks",
    "save_masks",
    "add_rule",
    "remove_rule",
    "list_rules",
    "is_allowed",
    "reason",
    "simulate",
    "audit_tail",
    "export_rules",
    "import_rules",
    "evaluate",
    "cli_main",
]
