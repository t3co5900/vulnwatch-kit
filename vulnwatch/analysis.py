"""Matching contra el inventario, comparación de versiones y nivel de riesgo."""
import re

from packaging.version import InvalidVersion, Version

LEVELS = ["bajo", "medio", "alto", "crítico"]
_BASE = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _ver(s):
    try:
        return Version(s)
    except (InvalidVersion, TypeError):
        return None


def _entry_affects(entry, installed):
    """True / False / None (no se puede saber) para una versión instalada."""
    inst = _ver(installed)
    if inst is None:
        return None
    lo_i, lo_e = entry.get("versionStartIncluding"), entry.get("versionStartExcluding")
    hi_i, hi_e = entry.get("versionEndIncluding"), entry.get("versionEndExcluding")
    if not any((lo_i, lo_e, hi_i, hi_e)):
        crit_ver = entry["criteria"].split(":")[5]
        if crit_ver == "*":
            return True
        if crit_ver == "-":
            return None
        v = _ver(crit_ver)
        return None if v is None else inst == v
    bounds = [(lo_i, lambda a, b: a >= b), (lo_e, lambda a, b: a > b),
              (hi_i, lambda a, b: a <= b), (hi_e, lambda a, b: a < b)]
    for raw, ok in bounds:
        if raw:
            b = _ver(raw)
            if b is None:
                return None
            if not ok(inst, b):
                return False
    return True


def match_product(vuln, product):
    """Devuelve dict {affects_me, fixed} si el CVE toca al producto, o None si no."""
    prefixes = tuple(product.get("cpes", []))
    entries = [m for m in vuln.get("cpe_matches", []) if m["criteria"].startswith(prefixes)]
    if entries:
        installed = product.get("installed") or []
        affects = None
        if installed:
            results = []
            for v in installed:
                per_entry = [_entry_affects(e, v) for e in entries]
                results.append(True if True in per_entry else None if None in per_entry else False)
            affects = True if True in results else None if None in results else False
        fixed = sorted({e["versionEndExcluding"] for e in entries if e.get("versionEndExcluding")})
        return {"affects_me": affects, "fixed": ", ".join(fixed)}
    # CVE sin análisis de NVD todavía: probar por palabras clave en la descripción
    if not vuln.get("has_config"):
        text = vuln.get("description", "")[:200]  # el producto afectado se nombra al principio
        if any(re.search(k, text, re.I) for k in product.get("keywords", [])):
            return {"affects_me": None, "fixed": ""}
    return None


def risk_level(vuln, kev, epss):
    """Nivel final: CVSS base, sube por KEV (explotación real), EPSS alto o si te afecta."""
    lvl = _BASE.get(vuln.get("severity"), 1)
    if vuln["id"] in kev:
        lvl = 3
    if (epss or 0) >= 0.5:
        lvl += 1
    if vuln.get("affects_me") is True:
        lvl += 1
    return LEVELS[min(lvl, 3)]


def level_index(name):
    return LEVELS.index(name)
