"""Uso:  python -m vulnwatch alert|digest [--dry-run] [--days N]"""
import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from . import notify, report, sources
from .analysis import LEVELS, level_index, match_product, risk_level

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "state" / "state.json"
OUT = ROOT / "out"


def collect(start, end, inventory):
    """Baja todo, filtra por inventario y calcula el riesgo. Devuelve lista de dicts."""
    products = inventory["products"]
    raw = sources.fetch_nvd(start, end)
    for p in products:
        for pkg in p.get("packages", []):
            try:
                raw += [dict(a, _product=p["name"]) for a in
                        sources.fetch_ghsa(pkg["ecosystem"], pkg["name"], start)]
            except Exception as e:  # GHSA es complementario: no frenar todo
                print(f"[aviso] GHSA {pkg['name']}: {e}", file=sys.stderr)

    found = {}
    for v in raw:
        hits = []
        if "_product" in v:
            prod = next(p for p in products if p["name"] == v["_product"])
            hits.append((prod, {"affects_me": None, "fixed": v.get("fixed", "")}))
        else:
            hits = [(p, m) for p in products if (m := match_product(v, p))]
        for prod, m in hits:
            cur = found.setdefault(v["id"], {**v, "products": [], "fixed": "", "_aff": [],
                                             "only_kev": True})
            cur["products"].append(prod["name"])
            cur["only_kev"] &= bool(prod.get("only_kev"))
            cur["_aff"].append(m["affects_me"])
            if m["fixed"] and m["fixed"] not in cur["fixed"]:
                cur["fixed"] = (cur["fixed"] + " " + m["fixed"]).strip()
    for cur in found.values():
        aff = cur.pop("_aff")
        cur["affects_me"] = True if True in aff else None if None in aff else False

    kev = sources.fetch_kev()
    epss = sources.fetch_epss(found.keys()) if found else {}
    result = []
    for v in found.values():
        if v.pop("only_kev") and v["id"] not in kev:
            continue
        v["kev"] = v["id"] in kev
        v["epss"] = epss.get(v["id"], 0.0)
        v["level"] = risk_level(v, kev, v["epss"])
        result.append(v)
    return result


def load_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {"seen": {}, "last_run": None}


def run_alert(inventory, dry):
    st = load_state()
    end = sources.now()
    start = datetime.fromisoformat(st["last_run"]) - timedelta(hours=1) if st["last_run"] \
        else end - timedelta(days=2)
    vulns = collect(start, end, inventory)
    min_idx = level_index(inventory.get("min_alert_level", "alto"))
    new = []
    for v in vulns:
        if v.get("affects_me") is False or level_index(v["level"]) < min_idx:
            continue
        prev = st["seen"].get(v["id"])
        if prev is None or level_index(v["level"]) > level_index(prev):
            new.append(v)
    new.sort(key=lambda v: -level_index(v["level"]))
    print(f"{len(vulns)} relevantes, {len(new)} para avisar")
    if st["last_run"] is None:
        # primera corrida: registrar lo existente sin mandar un aluvión de avisos viejos
        print("Primera corrida: se registra el estado inicial sin avisar")
        if not dry and notify.telegram_configured():
            notify.send_telegram(f"✅ vulnwatch activo. Línea base registrada ({len(new)} hallazgos previos "
                                 "no se notifican). Desde ahora solo recibís novedades.")
        elif not dry:
            sys.exit("Faltan TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID")
    elif new:
        text = notify.format_alert(new)
        if dry:
            print(text)
        elif not notify.telegram_configured():
            sys.exit("Faltan TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID")
        else:
            notify.send_telegram(text)
    if not dry:
        for v in new:
            st["seen"][v["id"]] = v["level"]
        st["last_run"] = end.isoformat()
        STATE.parent.mkdir(exist_ok=True)
        STATE.write_text(json.dumps(st, indent=1, ensure_ascii=False))


def run_digest(inventory, dry, days):
    days = days or inventory.get("digest_days", 7)
    vulns = collect(sources.now() - timedelta(days=days), sources.now(), inventory)
    vulns = [v for v in vulns if v.get("affects_me") is not False]
    OUT.mkdir(exist_ok=True)
    xlsx, pdf = OUT / "vulnerabilidades.xlsx", OUT / "vulnerabilidades.pdf"
    report.write_excel(vulns, xlsx, days)
    report.write_pdf(vulns, pdf, days)
    counts = {lvl: sum(1 for v in vulns if v["level"] == lvl) for lvl in reversed(LEVELS)}
    summary = " | ".join(f"{k}: {n}" for k, n in counts.items())
    print(f"{len(vulns)} vulnerabilidades ({summary}). Archivos en {OUT}")
    if dry:
        return
    notify.send_mail(f"Reporte de vulnerabilidades — {summary}",
                     f"Resumen de los últimos {days} días.\n{summary}\n\nDetalle en el PDF y el Excel adjuntos.",
                     [pdf, xlsx])
    if notify.telegram_configured():
        notify.send_telegram(f"📬 Reporte semanal enviado por mail.\n{summary}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["alert", "digest"])
    ap.add_argument("--dry-run", action="store_true", help="no envía ni guarda estado")
    ap.add_argument("--days", type=int)
    a = ap.parse_args()
    inventory = yaml.safe_load((ROOT / "inventory.yml").read_text())
    if a.mode == "alert":
        run_alert(inventory, a.dry_run)
    else:
        run_digest(inventory, a.dry_run, a.days)
