"""Descarga de datos: NVD, CISA KEV, EPSS y GitHub Security Advisories."""
import os
import time
from datetime import datetime, timezone

import requests

UA = {"User-Agent": "vulnwatch/1.0 (uso personal)"}
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"


def _get(url, params=None, headers=None, retries=6):
    for i in range(retries):
        r = requests.get(url, params=params, headers={**UA, **(headers or {})}, timeout=90)
        if r.status_code in (403, 429, 500, 502, 503, 504):
            time.sleep(10 * (i + 1))
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError(f"Falló {url} tras {retries} intentos")


def _nvd_date(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _metrics(cve):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        lst = cve.get("metrics", {}).get(key)
        if lst:
            m = lst[0]
            data = m["cvssData"]
            sev = data.get("baseSeverity") or m.get("baseSeverity")
            return data.get("baseScore"), (sev or "").upper() or None, data.get("vectorString")
    return None, None, None


def fetch_nvd(start, end):
    """Todos los CVE modificados entre start y end (el filtro por producto se hace local,
    porque los CVE recién publicados todavía no tienen CPE asignado en NVD)."""
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    pause = 0.8 if key else 6.5
    out, idx = [], 0
    while True:
        params = {
            "lastModStartDate": _nvd_date(start),
            "lastModEndDate": _nvd_date(end),
            "startIndex": idx,
            "resultsPerPage": 2000,
        }
        data = _get(NVD_URL, params, headers)
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            score, sev, vector = _metrics(c)
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            matches = [
                m
                for conf in c.get("configurations", [])
                for node in conf.get("nodes", [])
                for m in node.get("cpeMatch", [])
                if m.get("vulnerable")
            ]
            out.append({
                "id": c["id"],
                "description": desc,
                "published": c.get("published", ""),
                "modified": c.get("lastModified", ""),
                "score": score,
                "severity": sev,
                "vector": vector,
                "cpe_matches": matches,
                "has_config": bool(c.get("configurations")),
                "refs": [r["url"] for r in c.get("references", [])[:3]],
                "source": "NVD",
            })
        idx += data.get("resultsPerPage", 0)
        if idx >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
            break
        time.sleep(pause)
    return out


def fetch_kev():
    data = _get(KEV_URL)
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def fetch_epss(cve_ids):
    scores = {}
    ids = sorted(cve_ids)
    for i in range(0, len(ids), 100):
        data = _get(EPSS_URL, {"cve": ",".join(ids[i:i + 100])})
        for row in data.get("data", []):
            scores[row["cve"]] = float(row["epss"])
    return scores


def fetch_ghsa(ecosystem, package, since):
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = {
        "ecosystem": ecosystem,
        "affects": package,
        "type": "reviewed",
        "modified": f">={since.strftime('%Y-%m-%d')}",
        "per_page": 100,
    }
    out = []
    for adv in _get(GHSA_URL, params, headers):
        fixed = sorted({
            v["first_patched_version"]
            for v in adv.get("vulnerabilities", [])
            if v.get("first_patched_version")
        })
        score = (adv.get("cvss") or {}).get("score")
        out.append({
            "id": adv.get("cve_id") or adv["ghsa_id"],
            "description": adv.get("summary", ""),
            "published": adv.get("published_at", ""),
            "modified": adv.get("updated_at", ""),
            "score": score,
            "severity": (adv.get("severity") or "").upper() or None,
            "vector": (adv.get("cvss") or {}).get("vector_string"),
            "refs": [adv["html_url"]],
            "fixed": ", ".join(fixed),
            "source": "GitHub Advisory",
        })
    return out


def now():
    return datetime.now(timezone.utc)
