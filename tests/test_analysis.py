from vulnwatch.analysis import match_product, risk_level

PHP = {"name": "PHP", "cpes": ["cpe:2.3:a:php:php:"], "keywords": [r"\bPHP\s+(?:before|\d)"],
       "installed": ["8.2.12"]}


def entry(**kw):
    return {"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "vulnerable": True, **kw}


def test_afecta_version_en_rango():
    v = {"cpe_matches": [entry(versionStartIncluding="8.2.0", versionEndExcluding="8.2.20")]}
    m = match_product(v, PHP)
    assert m["affects_me"] is True and m["fixed"] == "8.2.20"


def test_no_afecta_version_corregida():
    v = {"cpe_matches": [entry(versionEndExcluding="8.2.10")]}
    assert match_product(v, PHP)["affects_me"] is False


def test_sin_analizar_usa_keywords():
    v = {"cpe_matches": [], "has_config": False, "description": "PHP before 8.3.9 allows RCE"}
    assert match_product(v, PHP) == {"affects_me": None, "fixed": ""}


def test_producto_ajeno():
    v = {"cpe_matches": [{"criteria": "cpe:2.3:a:otro:otro:1.0:*:*:*:*:*:*:*"}], "has_config": True}
    assert match_product(v, PHP) is None


def test_kev_sube_a_critico():
    v = {"id": "CVE-1", "severity": "MEDIUM"}
    assert risk_level(v, {"CVE-1"}, 0) == "crítico"
    assert risk_level(v, set(), 0) == "medio"
