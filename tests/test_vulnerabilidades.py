"""Vulnerabilidades: lectura de NVD, prioridad, clasificación por sistema y lenguajes.

Las respuestas imitan las reales (comprobadas contra NVD, EPSS, KEV y la GitHub
Advisory Database desde un runner de Actions el 26/10/2026), recortadas."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vulnerabilidades as v  # noqa: E402

HOY = datetime.now(timezone.utc).date()


def nvd_cve(cid, cna="disclosure@vulncheck.com", desc="Missing authorization in Example.", estado="Analyzed",
            primaria=None, secundaria=None, cpe=None, ssvc_expl="none", kev=False):
    metrics = {}
    if secundaria:
        metrics["cvssMetricV40"] = [{"source": cna, "type": "Secondary",
                                     "cvssData": {"version": "4.0", "baseScore": secundaria, "baseSeverity": "MEDIUM"}}]
    if primaria:
        metrics["cvssMetricV31"] = [{"source": "nvd@nist.gov", "type": "Primary",
                                     "cvssData": {"version": "3.1", "baseScore": primaria, "baseSeverity": "HIGH"}}]
    metrics["ssvcV203"] = [{"source": "134c704f", "ssvcData": {"options": [
        {"exploitation": ssvc_expl}, {"automatable": "no"}, {"technicalImpact": "partial"}]}}]
    cve = {"id": cid, "sourceIdentifier": cna, "published": f"{HOY}T10:00:00.000", "vulnStatus": estado,
           "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics,
           "weaknesses": [{"description": [{"lang": "en", "value": "CWE-862"}]}]}
    if cpe:
        cve["configurations"] = [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}]
    if kev:
        cve["cisaExploitAdd"] = str(HOY)
    return {"cve": cve}


class Resp:
    def __init__(self, data, link=""):
        self._data, self.headers, self.status_code = data, {"Link": link}, 200

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


# ── lectura de NVD ───────────────────────────────────────────────────────────
def test_cvss_de_nvd_antes_que_el_del_cna_y_ssvc():
    c = v.resumir_cve(nvd_cve("CVE-2026-112778", primaria=8.8, secundaria=6.4)["cve"])
    assert (c["cvss"], c["cvss_version"]) == (8.8, "3.1"), "la Primary de NVD manda sobre la v4 del CNA"
    assert c["ssvc"]["exploitation"] == "none" and c["cwe"] == ["CWE-862"]
    sin_nvd = v.resumir_cve(nvd_cve("CVE-2026-1001", secundaria=6.4, estado="Awaiting Analysis")["cve"])
    assert (sin_nvd["cvss"], sin_nvd["cvss_version"]) == (6.4, "4.0"), "sin análisis de NVD, la del CNA"
    assert v.resumir_cve(nvd_cve("CVE-2026-1002", primaria=9.8)["cve"] | {"vulnStatus": "Rejected"}) is None


def test_cpe_da_fabricante_y_producto():
    c = v.resumir_cve(nvd_cve("CVE-2026-1003", cpe="cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")["cve"])
    assert (c["cpe_fabricante"], c["cpe_producto"]) == ("linux", "linux kernel")


# ── prioridad ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("datos, esperada", [
    ({"kev": True, "cvss": 5.0}, "explotada"),
    ({"ssvc": {"exploitation": "active"}, "cvss": 6.1}, "explotada"),
    ({"epss": 0.25, "cvss": 5.0}, "urgente"),
    ({"cvss": 9.8, "ssvc": {"exploitation": "poc"}}, "urgente"),
    ({"cvss": 9.8, "epss": 0.001}, "alta"),
    ({"cvss": 7.5}, "alta"),
    ({"cvss": 5.0, "epss_percentil": 0.95}, "alta"),
    ({"cvss": 5.0}, "media"),
    ({"cvss": None}, "baja"),
])
def test_prioridad(datos, esperada):
    assert v.prioridad(datos) == esperada


def test_un_7_5_explotado_va_antes_que_un_9_8_que_nadie_ataca():
    a = {"cve": "CVE-2026-1010", "cvss": 9.8, "epss": 0.002}
    b = {"cve": "CVE-2026-1011", "cvss": 7.5, "kev": True}
    for c in (a, b):
        c["prioridad"] = v.prioridad(c)
    assert sorted([a, b], key=v._orden)[0]["cve"] == "CVE-2026-1011"


# ── clasificación ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cve, kev, categoria", [
    ({"cna": "secalert_us@oracle.com", "descripcion": "Vulnerability in the MySQL Server product of Oracle MySQL"}, None, "empresarial"),
    ({"cna": "chrome-cve-admin@google.com", "descripcion": "Use after free in V8 in Google Chrome prior to 141"}, None, "navegadores"),
    ({"cna": "security@android.com", "descripcion": "In multiple locations, there is a possible way"}, None, "android"),
    ({"cna": "product-security@apple.com", "descripcion": "The issue was addressed with improved checks."}, None, "apple"),
    ({"cna": "security-advisories@github.com", "descripcion": "Prototype pollution in lodash"}, None, "oss"),
    ({"cna": "security@wordfence.com", "descripcion": "The Contact Form plugin for WordPress is vulnerable"}, None, "web"),
    ({"cna": "5f57b9bf-260d", "descripcion": "A heap overflow in Fortinet FortiOS SSL-VPN allows"}, None, "red"),
    ({"cna": "x", "cpe_fabricante": "linux", "cpe_producto": "linux kernel", "descripcion": "In the Linux kernel"}, None, "linux"),
    ({"cna": "x", "descripcion": "Something"}, {"vendorProject": "Microsoft", "product": "Windows"}, "microsoft"),
    ({"cna": "x", "descripcion": "A flaw in an unknown product"}, None, "otros"),
    ({"cna": "psirt@cisco.com", "descripcion": "A vulnerability in Cisco IOS XE Software"}, None, "red"),
    ({"cna": "x", "descripcion": "A flaw was found in TOTOLINK A950RG. The function UploadCustomModule"}, None, "iot"),
    ({"cna": "x", "descripcion": "SQL injection in /admin/login.php of Hospital Management System"}, None, "web"),
    ({"cna": "x", "descripcion": "PHP has several global states"}, {"vendorProject": "PHP Group", "product": "PHP"}, "runtimes"),
    ({"cna": "x", "cpe_fabricante": "python", "cpe_producto": "python", "descripcion": "In CPython"}, None, "runtimes"),
])


def test_clasificar(cve, kev, categoria):
    assert v.clasificar(cve, kev)[0] == categoria


@pytest.mark.parametrize("fab, prod, eco", [
    ("PHP Group", "PHP", "composer"), ("python", "python", "pip"), ("nodejs", "node.js", "npm"),
    ("Oracle", "Java SE", "maven"), ("Microsoft", ".NET", "nuget"), ("golang", "go", "go"),
    ("Python-Jose Project", "python-jose", None), ("Phpmyadmin", "phpmyadmin", None), ("Oracle", "MySQL", None),
])
def test_el_propio_lenguaje_solo_por_fabricante_y_producto(fab, prod, eco):
    assert v.runtime_de(fab, prod) == eco


# ── GitHub Advisory Database ─────────────────────────────────────────────────
def aviso(ghsa, eco="npm", tipo="malware", sev="critical", nombre="paquete-malo", cve=None, epss=None):
    return {"ghsa_id": ghsa, "cve_id": cve, "summary": f"Malware in {nombre}", "severity": sev, "type": tipo,
            "published_at": f"{HOY}T16:28:46Z", "epss": epss,
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": nombre}, "first_patched_version": None}]}


def test_paginacion_y_tope(monkeypatch):
    llamadas = []

    def falso(url, params=None, headers=None, **_):
        llamadas.append(url)
        return Resp([aviso("GHSA-2222-3333-4444")] * 100, link='<https://api.github.com/advisories?after=x>; rel="next"')

    monkeypatch.setattr(v, "_get", falso)
    avisos, mas = v.github_avisos("npm", "malware", max_paginas=3)
    assert len(avisos) == 300 and mas is True and len(llamadas) == 3


def test_identificadores_raros_no_salen_como_enlace():
    a = v._aviso(aviso('javascript:alert(1)//', cve="<img src=x>"), "npm")
    assert a["ghsa"] is None and a["cve"] is None
    assert v._aviso(aviso("GHSA-g457-v22r-g8j3", cve="CVE-2026-1234"), "npm")["ghsa"] == "GHSA-g457-v22r-g8j3"


# ── todo junto, con una fuente caída ─────────────────────────────────────────
def fuentes_falsas(monkeypatch, nvd_cae=False):
    kev = [{"cveID": "CVE-2026-1500", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "x",
            "dateAdded": str(HOY - timedelta(days=3)), "shortDescription": "Fortinet FortiOS", "knownRansomwareCampaignUse": "Known"},
           {"cveID": "CVE-2026-1600", "vendorProject": "PHP Group", "product": "PHP", "vulnerabilityName": "PHP UAF",
            "dateAdded": str(HOY - timedelta(days=5)), "shortDescription": "PHP", "knownRansomwareCampaignUse": "Unknown"}]

    def falso(url, params=None, headers=None, **_):
        if url == v.NVD_URL:
            if nvd_cae:
                raise v.requests.ConnectionError("503")
            vulns = [nvd_cve("CVE-2026-1500", desc="Heap overflow in Fortinet FortiOS", primaria=7.5),
                     nvd_cve("CVE-2026-1501", cna="secalert_us@oracle.com", desc="Oracle MySQL", primaria=9.8),
                     nvd_cve("CVE-2026-1502", cna="chrome-cve-admin@google.com", desc="V8 in Google Chrome", secundaria=8.8),
                     nvd_cve("CVE-2026-1503", primaria=9.9, estado="Rejected")]
            return Resp({"totalResults": 4, "vulnerabilities": vulns})
        if url == v.EPSS_URL:
            return Resp({"data": [{"cve": "CVE-2026-1502", "epss": "0.31", "percentile": "0.99", "date": str(HOY)}]})
        if url == v.GH_URL:
            if params["type"] == "malware":
                return Resp([aviso("GHSA-g457-v22r-g8j3", eco=params["ecosystem"])] if params["ecosystem"] in ("npm", "pip") else [])
            return Resp([aviso("GHSA-jqc4-5cvw-7w85", eco=params["ecosystem"], tipo="reviewed", sev="high")]
                        if params["ecosystem"] == "maven" else [])
        raise AssertionError(url)

    monkeypatch.setattr(v, "_get", falso)
    monkeypatch.setattr(v.time, "sleep", lambda s: None)
    return kev


def test_construir(monkeypatch):
    kev = fuentes_falsas(monkeypatch)
    out = v.construir(dias=7, kev_cat=kev)
    assert out["fuentes"] == {"nvd": "ok", "kev": "ok", "epss": "ok", "github_advisories": "ok"}
    assert [c["cve"] for c in out["cves"]] == ["CVE-2026-1500", "CVE-2026-1502", "CVE-2026-1501"], \
        "explotada (KEV) > urgente (EPSS 31 %) > alta (9.8 sin explotar); el rechazado no sale"
    assert out["resumen"]["explotados"] == 1 and out["resumen"]["paquetes_maliciosos"] == 2
    lengs = {x["ecosistema"]: x for x in out["lenguajes"]}
    assert lengs["npm"]["estado"] == "maliciosos" and lengs["maven"]["estado"] == "alto"
    assert lengs["go"]["estado"] == "sin_alertas"
    assert lengs["composer"]["estado"] == "runtime_explotado", "CISA da el propio PHP por explotado"
    assert lengs["composer"]["runtime"]["explotados"][0]["cve"] == "CVE-2026-1600"
    sist = {s["categoria"]: s for s in out["sistemas"]}
    assert sist["red"]["estado"] == "explotacion_activa" and sist["red"]["kev_recientes"][0]["ransomware"]
    assert out["sistemas"][0]["categoria"] == "red", "lo explotado sale primero"


def test_si_nvd_cae_se_publica_lo_demas(monkeypatch):
    kev = fuentes_falsas(monkeypatch, nvd_cae=True)
    out = v.construir(dias=7, kev_cat=kev)
    assert out["fuentes"]["nvd"] == "error" and out["cves"] == []
    assert out["lenguajes"] and out["sistemas"][0]["kev_recientes"], "KEV y lenguajes siguen saliendo"
