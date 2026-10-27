"""Vulnerabilidades: qué CVE nuevos importan, qué lenguajes y qué sistemas están en riesgo.

Fuentes (todas gratuitas):
  - NVD API 2.0: los CVE publicados en los últimos días, con CVSS, CWE, CPE y la
    valoración SSVC de CISA (si ya se explota o hay prueba de concepto).
  - FIRST EPSS: la probabilidad de que cada CVE se explote en los próximos 30 días.
  - CISA KEV: los CVE que ya se están explotando (catálogo completo).
  - GitHub Advisory Database: por ecosistema (npm, PyPI, Maven…), los paquetes
    maliciosos publicados y los avisos de vulnerabilidad revisados.

La prioridad no es el CVSS: un 7.5 que ya se explota va antes que un 9.8 que nadie
ataca. Cada fuente que falla se anota en `fuentes` y el resto se publica igual.
"""
from __future__ import annotations

import logging
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger(__name__)
TIMEOUT = 60
UA = {"User-Agent": "ScriptNewsCTI (+https://cti.carlosvillalbalagos.com)"}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_PAGINA = 2000
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GH_URL = "https://api.github.com/advisories"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

MAX_CVES_PUBLICADOS = 600      # filas de la tabla (las más prioritarias); las cifras cuentan todas
MAX_EJEMPLOS = 5

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")

# Ecosistemas de la GitHub Advisory Database -> lenguaje que se muestra
ECOSISTEMAS = {
    "npm": ("JavaScript / TypeScript", "npm"),
    "pip": ("Python", "PyPI"),
    "maven": ("Java / Kotlin", "Maven"),
    "nuget": (".NET (C#)", "NuGet"),
    "composer": ("PHP", "Packagist"),
    "go": ("Go", "Go modules"),
    "rust": ("Rust", "crates.io"),
    "rubygems": ("Ruby", "RubyGems"),
    "erlang": ("Erlang / Elixir", "Hex"),
    "pub": ("Dart / Flutter", "pub.dev"),
    "swift": ("Swift", "SwiftPM"),
    "actions": ("GitHub Actions", "Marketplace"),
}

# El propio lenguaje (intérprete, compilador, runtime), por (fabricante, producto)
# de KEV o del CPE de NVD. Solo con fabricante y producto: en la descripción,
# «PHP» o «Python» aparecen en miles de CVE que no son del lenguaje.
RUNTIMES = {
    "pip": ("Python", r"^(python|python software foundation)\|(python|cpython)$"),
    "npm": ("Node.js", r"^(nodejs|node\.js|openjs foundation)\|node\.?js$"),
    "maven": ("Java (JDK)", r"^(oracle|openjdk|eclipse adoptium)\|(jdk|jre|java se|java|openjdk|graalvm)( .*)?$"),
    "nuget": (".NET", r"^microsoft\|(\.net|\.net framework|\.net core|asp\.net core)$"),
    "composer": ("PHP", r"^(php|php group|the php group)\|php$"),
    "go": ("Go", r"^(golang|google)\|go$"),
    "rust": ("Rust", r"^(rust-lang|rust)\|rust$"),
    "rubygems": ("Ruby", r"^(ruby-lang|ruby)\|ruby$"),
    "erlang": ("Erlang/OTP", r"^(erlang|ericsson)\|(erlang/otp|otp|erlang)$"),
    "swift": ("Swift", r"^(apple|swift)\|swift$"),
    "pub": ("Dart", r"^(dart|google)\|dart( sdk)?$"),
}
_RUNTIMES = {eco: re.compile(rx, re.I) for eco, (_, rx) in RUNTIMES.items()}


def runtime_de(fabricante: str, producto: str) -> str | None:
    clave = f"{(fabricante or '').strip()}|{(producto or '').strip()}"
    return next((eco for eco, rx in _RUNTIMES.items() if rx.match(clave)), None)


# Sistemas: categoría, nombre visible y patrón. Primero se busca en fabricante y
# producto (KEV, CPE o CNA) y solo si no hay suerte, en la descripción. El orden
# importa: lo más específico, antes («Cisco IOS» es red, no Apple).
CATEGORIAS = [
    ("android", "Android", r"\bandroid\b"),
    ("navegadores", "Navegadores",
     r"\bchrom(e|ium)\b|\bfirefox\b|\bthunderbird\b|\bmozilla\b|\bwebkit\b|\bsafari\b|\bmicrosoft edge\b|\bv8\b"),
    ("microsoft", "Windows y Microsoft", r"\bmicrosoft\b|\bwindows\b|\bexchange server\b|\bsharepoint\b|\bazure\b|\bhyper-v\b"),
    ("red", "Red, VPN y firewalls",
     r"\bcisco\b|\bfortinet\b|\bforti\w+|\bpalo ?alto\b|\bpan-os\b|\bivanti\b|\bcitrix\b|\bnetscaler\b|\bjuniper\b"
     r"|\bjunos\b|\bsonicwall\b|\bf5\b|\bbig-ip\b|\bcheck ?point\b|\bzyxel\b|\bmikrotik\b|\bubiquiti\b|\bdraytek\b"
     r"|\bsophos\b|\bwatchguard\b|\bbarracuda\b|\baruba\b|\baos-\d+\b|\barista\b|\bvelocloud\b|\bopenvpn\b|\bpulse secure\b"),
    ("iot", "Routers domésticos, IoT y cámaras",
     r"\btotolink\b|\bwavlink\b|\btenda\b|\btp-link\b|\bd-link\b|\bnetgear\b|\blinksys\b|\bhikvision\b|\bdahua\b"
     r"|\bedimax\b|\btrendnet\b|\bunitree\b|\brouter\b|\bboa\b|\bdvr\b|\bnvr\b|\bip camera\b|\bwi-?fi extender\b"),
    ("apple", "Apple (macOS · iOS)", r"\bapple\b|\bmacos\b|\bipados\b|(?<!cisco )\bios\b(?! xe| xr)|\bwatchos\b|\bvisionos\b|\btvos\b"),
    ("linux", "Linux", r"\blinux\b|\bred ?hat\b|\bubuntu\b|\bdebian\b|\bsuse\b|\bcanonical\b|\bfedora\b"),
    ("virtualizacion", "Virtualización y nube",
     r"\bvmware\b|\bbroadcom\b|\besxi\b|\bvcenter\b|\bkubernetes\b|\bdocker\b|\bcontainerd\b|\bopenshift\b|\bproxmox\b|\bxen\b"),
    ("ics", "Industrial (OT · ICS)",
     r"\bsiemens\b|\bschneider\b|\brockwell\b|\babb\b|\bhoneywell\b|\bmitsubishi electric\b|\bomron\b|\bscada\b|\bplc\b"),
    ("empresarial", "Software empresarial",
     r"\boracle\b|\bsap\b|\bibm\b|\batlassian\b|\bconfluence\b|\bjira\b|\bsolarwinds\b|\badobe\b|\bservicenow\b"
     r"|\bjenkins\b|\bgitlab\b|\bapache\b|\bveeam\b|\bsalesforce\b|\bfinereport\b"),
    ("web", "Aplicaciones web y CMS",
     r"\bwordpress\b|\bdrupal\b|\bjoomla\b|\bmagento\b|\bprestashop\b|\bwoocommerce\b|\bplugin\b"),
]
# Solo en la descripción, como último recurso: señales típicas de aplicación web
WEB_DESC = re.compile(r"\.php\b|\bcross-site scripting\b|\bsql injection\b|\bweb (interface|application|panel)\b"
                      r"|\bcontrol panel\b|\bcms\b|/api/|/admin/", re.I)
NOMBRE_CATEGORIA = {c: n for c, n, _ in CATEGORIAS} | {
    "runtimes": "Lenguajes y entornos de ejecución", "oss": "Librerías de código abierto", "otros": "Otros"}
_PATRONES = [(c, re.compile(p, re.I)) for c, _, p in CATEGORIAS]

# CNA (quien publica el CVE) -> fabricante. Muchos CVE nuevos aún no tienen CPE en
# NVD ("Awaiting Analysis"); el CNA dice de quién es el producto.
CNA_FABRICANTE = {
    "secure@microsoft.com": "Microsoft", "secalert_us@oracle.com": "Oracle",
    "chrome-cve-admin@google.com": "Google Chrome", "security@android.com": "Google Android",
    "product-security@apple.com": "Apple", "security@mozilla.org": "Mozilla", "psirt@adobe.com": "Adobe",
    "psirt@us.ibm.com": "IBM", "secalert@redhat.com": "Red Hat", "security@apache.org": "Apache",
    "psirt@cisco.com": "Cisco", "psirt@fortinet.com": "Fortinet", "psirt@paloaltonetworks.com": "Palo Alto Networks",
    "security@vmware.com": "VMware", "cna@sap.com": "SAP", "productcert@siemens.com": "Siemens",
    "cybersecurity@schneider-electric.com": "Schneider Electric", "psirt@solarwinds.com": "SolarWinds",
    "security@atlassian.com": "Atlassian", "secure@intel.com": "Intel", "psirt@nvidia.com": "NVIDIA",
    "security@wordfence.com": "WordPress (plugins)", "audit@patchstack.com": "WordPress (plugins)",
    "cve@kernel.org": "Linux kernel", "security-advisories@github.com": "Código abierto (GitHub)",
    "security@ubuntu.com": "Canonical (Ubuntu)", "sirt@juniper.net": "Juniper", "psirt@zyxel.com.tw": "Zyxel",
    "security@hpe.com": "HPE", "secure@dell.com": "Dell", "psirt@amd.com": "AMD", "psirt@huawei.com": "Huawei",
    "vulnerabilities@zephyrproject.org": "Zephyr RTOS", "emo@eclipse.org": "Eclipse",
}


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def _get(url, *, params=None, headers=None, intentos=4, pausa=6.0):
    """GET con reintentos para 429/5xx (NVD responde 503 a menudo)."""
    for n in range(intentos):
        try:
            r = requests.get(url, params=params, headers={**UA, **(headers or {})}, timeout=TIMEOUT)
            if r.status_code in (429, 500, 502, 503, 504) and n < intentos - 1:
                time.sleep(pausa * (n + 1))
                continue
            r.raise_for_status()
            return r
        except requests.RequestException:
            if n == intentos - 1:
                raise
            time.sleep(pausa * (n + 1))
    raise RuntimeError("sin respuesta")


# ── NVD ──────────────────────────────────────────────────────────────────────
def _metricas(m: dict) -> tuple[float | None, str | None, str | None]:
    """La puntuación de NVD (Primary) si la hay; si no, la del CNA. En cada grupo, la versión más nueva."""
    candidatos = []
    for rango, clave in enumerate(("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")):
        for x in m.get(clave) or []:
            d = x.get("cvssData") or {}
            if d.get("baseScore") is None:
                continue
            sev = (d.get("baseSeverity") or x.get("baseSeverity") or "").lower() or None
            candidatos.append((x.get("type") != "Primary", rango, float(d["baseScore"]), sev, d.get("version")))
    if not candidatos:
        return None, None, None
    _, _, nota, sev, version = min(candidatos, key=lambda c: (c[0], c[1]))
    return nota, sev, version


def _ssvc(m: dict) -> dict:
    """Valoración SSVC de CISA (Vulnrichment): explotación none / poc / active."""
    for s in m.get("ssvcV203") or m.get("ssvcV2") or []:
        out = {}
        for op in (s.get("ssvcData") or {}).get("options") or []:
            out.update({k.lower(): str(v).lower() for k, v in op.items()})
        if out:
            return out
    return {}


def _cpe(configs: list) -> tuple[str | None, str | None]:
    for c in configs or []:
        for nodo in c.get("nodes") or []:
            for match in nodo.get("cpeMatch") or []:
                if match.get("vulnerable"):
                    partes = (match.get("criteria") or "").split(":")
                    if len(partes) > 5:
                        return partes[3].replace("_", " "), partes[4].replace("_", " ")
    return None, None


def resumir_cve(cve: dict) -> dict | None:
    """De un objeto `cve` de NVD a lo que necesita el panel. None si está rechazado."""
    if cve.get("vulnStatus") == "Rejected" or not CVE_RE.match(cve.get("id") or ""):
        return None
    descs = cve.get("descriptions") or []
    desc = next((d.get("value") for d in descs if d.get("lang") == "es"), None) or \
        next((d.get("value") for d in descs if d.get("lang") == "en"), "")
    m = cve.get("metrics") or {}
    cvss, sev, version = _metricas(m)
    vendor, producto = _cpe(cve.get("configurations"))
    cwes = sorted({d.get("value") for w in cve.get("weaknesses") or [] for d in w.get("description") or []
                   if (d.get("value") or "").startswith("CWE-")})
    return {
        "cve": cve["id"],
        "publicado": (cve.get("published") or "")[:10],
        "estado_nvd": cve.get("vulnStatus"),
        "cna": cve.get("sourceIdentifier") or "",
        "descripcion": re.sub(r"\s+", " ", desc or "").strip(),
        "cvss": cvss,
        "gravedad": sev,
        "cvss_version": version,
        "cwe": cwes[:3],
        "cpe_fabricante": vendor,
        "cpe_producto": producto,
        "ssvc": _ssvc(m),
        "kev_nvd": bool(cve.get("cisaExploitAdd")),
    }


def nvd_recientes(dias: int = 7, max_paginas: int = 6) -> list[dict]:
    """CVE publicados en los últimos `dias` (NVD API 2.0, ventana máxima 120 días)."""
    fin = _ahora()
    ini = fin - timedelta(days=dias)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    cab = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    pausa = 0.7 if NVD_API_KEY else 6.5      # 50 o 5 peticiones cada 30 s
    salida, inicio = [], 0
    for pagina in range(max_paginas):
        if pagina:
            time.sleep(pausa)
        r = _get(NVD_URL, params={"pubStartDate": ini.strftime(fmt), "pubEndDate": fin.strftime(fmt),
                                  "resultsPerPage": NVD_PAGINA, "startIndex": inicio}, headers=cab, pausa=pausa)
        j = r.json()
        vulns = j.get("vulnerabilities") or []
        salida += [x for x in (resumir_cve(v.get("cve") or {}) for v in vulns) if x]
        inicio += len(vulns)
        if not vulns or inicio >= int(j.get("totalResults") or 0):
            break
    log.info("NVD: %d CVE publicados en %d días", len(salida), dias)
    return salida


# ── EPSS ─────────────────────────────────────────────────────────────────────
def epss(ids: list[str], lote: int = 100) -> dict[str, tuple[float, float]]:
    """{CVE: (probabilidad, percentil)}. El parámetro cve admite ~2000 caracteres: lotes de 100."""
    out: dict[str, tuple[float, float]] = {}
    ids = [i for i in ids if CVE_RE.match(i)]
    for n in range(0, len(ids), lote):
        if n:
            time.sleep(0.3)
        trozo = ids[n:n + lote]
        r = _get(EPSS_URL, params={"cve": ",".join(trozo), "limit": lote}, pausa=2.0)
        for d in r.json().get("data") or []:
            try:
                out[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    log.info("EPSS: %d de %d CVE con puntuación", len(out), len(ids))
    return out


# ── CISA KEV ─────────────────────────────────────────────────────────────────
def kev_catalogo() -> list[dict]:
    r = _get(KEV_URL)
    vulns = r.json().get("vulnerabilities") or []
    log.info("CISA KEV: %d CVE en el catálogo", len(vulns))
    return vulns


# ── GitHub Advisory Database ─────────────────────────────────────────────────
def _siguiente(link: str) -> str | None:
    m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
    return m.group(1) if m else None


def github_avisos(ecosistema: str, tipo: str, dias: int = 7, max_paginas: int = 10) -> tuple[list[dict], bool]:
    """Avisos publicados en los últimos días. Devuelve (avisos, hay_mas_de_los_leidos)."""
    desde = (_ahora() - timedelta(days=dias)).strftime("%Y-%m-%d")
    cab = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        cab["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    url, params, avisos = GH_URL, {"type": tipo, "ecosystem": ecosistema, "published": f">={desde}",
                                   "per_page": 100, "sort": "published", "direction": "desc"}, []
    for _ in range(max_paginas):
        r = _get(url, params=params, headers=cab, pausa=3.0)
        avisos += r.json() or []
        url, params = _siguiente(r.headers.get("Link", "")), None
        if not url:
            return avisos, False
    return avisos, True


def _aviso(a: dict, ecosistema: str) -> dict:
    paquetes = list(dict.fromkeys(v.get("package", {}).get("name") for v in a.get("vulnerabilities") or []
                                  if (v.get("package") or {}).get("ecosystem") == ecosistema))
    parcheada = next((v.get("first_patched_version") for v in a.get("vulnerabilities") or []
                      if v.get("first_patched_version")), None)
    ghsa = a.get("ghsa_id") if GHSA_RE.match(a.get("ghsa_id") or "") else None
    cve = a.get("cve_id") if CVE_RE.match(a.get("cve_id") or "") else None
    e = a.get("epss") or {}
    return {"ghsa": ghsa, "cve": cve, "paquete": ", ".join(p for p in paquetes if p)[:120],
            "resumen": (a.get("summary") or "")[:200], "gravedad": a.get("severity"),
            "cvss": (a.get("cvss") or {}).get("score") or None,
            "epss": e.get("percentage"), "corregido_en": parcheada, "publicado": (a.get("published_at") or "")[:10]}


def _runtime(eco: str, cves: list[dict], kev_cat: list[dict], dias_kev: int = 90) -> dict | None:
    """CVE del propio lenguaje esta semana y los que CISA da por explotados (90 días)."""
    if eco not in RUNTIMES:
        return None
    corte = (_ahora() - timedelta(days=dias_kev)).date().isoformat()
    propios = [c for c in cves if c.get("runtime") == eco]
    explotados = sorted(({"cve": k.get("cveID"), "anadido": k.get("dateAdded"), "nombre": k.get("vulnerabilityName"),
                          "ransomware": k.get("knownRansomwareCampaignUse") == "Known"}
                         for k in kev_cat if (k.get("dateAdded") or "") >= corte
                         and runtime_de(k.get("vendorProject"), k.get("product")) == eco),
                        key=lambda x: x["anadido"] or "", reverse=True)
    return {"nombre": RUNTIMES[eco][0], "cves": len(propios),
            "ejemplos": [{k: c.get(k) for k in ("cve", "cvss", "epss", "prioridad")} for c in sorted(propios, key=_orden)[:3]],
            "explotados": explotados[:MAX_EJEMPLOS], "explotados_total": len(explotados)}


def lenguajes(dias: int = 7, cves: list[dict] | None = None, kev_cat: list[dict] | None = None) -> list[dict]:
    """Estado por lenguaje: el propio lenguaje (CVE y explotación) y sus registros
    de paquetes (paquetes maliciosos y vulnerabilidades revisadas)."""
    salida = []
    corte30 = (_ahora() - timedelta(days=30)).date().isoformat()
    for eco, (lenguaje, registro) in ECOSISTEMAS.items():
        rt = _runtime(eco, cves or [], kev_cat or [])
        fila = {"ecosistema": eco, "lenguaje": lenguaje, "registro": registro, "error": None, "runtime": rt}
        try:
            mal, mal_mas = github_avisos(eco, "malware", dias)
            rev, rev_mas = github_avisos(eco, "reviewed", dias, max_paginas=3)
        except Exception as exc:          # una caída de la API no tumba el resto
            log.error("GitHub Advisory (%s) falló: %s", eco, exc)
            fila["error"] = "fuente no disponible"
            if rt and any((x["anadido"] or "") >= corte30 for x in rt["explotados"]):
                fila["estado"] = "runtime_explotado"
            salida.append(fila)
            continue
        sev = Counter(a.get("severity") for a in rev)
        graves = sorted((a for a in rev if a.get("severity") in ("critical", "high")),
                        key=lambda a: ({"critical": 0, "high": 1}[a["severity"]],
                                       -((a.get("epss") or {}).get("percentage") or 0)))
        fila.update({
            "maliciosos": len(mal), "maliciosos_mas": mal_mas,
            "avisos": len(rev), "avisos_mas": rev_mas,
            "criticos": sev.get("critical", 0), "altos": sev.get("high", 0),
            "ejemplos_maliciosos": [_aviso(a, eco) for a in mal[:MAX_EJEMPLOS]],
            "ejemplos_graves": [_aviso(a, eco) for a in graves[:MAX_EJEMPLOS]],
        })
        runtime_explotado = bool(rt and any((x["anadido"] or "") >= corte30 for x in rt["explotados"]))
        fila["estado"] = ("runtime_explotado" if runtime_explotado else
                          "maliciosos" if fila["maliciosos"] else
                          "critico" if fila["criticos"] else
                          "alto" if fila["altos"] else "sin_alertas")
        salida.append(fila)
    log.info("GitHub Advisory: %d ecosistemas", len(salida))
    return salida


# ── clasificación y prioridad ────────────────────────────────────────────────
def fabricante_producto(c: dict, kev: dict | None = None) -> tuple[str, str]:
    """De quién es: KEV > CPE de NVD > CNA que lo publica."""
    if kev:
        return kev.get("vendorProject") or "", kev.get("product") or ""
    if c.get("cpe_fabricante"):
        return c["cpe_fabricante"].title(), c.get("cpe_producto") or ""
    return CNA_FABRICANTE.get(c.get("cna"), ""), ""


def clasificar(c: dict, kev: dict | None = None) -> tuple[str, str]:
    """(categoría, fabricante) de un CVE: patrones sobre el fabricante y el
    producto y, si no, sobre la descripción."""
    fabricante, producto = fabricante_producto(c, kev)
    if runtime_de(fabricante, producto):
        return "runtimes", fabricante
    if c.get("cna") == "security-advisories@github.com" and not kev:
        return "oss", fabricante or "Código abierto (GitHub)"
    for texto in (f"{fabricante} {producto}", (c.get("descripcion") or "")[:200]):
        for cat, rx in _PATRONES:
            m = rx.search(texto)
            if m:
                return cat, fabricante or m.group(0).title()
    if WEB_DESC.search(c.get("descripcion") or ""):
        return "web", fabricante
    return "otros", fabricante


def prioridad(c: dict) -> str:
    """explotada > urgente > alta > media > baja."""
    e, pct, cvss = c.get("epss") or 0.0, c.get("epss_percentil") or 0.0, c.get("cvss") or 0.0
    explot = (c.get("ssvc") or {}).get("exploitation")
    if c.get("kev") or explot == "active":
        return "explotada"
    if e >= 0.10 or (cvss >= 9.0 and (e >= 0.01 or explot == "poc")):
        return "urgente"
    if cvss >= 7.0 or pct >= 0.90 or explot == "poc":
        return "alta"
    return "media" if cvss >= 4.0 else "baja"


ORDEN_PRIORIDAD = {"explotada": 0, "urgente": 1, "alta": 2, "media": 3, "baja": 4}


def _orden(c: dict):
    return (ORDEN_PRIORIDAD[c["prioridad"]], -(c.get("epss") or 0), -(c.get("cvss") or 0), c["cve"])


def sistemas(cves: list[dict], kev_cat: list[dict], dias_kev: int = 30) -> list[dict]:
    """Estado por sistema: CVE nuevos, críticos, explotación activa reciente (KEV)."""
    corte = (_ahora() - timedelta(days=dias_kev)).date().isoformat()
    grupos: dict[str, dict] = defaultdict(lambda: {"cves": 0, "criticos": 0, "altos": 0, "urgentes": 0,
                                                   "epss_max": 0.0, "fabricantes": Counter(),
                                                   "kev_recientes": [], "destacados": []})
    for c in cves:
        g = grupos[c["categoria"]]
        g["cves"] += 1
        g["criticos"] += (c.get("cvss") or 0) >= 9.0
        g["altos"] += 7.0 <= (c.get("cvss") or 0) < 9.0
        g["urgentes"] += c["prioridad"] in ("explotada", "urgente")
        g["epss_max"] = max(g["epss_max"], c.get("epss") or 0.0)
        if c.get("fabricante"):
            g["fabricantes"][c["fabricante"]] += 1
        g["destacados"].append(c)
    for k in kev_cat:
        if (k.get("dateAdded") or "") >= corte:
            cat, fab = clasificar({"descripcion": k.get("shortDescription") or ""}, k)
            grupos[cat]["kev_recientes"].append({
                "cve": k.get("cveID"), "fabricante": fab, "producto": k.get("product"),
                "nombre": k.get("vulnerabilityName"), "anadido": k.get("dateAdded"),
                "ransomware": k.get("knownRansomwareCampaignUse") == "Known"})
    salida = []
    for cat, g in grupos.items():
        g["kev_recientes"].sort(key=lambda x: x["anadido"] or "", reverse=True)
        destacados = sorted(g["destacados"], key=_orden)[:MAX_EJEMPLOS]
        estado = ("explotacion_activa" if g["kev_recientes"] else
                  "riesgo_alto" if g["urgentes"] or g["criticos"] else "vigilar")
        salida.append({
            "categoria": cat, "nombre": NOMBRE_CATEGORIA.get(cat, cat), "estado": estado,
            "cves": g["cves"], "criticos": g["criticos"], "altos": g["altos"], "urgentes": g["urgentes"],
            "epss_max": round(g["epss_max"], 4),
            "fabricantes": [f for f, _ in g["fabricantes"].most_common(5)],
            "kev_recientes": g["kev_recientes"][:MAX_EJEMPLOS], "kev_recientes_total": len(g["kev_recientes"]),
            "destacados": [{k: c.get(k) for k in ("cve", "fabricante", "cvss", "epss", "prioridad")} for c in destacados],
        })
    orden_estado = {"explotacion_activa": 0, "riesgo_alto": 1, "vigilar": 2}
    salida.sort(key=lambda s: (orden_estado[s["estado"]], s["categoria"] == "otros", -s["urgentes"], -s["cves"]))
    return salida


def construir(dias: int = 7, kev_cat: list[dict] | None = None) -> dict:
    """Todo el bloque de vulnerabilidades, listo para data/vulns_latest.json."""
    fuentes = {}
    try:
        cves = nvd_recientes(dias)
        fuentes["nvd"] = "ok"
    except Exception as exc:
        log.error("NVD falló: %s", exc)
        cves, fuentes["nvd"] = [], "error"
    try:
        kev_cat = kev_cat if kev_cat is not None else kev_catalogo()
        fuentes["kev"] = "ok"
    except Exception as exc:
        log.error("CISA KEV falló: %s", exc)
        kev_cat, fuentes["kev"] = [], "error"
    try:
        puntos = epss([c["cve"] for c in cves])
        fuentes["epss"] = "ok"
    except Exception as exc:
        log.error("EPSS falló: %s", exc)
        puntos, fuentes["epss"] = {}, "error"

    kev_por_cve = {k.get("cveID"): k for k in kev_cat}
    for c in cves:
        c["epss"], c["epss_percentil"] = puntos.get(c["cve"], (None, None))
        k = kev_por_cve.get(c["cve"])
        c["kev"] = bool(k) or c.pop("kev_nvd", False)
        c.pop("kev_nvd", None)
        c["categoria"], c["fabricante"] = clasificar(c, k)
        c["runtime"] = runtime_de(*fabricante_producto(c, k))
        c["prioridad"] = prioridad(c)
    cves.sort(key=_orden)

    try:
        lengs = lenguajes(dias, cves, kev_cat)
        fuentes["github_advisories"] = "ok" if not all(x.get("error") for x in lengs) else "error"
    except Exception as exc:
        log.error("GitHub Advisory falló: %s", exc)
        lengs, fuentes["github_advisories"] = [], "error"

    por_prioridad = Counter(c["prioridad"] for c in cves)
    publicados = []
    for c in cves[:MAX_CVES_PUBLICADOS]:
        publicados.append({**{k: c.get(k) for k in (
            "cve", "publicado", "prioridad", "cvss", "gravedad", "epss", "epss_percentil", "kev",
            "categoria", "fabricante", "cwe", "estado_nvd")},
            "explotacion_ssvc": (c.get("ssvc") or {}).get("exploitation"),
            "descripcion": c["descripcion"][:280] + ("…" if len(c["descripcion"]) > 280 else "")})
    return {
        "generado_utc": _ahora().strftime("%Y-%m-%d %H:%M"),
        "ventana_dias": dias,
        "fuentes": fuentes,
        "resumen": {
            "cves": len(cves),
            "criticos": sum((c.get("cvss") or 0) >= 9.0 for c in cves),
            "explotados": por_prioridad.get("explotada", 0),
            "urgentes": por_prioridad.get("urgente", 0),
            "epss_10": sum((c.get("epss") or 0) >= 0.10 for c in cves),
            "sin_puntuar": sum(c.get("cvss") is None for c in cves),
            "por_prioridad": dict(por_prioridad),
            "paquetes_maliciosos": sum(x.get("maliciosos") or 0 for x in lengs),
        },
        "cves": publicados,
        "cves_publicados": len(publicados),
        "lenguajes": lengs,
        "sistemas": sistemas(cves, kev_cat),
    }
