"""Avisos de seguridad que van saliendo: fabricantes, CERT, exploits y noticias.

Cada fuente es un feed RSS/Atom público y gratuito. De cada entrada se guarda solo
lo que hace falta para decidir si mirarla: título, enlace, fecha, los CVE que
menciona y si dice que ya se explota. El texto del aviso no se publica (es del
autor); se lee únicamente para sacar los CVE y las señales de explotación.

Después se cruza con lo que ya sabe el panel: un aviso cuyo CVE está en el
catálogo KEV de CISA sale como explotado aunque el aviso no lo diga, y se anota
la probabilidad EPSS más alta de sus CVE.

Si una fuente falla, se anota en `fuentes` y el resto se publica igual.
"""
from __future__ import annotations

import html
import logging
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)
TIMEOUT = 30
UA = {"User-Agent": "ScriptNewsCTI (+https://cti.carlosvillalbalagos.com)",
      "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8"}
MAX_BYTES = 8 * 1024 * 1024        # un feed más grande que esto no es un feed
MAX_POR_FUENTE = 40
MAX_CVES_POR_AVISO = 12

TIPOS = {
    "fabricante": "Fabricantes",
    "cert": "CERT y gobiernos",
    "exploit": "Exploits e investigación",
    "noticia": "Noticias",
}

# filtro: "todo" publica cada entrada; "vuln" solo las que hablan de una
# vulnerabilidad (título con palabras clave o algún CVE); "cve" solo las que
# citan un CVE (p. ej. el blog de versiones de Chrome, donde solo las del canal
# estable traen correcciones de seguridad).
FUENTES = [
    # CERT y gobiernos
    {"id": "incibe", "nombre": "INCIBE-CERT", "tipo": "cert", "idioma": "es", "filtro": "todo",
     "url": "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed"},
    {"id": "incibe_sci", "nombre": "INCIBE-CERT · industrial", "tipo": "cert", "idioma": "es", "filtro": "todo",
     "url": "https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/feed"},
    {"id": "cisa", "nombre": "CISA", "tipo": "cert", "idioma": "en", "filtro": "todo",
     "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"id": "cert_eu", "nombre": "CERT-EU", "tipo": "cert", "idioma": "en", "filtro": "todo",
     "url": "https://cert.europa.eu/publications/security-advisories-rss"},
    {"id": "cert_fr", "nombre": "CERT-FR · alertas", "tipo": "cert", "idioma": "fr", "filtro": "todo",
     "url": "https://www.cert.ssi.gouv.fr/alerte/feed/"},
    {"id": "certcc", "nombre": "CERT/CC", "tipo": "cert", "idioma": "en", "filtro": "todo",
     "url": "https://www.kb.cert.org/vuls/atomfeed/"},
    # Fabricantes
    {"id": "msrc", "nombre": "Microsoft", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://api.msrc.microsoft.com/update-guide/rss"},
    {"id": "cisco", "nombre": "Cisco", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"},
    {"id": "fortinet", "nombre": "Fortinet", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml"},
    {"id": "paloalto", "nombre": "Palo Alto Networks", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://security.paloaltonetworks.com/rss.xml"},
    {"id": "chrome", "nombre": "Google Chrome", "tipo": "fabricante", "idioma": "en", "filtro": "cve",
     "url": "https://chromereleases.googleblog.com/feeds/posts/default"},
    {"id": "siemens", "nombre": "Siemens ProductCERT", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://cert-portal.siemens.com/productcert/rss/advisories.atom"},
    {"id": "gitlab", "nombre": "GitLab", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://about.gitlab.com/security-releases.xml"},
    {"id": "ubuntu", "nombre": "Ubuntu", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://ubuntu.com/security/notices/rss.xml"},
    {"id": "debian", "nombre": "Debian", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://www.debian.org/security/dsa-long"},
    # Exploits e investigación
    {"id": "zdi", "nombre": "Zero Day Initiative", "tipo": "exploit", "idioma": "en", "filtro": "todo",
     "url": "https://www.zerodayinitiative.com/rss/published/"},
    {"id": "exploitdb", "nombre": "Exploit-DB", "tipo": "exploit", "idioma": "en", "filtro": "todo",
     "url": "https://www.exploit-db.com/rss.xml"},
    {"id": "projectzero", "nombre": "Google Project Zero", "tipo": "exploit", "idioma": "en", "filtro": "todo",
     "url": "https://googleprojectzero.blogspot.com/feeds/posts/default"},
    # Noticias de vulnerabilidades (solo titulares que hablan de una)
    {"id": "unaaldia", "nombre": "Una al Día (Hispasec)", "tipo": "noticia", "idioma": "es", "filtro": "vuln",
     "url": "https://unaaldia.hispasec.com/feed"},
    {"id": "thehackernews", "nombre": "The Hacker News", "tipo": "noticia", "idioma": "en", "filtro": "vuln",
     "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"id": "bleeping", "nombre": "BleepingComputer", "tipo": "noticia", "idioma": "en", "filtro": "vuln",
     "url": "https://www.bleepingcomputer.com/feed/"},
    {"id": "securityweek", "nombre": "SecurityWeek", "tipo": "noticia", "idioma": "en", "filtro": "vuln",
     "url": "https://www.securityweek.com/feed/"},
]

CVE_TXT = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Señales de que ya se explota, en los idiomas de las fuentes
EXPLOTADA_RE = re.compile(
    r"exploited in the wild|actively exploited|under active exploitation|being exploited|exploited as a zero"
    r"|known to be exploited|exploitation (?:has been |was )?(?:observed|detected|reported)"
    r"|exploit for cve-\d{4}-\d+ exists in the wild|in-the-wild exploit"
    r"|zero[- ]day|\b0[- ]?day\b"
    r"|explotad[ao]s? activamente|explotaci[oó]n activa|est[aá]n? siendo explotad|d[ií]a cero"
    r"|activement exploit|exploit[ée]+e?s? activement|en cours d'exploitation", re.I)
DIA_CERO_RE = re.compile(r"zero[- ]day|\b0[- ]?day\b|d[ií]a cero|exists in the wild|exploited as a zero", re.I)
CRITICA_RE = re.compile(r"\bcritical\b|\bcr[ií]tic[ao]s?\b|\bcritique\b", re.I)
VULN_RE = re.compile(
    r"vulnerab|\bcve-\d|zero[- ]day|\b0[- ]?day\b|exploit|\bpatch|parche|\bfallos?\b|\bflaws?\b|\brce\b"
    r"|remote code|security (?:update|fix|advisory)|actualizaci[oó]n(?:es)? de seguridad|backdoor"
    r"|puerta trasera|\bbug\b.*\b(?:fix|patch)|explotad|explotaci[oó]n", re.I)
_ETIQUETAS = re.compile(r"<[^>]+>")


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


# ── lectura de feeds ─────────────────────────────────────────────────────────
def descargar(url: str) -> bytes:
    """GET con límite de tamaño: un feed de 50 MB o una respuesta infinita no
    pueden tumbar el pipeline."""
    with requests.get(url, headers=UA, timeout=TIMEOUT, stream=True) as r:
        r.raise_for_status()
        datos = b""
        for trozo in r.iter_content(64 * 1024):
            datos += trozo
            if len(datos) > MAX_BYTES:
                raise ValueError(f"más de {MAX_BYTES // 1024 // 1024} MB")
        return datos


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _texto(el) -> str:
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip() if el is not None else ""


def _plano(s: str) -> str:
    """HTML de la descripción a texto: solo para buscar CVE y palabras clave."""
    return re.sub(r"\s+", " ", html.unescape(_ETIQUETAS.sub(" ", html.unescape(s or "")))).strip()


def _fecha(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    d = None
    try:
        d = parsedate_to_datetime(s)            # RSS: «Tue, 27 Oct 2026 09:15:00 +0000»
    except (TypeError, ValueError, IndexError):
        pass
    if d is None:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))   # Atom / dc:date
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def _enlace(hijos: list) -> str:
    """Atom: <link rel="alternate" href>; RSS: <link>texto</link>; y si no, un guid que sea URL."""
    candidatos = []
    for h in hijos:
        nombre = _local(h.tag)
        if nombre == "link":
            href = h.get("href")
            if href:
                candidatos.append((h.get("rel", "alternate") != "alternate", href.strip()))
            elif (h.text or "").strip():
                candidatos.append((False, h.text.strip()))
        elif nombre in ("guid", "id") and (h.text or "").strip().startswith("http"):
            candidatos.append((True, h.text.strip()))
    candidatos.sort(key=lambda c: c[0])
    return candidatos[0][1] if candidatos else ""


def enlace_seguro(url: str) -> str:
    """Solo http(s) con host: nada de javascript:, data: ni rutas relativas."""
    try:
        p = urlparse((url or "").strip())
    except ValueError:
        return ""
    return url.strip() if p.scheme in ("http", "https") and p.netloc else ""


def leer_feed(datos: bytes) -> list[dict]:
    """RSS 2.0, RSS 1.0 (RDF) o Atom -> [{titulo, enlace, fecha, texto}].

    ElementTree no resuelve entidades externas y expat (>= 2.4, el de Python 3.12)
    limita la expansión de entidades; aun así, un feed con declaraciones de
    entidades no tiene motivo legítimo y se rechaza."""
    if b"<!ENTITY" in datos[:4096].upper():
        raise ValueError("el feed declara entidades XML")
    raiz = ET.fromstring(datos)
    entradas = []
    for el in raiz.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        hijos = list(el)
        primero = {}
        for h in hijos:
            primero.setdefault(_local(h.tag), h)
        fecha = None
        for clave in ("pubdate", "published", "date", "issued", "updated", "modified"):
            if clave in primero:
                fecha = _fecha(_texto(primero[clave]))
                if fecha:
                    break
        cuerpo = " ".join(_plano(_texto(primero[c])) for c in ("description", "summary", "content", "encoded")
                          if c in primero)
        entradas.append({"titulo": _plano(_texto(primero.get("title")))[:300], "enlace": _enlace(hijos),
                         "fecha": fecha, "texto": cuerpo})
    return entradas


def cves_de(*textos: str) -> list[str]:
    """CVE citados, sin repetir y en el orden en que aparecen."""
    vistos = {}
    for t in textos:
        for m in CVE_TXT.finditer(t or ""):
            vistos.setdefault(f"CVE-{m.group(1)}-{m.group(2)}", None)
    return list(vistos)


def pasa_filtro(filtro: str, titulo: str, cves: list[str]) -> bool:
    if filtro == "cve":
        return bool(cves)
    if filtro == "vuln":
        return bool(VULN_RE.search(titulo)) or bool(cves_de(titulo))
    return True


def aviso(fuente: dict, e: dict) -> dict | None:
    enlace = enlace_seguro(e["enlace"])
    if not e["titulo"] or not enlace:
        return None
    cves = cves_de(e["titulo"], e["texto"], enlace)
    if not pasa_filtro(fuente.get("filtro", "todo"), e["titulo"], cves):
        return None
    texto = f"{e['titulo']} {e['texto']}"
    return {
        "fuente": fuente["id"],
        "titulo": e["titulo"],
        "enlace": enlace,
        "fecha": e["fecha"].strftime("%Y-%m-%dT%H:%MZ"),
        "cves": cves[:MAX_CVES_POR_AVISO],
        "cves_total": len(cves),
        "explotada_texto": bool(EXPLOTADA_RE.search(texto)),
        "dia_cero": bool(DIA_CERO_RE.search(texto)),
        "critica_texto": bool(CRITICA_RE.search(e["titulo"])),
    }


def de_fuente(fuente: dict, desde: datetime) -> list[dict]:
    entradas = leer_feed(descargar(fuente["url"]))
    out, vistos = [], set()
    for e in sorted((x for x in entradas if x["fecha"] and x["fecha"] >= desde),
                    key=lambda x: x["fecha"], reverse=True):
        a = aviso(fuente, e)
        if a and a["enlace"] not in vistos:
            vistos.add(a["enlace"])
            out.append(a)
        if len(out) >= MAX_POR_FUENTE:
            break
    return out


# ── cruce con lo que ya sabe el panel ────────────────────────────────────────
def cruzar(avisos: list[dict], kev: set[str], info_cve: dict[str, dict], epss: dict[str, tuple]) -> None:
    """Explotado si el aviso lo dice o si alguno de sus CVE está en KEV; crítico si
    lo dice el título o algún CVE tiene CVSS >= 9; EPSS, el más alto de sus CVE."""
    for a in avisos:
        en_kev = [c for c in a["cves"] if c in kev]
        cvss = [info_cve[c]["cvss"] for c in a["cves"] if (info_cve.get(c) or {}).get("cvss") is not None]
        puntos = [epss[c][0] for c in a["cves"] if c in epss]
        a["kev"] = en_kev
        a["explotada"] = bool(en_kev) or a.pop("explotada_texto")
        a["critica"] = a.pop("critica_texto") or any(x >= 9.0 for x in cvss)
        a["cvss_max"] = max(cvss) if cvss else None
        a["epss_max"] = round(max(puntos), 4) if puntos else None
        a["exploit_publico"] = any((info_cve.get(c) or {}).get("exploit_publico") for c in a["cves"])


def construir(dias: int = 7, kev_cat: list[dict] | None = None, vulns: dict | None = None,
              epss_fn=None) -> dict:
    """Todo el bloque de avisos, listo para data/avisos_latest.json.

    `vulns` es lo que ya calculó vulnerabilidades.construir(): de ahí salen el CVSS
    y el EPSS de los CVE de la semana. Para los CVE más antiguos que citen los
    avisos, `epss_fn` (vulnerabilidades.epss) trae su EPSS en una sola tanda."""
    desde = _ahora() - timedelta(days=dias)
    avisos, estado = [], []
    for f in FUENTES:
        fila = {k: f[k] for k in ("id", "nombre", "tipo", "idioma")} | {"url": f["url"]}
        try:
            nuevos = de_fuente(f, desde)
            fila |= {"estado": "ok", "avisos": len(nuevos)}
            avisos += nuevos
        except Exception as exc:            # una fuente caída no tumba el resto
            log.warning("Avisos %s falló: %s", f["id"], exc)
            fila |= {"estado": "error", "avisos": 0}
        estado.append(fila)

    info_cve = {c["cve"]: c for c in (vulns or {}).get("cves") or []}
    kev = {k.get("cveID") for k in kev_cat or []}
    epss = {c: (v["epss"], v.get("epss_percentil")) for c, v in info_cve.items() if v.get("epss") is not None}
    sin_epss = sorted({c for a in avisos for c in a["cves"] if CVE_RE.match(c) and c not in epss})
    if sin_epss and epss_fn:
        try:
            epss |= epss_fn(sin_epss)
        except Exception as exc:
            log.warning("EPSS de los CVE de avisos falló: %s", exc)
    cruzar(avisos, kev, info_cve, epss)
    avisos.sort(key=lambda a: a["fecha"], reverse=True)

    por_tipo = Counter(next(f["tipo"] for f in FUENTES if f["id"] == a["fuente"]) for a in avisos)
    menciones = Counter(c for a in avisos for c in a["cves"])
    log.info("Avisos: %d en %d días de %d fuentes (%d con error)", len(avisos), dias,
             len(FUENTES), sum(f["estado"] == "error" for f in estado))
    return {
        "generado_utc": _ahora().strftime("%Y-%m-%d %H:%M"),
        "ventana_dias": dias,
        "tipos": TIPOS,
        "fuentes": estado,
        "resumen": {
            "avisos": len(avisos),
            "por_tipo": dict(por_tipo),
            "explotados": sum(a["explotada"] for a in avisos),
            "dia_cero": sum(a["dia_cero"] for a in avisos),
            "criticos": sum(a["critica"] for a in avisos),
            "cves_citados": len(menciones),
            "fuentes_ok": sum(f["estado"] == "ok" for f in estado),
            "fuentes_total": len(estado),
        },
        # Los CVE de los que más se habla esta semana, con quién los cita
        "mas_citados": [{"cve": c, "avisos": n, "kev": c in kev,
                         "fuentes": sorted({a["fuente"] for a in avisos if c in a["cves"]})}
                        for c, n in menciones.most_common(10) if n > 1],
        "avisos": avisos,
    }
