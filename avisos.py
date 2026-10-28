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
MAX_POR_FUENTE = 40              # de cada descarga
MAX_POR_FUENTE_VENTANA = 60      # de cada fuente en la semana, sumando ejecuciones anteriores
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
    {"id": "cisa", "nombre": "CISA", "tipo": "cert", "idioma": "en", "filtro": "todo",       # incluye los ICS
     "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"id": "cert_eu", "nombre": "CERT-EU", "tipo": "cert", "idioma": "en", "filtro": "todo",
     "url": "https://cert.europa.eu/publications/security-advisories-rss"},
    {"id": "cert_fr", "nombre": "CERT-FR · alertas", "tipo": "cert", "idioma": "fr", "filtro": "todo",
     "url": "https://www.cert.ssi.gouv.fr/alerte/feed/"},
    {"id": "cert_fr_avis", "nombre": "CERT-FR · avisos", "tipo": "cert", "idioma": "fr", "filtro": "todo",
     "url": "https://www.cert.ssi.gouv.fr/avis/feed/"},
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
    {"id": "ivanti", "nombre": "Ivanti", "tipo": "fabricante", "idioma": "en", "filtro": "todo",
     "url": "https://www.ivanti.com/blog/topics/security-advisory/rss"},
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
     "url": "https://googleprojectzero.blogspot.com/feeds/posts/summary?max-results=10"},   # el feed completo pasa de 8 MB
    {"id": "wordfence", "nombre": "Wordfence (WordPress)", "tipo": "exploit", "idioma": "en", "filtro": "vuln",
     "url": "https://www.wordfence.com/feed/"},
    # Noticias de vulnerabilidades (solo titulares que hablan de una)
    {"id": "unaaldia", "nombre": "Una al Día (Hispasec)", "tipo": "noticia", "idioma": "es", "filtro": "vuln",
     "url": "https://unaaldia.hispasec.com/feed"},
    {"id": "seguinfo", "nombre": "Segu-Info", "tipo": "noticia", "idioma": "es", "filtro": "vuln",
     "url": "https://blog.segu-info.com.ar/feeds/posts/default"},
    {"id": "thehackernews", "nombre": "The Hacker News", "tipo": "noticia", "idioma": "en", "filtro": "vuln",
     "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"id": "bleeping", "nombre": "BleepingComputer", "tipo": "noticia", "idioma": "en", "filtro": "vuln",
     "url": "https://www.bleepingcomputer.com/feed/"},
    {"id": "securityweek", "nombre": "SecurityWeek", "tipo": "noticia", "idioma": "en", "filtro": "vuln",
     "url": "https://www.securityweek.com/feed/"},
]

CVE_TXT = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Señales en el texto, en los idiomas de las fuentes. «Zero-day» sola no
# significa explotada (ZDI llama «0Day» a lo que publica sin parche): para
# «explotada» hace falta que el texto lo diga o que el CVE esté en KEV.
EXPLOTADA_RE = re.compile(
    r"exploited in the wild|exploit(?:ation)? in the wild|in-the-wild|actively exploited|active(?:ly)? exploitation"
    r"|under (?:active )?exploitation|being exploited|known to be exploited"
    r"|exploitation (?:has been |was |is )?(?:observed|detected|reported|confirmed)"
    r"|exploit for cve-\d{4}-\d+ exists in the wild|exploits? (?:\w+ ){0,3}exists? in the wild"
    r"|exploit(?:s|ed|ing)? (?:a |an |the |\w+ )?(?:zero[- ]day|0[- ]?day)|zero[- ]day (?:exploit|attack)"
    r"|explotad[ao]s? activamente|explotaci[oó]n (?:activa|efectiva|confirmada)|est[aá]n? siendo explotad"
    r"|explotad[ao]s? en (?:ataques|la naturaleza)|activement exploit|exploit[ée]+e?s? activement"
    r"|en cours d'exploitation", re.I)
# «Hackers exploit…», «Attackers target…»: solo en el titular. En el cuerpo de un
# aviso de fabricante es la fórmula hipotética («could allow attackers to exploit»).
EXPLOTADA_TITULAR_RE = re.compile(
    r"\b(?:hackers|attackers|threat actors|ransomware(?: gangs?)?|apt\d*|[\w-]+-linked hackers)\s+"
    r"(?:\w+\s+){0,2}(?:exploit|target|abus|hijack|weaponi[sz])|\bexploited (?:as|by|in)\b", re.I)
# «No tenemos constancia de que se explote», «not aware of any exploitation in the
# wild»: la frase de explotación negada en la misma oración no cuenta.
NEGACION_RE = re.compile(
    r"(?:\b(?:not|no|never|unaware|nor|without)\b|no (?:tenemos|se tiene|hay) constancia|sin (?:evidencias?|constancia)"
    r"|\bni\b|n'a pas|aucune?)[^.!?]{0,90}$", re.I)
DIA_CERO_RE = re.compile(r"zero[- ]day|d[ií]a cero|exists in the wild", re.I)
# «0day» a secas es la etiqueta de lo que se publica sin parche: ZDI lo pone en el
# título, «(0Day)», e INCIBE como etiqueta cuando el fabricante no ha corregido.
SIN_PARCHE_RE = re.compile(
    r"\b0[- ]?day\b|no (?:patch|fix) (?:is )?(?:yet )?available|\bunpatched\b|sin parche|without (?:a )?(?:patch|fix)"
    r"|pas de correctif|sin corregir|no se ha (?:comunicado|publicado) (?:un |ning[uú]n )?parche"
    r"|no (?:hay|existe) (?:parche|soluci[oó]n)|sin soluci[oó]n", re.I)
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


def _afirma(rx: re.Pattern, texto: str) -> bool:
    """Alguna coincidencia de `rx` que no esté negada en la misma oración."""
    return any(not NEGACION_RE.search(texto[max(0, m.start() - 120):m.start()]) for m in rx.finditer(texto))


def senal_explotada(titulo: str, cuerpo: str = "") -> bool:
    return _afirma(EXPLOTADA_RE, titulo) or _afirma(EXPLOTADA_RE, cuerpo) or _afirma(EXPLOTADA_TITULAR_RE, titulo)


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
        "texto_explotada": senal_explotada(e["titulo"], e["texto"]),
        "texto_critica": bool(CRITICA_RE.search(e["titulo"])),
        "dia_cero": _afirma(DIA_CERO_RE, texto),
        "sin_parche": bool(SIN_PARCHE_RE.search(texto)),
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


# ── lo de ejecuciones anteriores ─────────────────────────────────────────────
FECHA_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z$")


def _limpio(a) -> dict | None:
    """Un aviso de data/avisos_latest.json, revalidado: ese fichero se lee de vuelta
    y no se confía en él más que en un feed."""
    if not isinstance(a, dict) or not isinstance(a.get("titulo"), str) or not FECHA_RE.match(str(a.get("fecha"))):
        return None
    enlace = enlace_seguro(a.get("enlace") if isinstance(a.get("enlace"), str) else "")
    cves = [c for c in a.get("cves") or [] if isinstance(c, str) and CVE_RE.match(c)]
    if not enlace or not a["titulo"].strip():
        return None
    return {"fuente": a.get("fuente"), "titulo": a["titulo"][:300], "enlace": enlace, "fecha": a["fecha"],
            "cves": cves[:MAX_CVES_POR_AVISO], "cves_total": max(len(cves), int(a.get("cves_total") or 0)),
            **{k: bool(a.get(k)) for k in ("texto_explotada", "texto_critica", "dia_cero", "sin_parche")}}


def fusionar(previos: list, nuevos: list[dict], desde: datetime) -> list[dict]:
    """Lo descargado ahora manda; de lo publicado antes se queda lo que sigue en la
    ventana y ya no sale en el feed (INCIBE, por ejemplo, solo trae sus 10 últimos).
    Así una fuente que hoy no responde no desaparece del panel."""
    ids = {f["id"] for f in FUENTES}
    corte = desde.strftime("%Y-%m-%dT%H:%MZ")
    vistos = {(a["fuente"], a["enlace"]) for a in nuevos}
    todos = list(nuevos)
    for a in map(_limpio, previos if isinstance(previos, list) else []):
        if a and a["fuente"] in ids and a["fecha"] >= corte and (a["fuente"], a["enlace"]) not in vistos:
            vistos.add((a["fuente"], a["enlace"]))
            todos.append(a)
    todos.sort(key=lambda a: a["fecha"], reverse=True)
    por_fuente: Counter = Counter()
    salida = []
    for a in todos:
        por_fuente[a["fuente"]] += 1
        if por_fuente[a["fuente"]] <= MAX_POR_FUENTE_VENTANA:
            salida.append(a)
    return salida


# ── cruce con lo que ya sabe el panel ────────────────────────────────────────
def cruzar(avisos: list[dict], kev: set[str], info_cve: dict[str, dict], epss: dict[str, tuple],
           exploits: dict | None = None) -> None:
    """Explotado si el aviso lo dice o si alguno de sus CVE está en KEV; crítico si
    lo dice el título o algún CVE tiene CVSS >= 9; EPSS, el más alto de sus CVE;
    exploit público si alguno de sus CVE (de esta semana o anterior) está en Exploit-DB."""
    exploits = exploits or {}
    for a in avisos:
        en_kev = [c for c in a["cves"] if c in kev]
        cvss = [info_cve[c]["cvss"] for c in a["cves"] if (info_cve.get(c) or {}).get("cvss") is not None]
        puntos = [epss[c][0] for c in a["cves"] if c in epss and epss[c][0] is not None]
        a["kev"] = en_kev
        a["explotada"] = bool(en_kev) or a["texto_explotada"]
        a["critica"] = a["texto_critica"] or any(x >= 9.0 for x in cvss)
        a["cvss_max"] = max(cvss) if cvss else None
        a["epss_max"] = round(max(puntos), 4) if puntos else None
        edb = next((exploits[c]["edb"] for c in a["cves"] if c in exploits), None) or \
            next((info_cve[c].get("exploitdb") for c in a["cves"] if (info_cve.get(c) or {}).get("exploitdb")), None)
        a["exploit_publico"] = bool(edb)
        a["exploitdb"] = edb


def citas_por_cve(avisos: list[dict]) -> dict[str, list[dict]]:
    """{CVE: [avisos que lo citan, del más reciente al más antiguo]}."""
    out: dict[str, list[dict]] = {}
    for a in sorted(avisos, key=lambda a: a["fecha"], reverse=True):
        for c in a["cves"]:
            out.setdefault(c, []).append(a)
    return out


def mas_citados(citas: dict[str, list[dict]], kev: set[str], info_cve: dict, epss: dict, n: int = 12) -> list[dict]:
    filas = []
    for c, avs in citas.items():
        fuentes = sorted({a["fuente"] for a in avs})
        if len(fuentes) >= 2:
            filas.append({"cve": c, "fuentes": fuentes, "avisos": len(avs), "kev": c in kev,
                          "cvss": (info_cve.get(c) or {}).get("cvss"), "epss": (epss.get(c) or (None,))[0],
                          "ultimo": avs[0]["fecha"]})
    filas.sort(key=lambda f: (-len(f["fuentes"]), -f["avisos"], f["cve"]))
    return filas[:n]


def anotar(vulns: dict, bloque: dict, max_por_cve: int = 3) -> None:
    """En la tabla de CVE, qué avisos de esta semana citan cada uno (enlace y fuente)."""
    citas = citas_por_cve(bloque.get("avisos") or [])
    nombre = {f["id"]: f["nombre"] for f in FUENTES}
    for c in (vulns or {}).get("cves") or []:
        avs = citas.get(c["cve"]) or []
        c["avisos"] = [{"fuente": a["fuente"], "nombre": nombre.get(a["fuente"], a["fuente"]), "enlace": a["enlace"]}
                       for a in avs[:max_por_cve]]
        c["avisos_total"] = len(avs)


def construir(dias: int = 7, kev_cat: list[dict] | None = None, vulns: dict | None = None,
              previos: list | None = None, epss_fn=None, exploits: dict | None = None) -> dict:
    """Todo el bloque de avisos, listo para data/avisos_latest.json.

    `vulns` es lo que ya calculó vulnerabilidades.construir(): de ahí salen el CVSS,
    el EPSS y los exploits públicos de los CVE de la semana. Para los CVE más
    antiguos que citen los avisos, `epss_fn` (vulnerabilidades.epss) trae su EPSS
    en una sola tanda. `previos` son los avisos publicados en la ejecución anterior y
    `exploits`, el mapa de Exploit-DB que ya descargó vulnerabilidades.exploitdb()."""
    desde = _ahora() - timedelta(days=dias)
    nuevos, estado, detalle = [], {}, {}
    for f in FUENTES:
        try:
            de_esta = de_fuente(f, desde)
            estado[f["id"]] = "ok"
            nuevos += de_esta
        except Exception as exc:            # una fuente caída no tumba el resto
            log.warning("Avisos %s falló: %s", f["id"], exc)
            estado[f["id"]] = "error"
            detalle[f["id"]] = f"{type(exc).__name__}: {exc}"[:160]
    avisos = fusionar(previos or [], nuevos, desde)

    info_cve = {c["cve"]: c for c in (vulns or {}).get("cves") or []}
    kev = {k.get("cveID") for k in kev_cat or []}
    epss = {c: (v["epss"], v.get("epss_percentil")) for c, v in info_cve.items() if v.get("epss") is not None}
    sin_epss = sorted({c for a in avisos for c in a["cves"] if CVE_RE.match(c) and c not in epss})
    if sin_epss and epss_fn:
        try:
            epss |= epss_fn(sin_epss)
        except Exception as exc:
            log.warning("EPSS de los CVE de avisos falló: %s", exc)
    cruzar(avisos, kev, info_cve, epss, exploits)

    tipo_de = {f["id"]: f["tipo"] for f in FUENTES}
    cuantos = Counter(a["fuente"] for a in avisos)
    fuentes = [{k: f[k] for k in ("id", "nombre", "tipo", "idioma", "url")}
               | {"estado": estado.get(f["id"], "error"), "avisos": cuantos.get(f["id"], 0)}
               | ({"detalle": detalle[f["id"]]} if f["id"] in detalle else {}) for f in FUENTES]
    citas = citas_por_cve(avisos)
    log.info("Avisos: %d en %d días (%d nuevos en esta ejecución) de %d fuentes, %d con error", len(avisos),
             dias, len(nuevos), len(FUENTES), sum(v == "error" for v in estado.values()))
    return {
        "generado_utc": _ahora().strftime("%Y-%m-%d %H:%M"),
        "ventana_dias": dias,
        "tipos": TIPOS,
        "fuentes": fuentes,
        "resumen": {
            "avisos": len(avisos),
            "por_tipo": dict(Counter(tipo_de[a["fuente"]] for a in avisos)),
            "explotados": sum(a["explotada"] for a in avisos),
            "dia_cero": sum(a["dia_cero"] for a in avisos),
            "sin_parche": sum(a["sin_parche"] for a in avisos),
            "criticos": sum(a["critica"] for a in avisos),
            "exploit_publico": sum(a["exploit_publico"] for a in avisos),
            "cves_citados": len(citas),
            "fuentes_ok": sum(f["estado"] == "ok" for f in fuentes),
            "fuentes_total": len(fuentes),
        },
        # De qué se habla esta semana: los CVE que citan a la vez varias fuentes distintas
        "mas_citados": mas_citados(citas, kev, info_cve, epss),
        "avisos": avisos,
    }
