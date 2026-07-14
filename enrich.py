"""Enriquecimiento y scoring de IOCs.

Añade tres capas sobre los feeds crudos:

1. Fusión multi-fuente: un mismo IOC visto en varios feeds se convierte en
   una sola entrada con la lista de fuentes (más fuentes = más confianza).
2. Estado histórico (data/ioc_state.json): persiste entre ejecuciones para
   calcular la edad real del indicador y cachear los enriquecimientos, de
   forma que no se repitan consultas a las APIs externas.
3. Validación externa opcional: AbuseIPDB (IPs, incluye país/ISP) y
   VirusTotal (hashes, dominios, URLs e IPs), con presupuesto por ejecución
   y pausas para respetar los límites de los planes gratuitos.

Sin API keys el módulo sigue funcionando (Fase 1): fusión, antigüedad y
confianza del feed. Con VT_API_KEY y/o ABUSEIPDB_API_KEY se activa la
Fase 2 automáticamente.

Modelo de scoring (0-100), también documentado en el README:

    base por fuente      ThreatFox/URLhaus 40 · OTX 25 · otras 20 (se toma el máximo)
    multi-fuente         +10 por cada fuente adicional (máx +20)
    confianza del feed   confidence * 0.15               (hasta +15)
    AbuseIPDB            abuseConfidenceScore * 0.20     (hasta +20)
    VirusTotal           (malicious / total) * 25        (hasta +25)
    frescura             x1.0 ≤7d · x0.85 ≤30d · x0.6 ≤90d · x0.3 resto

Niveles: alta ≥70 · media 40-69 · baja <40.

Además calcula la GRAVEDAD del IOC (crítica/alta/media/baja) clasificando la
familia o categoría de amenaza reportada — dimensión independiente del score:
el score mide cuánto fiarse del indicador; la gravedad, el impacto si es real.
Y resuelve GeoIP para todas las IPs sin API keys usando la base gratuita
DB-IP Country Lite (CC BY 4.0), descargada bajo demanda a un directorio
temporal (nunca al repo).
"""
import base64
import gzip
import ipaddress
import json
import logging
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

import requests

try:
    import maxminddb
except ImportError:  # GeoIP es opcional: el pipeline funciona sin la librería
    maxminddb = None

log = logging.getLogger(__name__)

STATE_PATH = os.path.join("data", "ioc_state.json")
TIMEOUT = 30

# --- Configuración vía variables de entorno (todas opcionales) ---
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_BUDGET = int(os.getenv("VT_BUDGET", "40"))              # lookups VT por ejecución
ABUSEIPDB_BUDGET = int(os.getenv("ABUSEIPDB_BUDGET", "150"))
VT_SLEEP = float(os.getenv("VT_SLEEP", "15.5"))            # 4 req/min en plan gratuito
RECHECK_DAYS = int(os.getenv("CTI_RECHECK_DAYS", "7"))     # caducidad de la caché
RETENTION_DAYS = int(os.getenv("CTI_RETENTION_DAYS", "14"))
MAX_STATE = int(os.getenv("CTI_MAX_STATE", "6000"))

SOURCE_BASE = {"ThreatFox": 40, "URLhaus": 40, "OTX": 25}
DEFAULT_BASE = 20

# Familias/categorías para clasificar la gravedad (subcadena, en minúsculas)
SEV_CRITICA = (
    "lockbit", "blackcat", "alphv", "akira", "ransomhub", "clop", "cl0p",
    "medusa", "black basta", "blackbasta", "ransom",
    "cobalt strike", "cobaltstrike", "sliver", "havoc", "brute ratel", "mythic",
)
SEV_ALTA = (
    "asyncrat", "remcos", "quasar", "njrat", "dcrat", "venomrat", "xworm",
    "nanocore", "lumma", "redline", "vidar", "stealc", "raccoon",
    "rhadamanthys", "agenttesla", "agent tesla", "formbook", "snake keylogger",
    "qakbot", "qbot", "pikabot", "icedid", "emotet", "trickbot", "bumblebee",
    "darkgate", "socgholish", "fakeupdates", "gootloader", "mirai", "amadey",
    "smokeloader", "latrodectus", "danabot", "netsupport",
    "clearfake", "kongtuke", "aisuru",
)
# Categorías genéricas: si la familia no está en las listas pero su nombre
# delata el tipo de malware, también es gravedad alta
SEV_ALTA_GENERICAS = (
    "stealer", "rat", "loader", "backdoor", "keylogger", "botnet",
    "banker", "spyware",
)

GEO_PATH = os.path.join(tempfile.gettempdir(), "dbip-country-lite.mmdb")
GEO_URL = "https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz"
_geo_db = None


# ---------------------------------------------------------------- utilidades
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_days(iso: str) -> int | None:
    """Días transcurridos desde un timestamp ISO propio (o None si no parsea)."""
    if not iso:
        return None
    try:
        then = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max(0, (datetime.now(timezone.utc) - then).days)


def _extract_ip(value: str, ioc_type: str) -> str | None:
    """Devuelve la IP válida contenida en el IOC, o None si no aplica."""
    t = (ioc_type or "").lower()
    v = (value or "").strip()
    if t == "ip:port":
        v = v.rsplit(":", 1)[0]
    elif "ip" not in t:
        return None
    v = v.strip("[]")
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        return None


def _vt_target(value: str, ioc_type: str):
    """Mapea (valor, tipo) a la colección de la API v3 de VirusTotal."""
    t = (ioc_type or "").lower()
    if any(h in t for h in ("sha256", "sha1", "md5", "hash")):
        return "files", value.lower()
    if t in ("domain", "hostname"):
        return "domains", value
    if t == "url":
        vid = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return "urls", vid
    ip = _extract_ip(value, ioc_type)
    if ip:
        return "ip_addresses", ip
    return None, None


# ------------------------------------------------------ geoip y gravedad
def _ensure_geodb() -> None:
    """Descarga (si hace falta) y abre la base DB-IP Country Lite.

    Sin registro ni API key; ~10 MB, se guarda en el directorio temporal
    del runner. Si algo falla, el pipeline sigue sin GeoIP.
    """
    global _geo_db
    if _geo_db is not None or maxminddb is None:
        return
    if not os.path.exists(GEO_PATH):
        now = datetime.now(timezone.utc)
        prev = (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
        for ym in (now.strftime("%Y-%m"), prev):
            try:
                r = requests.get(GEO_URL.format(ym=ym), timeout=60)
                r.raise_for_status()
                with open(GEO_PATH, "wb") as f:
                    f.write(gzip.decompress(r.content))
                log.info("GeoIP: base DB-IP %s descargada", ym)
                break
            except Exception as exc:
                log.warning("GeoIP: no se pudo descargar la base %s (%s)", ym, exc)
    try:
        _geo_db = maxminddb.open_database(GEO_PATH)
    except Exception as exc:
        log.warning("GeoIP desactivado: %s", exc)
        _geo_db = False  # centinela: no reintentar en esta ejecución


def _geo_lookup(ip: str) -> str:
    """Código ISO del país de una IP, o cadena vacía."""
    if not _geo_db:
        return ""
    try:
        rec = _geo_db.get(ip) or {}
        return ((rec.get("country") or {}).get("iso_code")) or ""
    except Exception:
        return ""


def classify_severity(threat: str, vt: dict | None) -> str:
    """Gravedad del IOC según la familia/categoría de amenaza reportada.

    crítica  ransomware y frameworks C2 (Cobalt Strike, Sliver…)
    alta     RATs, stealers, loaders y botnets — familias conocidas o
             categoría genérica en el nombre ("X Stealer", "Unknown RAT"…)
    media    resto de amenazas identificadas (payload delivery, phishing…)
             o desconocidas con ratio de detecciones VT >= 0,3
    baja     sin familia identificada ni señal externa
    """
    t = (threat or "").lower()
    if any(k in t for k in SEV_CRITICA):
        return "critica"
    if any(k in t for k in SEV_ALTA):
        return "alta"
    if any(k in t for k in SEV_ALTA_GENERICAS):
        return "alta"
    if t and t != "unknown":
        return "media"
    ratio = (vt["malicious"] / vt["total"]) if vt and vt.get("total") else 0.0
    return "media" if ratio >= 0.3 else "baja"


# ------------------------------------------------------------ fusión de feeds
def merge_sources(iocs: list[dict]) -> list[dict]:
    """Fusiona IOCs duplicados entre feeds conservando la información más rica.

    A diferencia de un dedupe simple, guarda la lista completa de fuentes
    (clave para el scoring), la confianza máxima reportada y la primera
    referencia/amenaza no vacía.
    """
    merged: dict[str, dict] = {}
    for i in iocs:
        v = i.get("value")
        if not v:
            continue
        m = merged.get(v)
        if m is None:
            m = dict(i)
            m["sources"] = [i["source"]] if i.get("source") else []
            merged[v] = m
            continue
        s = i.get("source")
        if s and s not in m["sources"]:
            m["sources"].append(s)
        c = i.get("confidence")
        if c is not None and (m.get("confidence") is None or c > m["confidence"]):
            m["confidence"] = c
        if m.get("threat") in (None, "", "unknown") and i.get("threat"):
            m["threat"] = i["threat"]
        if not m.get("reference") and i.get("reference"):
            m["reference"] = i["reference"]
        if not m.get("first_seen") and i.get("first_seen"):
            m["first_seen"] = i["first_seen"]
    return list(merged.values())


# ------------------------------------------------------------------- estado
def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def _update_state(state: dict, iocs: list[dict]) -> None:
    now = _now_iso()
    for i in iocs:
        entry = state.setdefault(i["value"], {"first_seen_local": now, "sources": []})
        entry["last_seen_local"] = now
        for s in i.get("sources") or []:
            if s not in entry["sources"]:
                entry["sources"].append(s)


def _prune_state(state: dict) -> int:
    """Retira entradas antiguas para que el fichero no crezca sin control."""
    before = len(state)
    stale = [
        v for v, e in state.items()
        if (_age_days(e.get("last_seen_local")) or 0) > RETENTION_DAYS
    ]
    for v in stale:
        del state[v]
    if len(state) > MAX_STATE:
        keep = sorted(
            state.items(),
            key=lambda kv: kv[1].get("last_seen_local", ""),
            reverse=True,
        )[:MAX_STATE]
        state.clear()
        state.update(dict(keep))
    return before - len(state)


# ----------------------------------------------------- consultas a APIs externas
def _needs_check(cached: dict | None) -> bool:
    if not cached:
        return True
    age = _age_days(cached.get("checked"))
    return age is None or age >= RECHECK_DAYS


def _abuse_request(ip: str) -> dict:
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    d = r.json().get("data") or {}
    return {
        "score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode") or "",
        "isp": d.get("isp") or "",
        "checked": _now_iso(),
    }


def _vt_request(collection: str, vid: str) -> dict:
    r = requests.get(
        f"https://www.virustotal.com/api/v3/{collection}/{vid}",
        headers={"x-apikey": VT_API_KEY},
        timeout=TIMEOUT,
    )
    if r.status_code == 404:  # VT no conoce el IOC: se cachea para no reintentar
        return {"malicious": 0, "total": 0, "checked": _now_iso(), "found": False}
    r.raise_for_status()
    attrs = (r.json().get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    return {
        "malicious": int(stats.get("malicious") or 0),
        "total": total,
        "checked": _now_iso(),
        "found": True,
    }


def _candidates(state: dict, iocs: list[dict], kind: str) -> list[dict]:
    """IOCs de esta ejecución pendientes de consulta, nuevos primero."""
    pending = [
        i for i in iocs
        if _needs_check((state.get(i["value"]) or {}).get(kind))
    ]
    pending.sort(
        key=lambda i: (state.get(i["value"], {}).get("first_seen_local", "")),
        reverse=True,
    )
    return pending


def _run_lookups(state: dict, iocs: list[dict]) -> None:
    # --- AbuseIPDB: solo IPs, plan gratuito 1.000 checks/día ---
    if ABUSEIPDB_API_KEY:
        done = 0
        for i in _candidates(state, iocs, "abuse"):
            if done >= ABUSEIPDB_BUDGET:
                break
            ip = _extract_ip(i.get("value"), i.get("type"))
            if not ip:
                continue
            try:
                state[i["value"]]["abuse"] = _abuse_request(ip)
                done += 1
                time.sleep(0.4)
            except Exception as exc:
                log.warning("AbuseIPDB falló para %s: %s", ip, exc)
                break  # si la API rechaza (cuota/clave), no insistimos
        log.info("AbuseIPDB: %d IPs consultadas", done)
    else:
        log.info("AbuseIPDB omitido: falta ABUSEIPDB_API_KEY (opcional)")

    # --- VirusTotal: 4 req/min y 500/día en plan gratuito ---
    if VT_API_KEY:
        done = 0
        for i in _candidates(state, iocs, "vt"):
            if done >= VT_BUDGET:
                break
            collection, vid = _vt_target(i.get("value"), i.get("type"))
            if not collection:
                continue
            try:
                state[i["value"]]["vt"] = _vt_request(collection, vid)
                done += 1
                if done < VT_BUDGET:
                    time.sleep(VT_SLEEP)
            except Exception as exc:
                log.warning("VirusTotal falló para %s: %s", i.get("value"), exc)
                break
        log.info("VirusTotal: %d IOCs consultados", done)
    else:
        log.info("VirusTotal omitido: falta VT_API_KEY (opcional)")


# ------------------------------------------------------------------- scoring
def compute_score(ioc: dict, entry: dict) -> tuple[int, str, int]:
    """Score 0-100 explicable + nivel + edad en días. Fórmula en el docstring."""
    sources = ioc.get("sources") or []
    base = max((SOURCE_BASE.get(s, DEFAULT_BASE) for s in sources), default=DEFAULT_BASE)
    multi = min(max(len(sources) - 1, 0), 2) * 10
    feed_conf = (ioc.get("confidence") or 0) * 0.15

    abuse = entry.get("abuse") or {}
    abuse_pts = (abuse.get("score") or 0) * 0.20

    vt = entry.get("vt") or {}
    vt_pts = (vt["malicious"] / vt["total"]) * 25 if vt.get("total") else 0.0

    raw = min(100.0, base + multi + feed_conf + abuse_pts + vt_pts)

    age = _age_days(entry.get("last_seen_local"))
    age = 0 if age is None else age
    freshness = 1.0 if age <= 7 else 0.85 if age <= 30 else 0.6 if age <= 90 else 0.3

    score = round(raw * freshness)
    level = "alta" if score >= 70 else "media" if score >= 40 else "baja"
    return score, level, age


# --------------------------------------------------------------- API pública
def enrich(iocs: list[dict]) -> list[dict]:
    """Punto de entrada: estado + APIs externas + score. Devuelve la lista
    ordenada por score descendente, lista para publicar."""
    state = _load_state()
    _update_state(state, iocs)
    _run_lookups(state, iocs)
    _ensure_geodb()

    out = []
    for i in iocs:
        entry = state.get(i["value"]) or {}
        score, level, age = compute_score(i, entry)
        abuse = entry.get("abuse") or {}
        vt = entry.get("vt") or {}
        severity = classify_severity(i.get("threat"), vt or None)
        ip = _extract_ip(i.get("value"), i.get("type"))
        country = (_geo_lookup(ip) if ip else "") or abuse.get("country") or ""
        sources = i.get("sources") or ([i["source"]] if i.get("source") else [])
        out.append({
            **i,
            "sources": sources,
            "source": ", ".join(sources),
            "score": score,
            "level": level,
            "severity": severity,
            "age_days": age,
            "country": country,
            "abuse_score": abuse.get("score"),
            "vt_detections": f"{vt.get('malicious', 0)}/{vt['total']}" if vt.get("total") else "",
            "first_seen_local": entry.get("first_seen_local", ""),
            "last_seen_local": entry.get("last_seen_local", ""),
        })

    out.sort(key=lambda x: (x["score"], x.get("first_seen") or ""), reverse=True)

    removed = _prune_state(state)
    _save_state(state)

    levels = {"alta": 0, "media": 0, "baja": 0}
    for i in out:
        levels[i["level"]] += 1
    log.info(
        "Scoring: %d alta · %d media · %d baja · estado: %d entradas (-%d purgadas)",
        levels["alta"], levels["media"], levels["baja"], len(state), removed,
    )
    return out
