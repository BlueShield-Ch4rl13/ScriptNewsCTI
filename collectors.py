"""Colectores de feeds CTI gratuitos.

Cada colector devuelve una lista de dicts normalizados:
{value, type, threat, confidence, first_seen, source, reference}

Si un feed falla o falta su API key, devuelve [] y el pipeline continúa.
"""
import logging
import os
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger(__name__)
TIMEOUT = 30

ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")


def _norm(value, ioc_type, threat, confidence, first_seen, source, reference=""):
    return {
        "value": value,
        "type": ioc_type,
        "threat": threat or "unknown",
        "confidence": confidence,
        "first_seen": first_seen,
        "source": source,
        "reference": reference,
    }


def threatfox(days: int = 1) -> list[dict]:
    """IOCs recientes de ThreatFox (abuse.ch). Requiere Auth-Key gratuita."""
    if not ABUSECH_API_KEY:
        log.warning("ThreatFox omitido: falta ABUSECH_API_KEY")
        return []
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": days},
            headers={"Auth-Key": ABUSECH_API_KEY},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        items = r.json().get("data") or []
        iocs = [
            _norm(
                i.get("ioc"),
                i.get("ioc_type"),
                i.get("malware_printable") or i.get("threat_type"),
                i.get("confidence_level"),
                i.get("first_seen"),
                "ThreatFox",
                i.get("reference") or "",
            )
            for i in items
        ]
        log.info("ThreatFox: %d IOCs", len(iocs))
        return iocs
    except Exception as exc:
        log.error("ThreatFox falló: %s", exc)
        return []


def urlhaus(limit: int = 100) -> list[dict]:
    """URLs maliciosas recientes de URLhaus (abuse.ch). Requiere Auth-Key gratuita."""
    if not ABUSECH_API_KEY:
        log.warning("URLhaus omitido: falta ABUSECH_API_KEY")
        return []
    try:
        r = requests.get(
            f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/",
            headers={"Auth-Key": ABUSECH_API_KEY},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        items = r.json().get("urls") or []
        iocs = [
            _norm(
                i.get("url"),
                "url",
                i.get("threat") or ",".join(i.get("tags") or []),
                None,
                i.get("date_added"),
                "URLhaus",
                i.get("urlhaus_reference") or "",
            )
            for i in items
        ]
        log.info("URLhaus: %d URLs", len(iocs))
        return iocs
    except Exception as exc:
        log.error("URLhaus falló: %s", exc)
        return []


def otx_pulses(limit: int = 10, max_indicators: int = 200) -> list[dict]:
    """Indicadores de los últimos pulses suscritos en AlienVault OTX (opcional)."""
    if not OTX_API_KEY:
        log.info("OTX omitido: falta OTX_API_KEY (opcional)")
        return []
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            params={"limit": limit},
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        pulses = r.json().get("results") or []
        iocs = []
        for p in pulses:
            for ind in p.get("indicators") or []:
                iocs.append(
                    _norm(
                        ind.get("indicator"),
                        (ind.get("type") or "").lower(),
                        p.get("name"),
                        None,
                        ind.get("created"),
                        "OTX",
                        f"https://otx.alienvault.com/pulse/{p.get('id')}",
                    )
                )
                if len(iocs) >= max_indicators:
                    break
            if len(iocs) >= max_indicators:
                break
        log.info("OTX: %d indicadores de %d pulses", len(iocs), len(pulses))
        return iocs
    except Exception as exc:
        log.error("OTX falló: %s", exc)
        return []


def cisa_kev(days: int = 14) -> list[dict]:
    """CVEs explotados activamente (CISA KEV) añadidos en los últimos N días. Sin API key."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities") or []
        cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)
        recent = []
        for v in vulns:
            try:
                added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").date()
            except ValueError:
                continue
            if added >= cutoff:
                recent.append(
                    {
                        "cve": v.get("cveID"),
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "name": v.get("vulnerabilityName"),
                        "date_added": v.get("dateAdded"),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    }
                )
        recent.sort(key=lambda x: x["date_added"], reverse=True)
        log.info("CISA KEV: %d CVEs en los últimos %d días", len(recent), days)
        return recent
    except Exception as exc:
        log.error("CISA KEV falló: %s", exc)
        return []
