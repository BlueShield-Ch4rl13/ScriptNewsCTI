"""Salidas para otras herramientas: feed Atom, feed MISP, histórico diario y alertas.

- Atom (data/avisos.xml): los avisos importantes de la semana, para un lector de
  feeds, Outlook, Teams o un flujo de n8n.
- MISP (data/misp/): los IOCs en formato de feed de MISP (manifest.json + un
  evento por día), para añadir https://cti.carlosvillalbalagos.com/data/misp como
  feed en cualquier MISP.
- Histórico (data/historico.json): una fila por día con las cifras del panel,
  para las gráficas de tendencia.
- Alertas: lo nuevo y grave de esta ejecución (o lo que toca la lista de
  vigilancia) se manda a un webhook (n8n, por ejemplo, y de ahí a Telegram).

Todo es opcional en el sentido de que un fallo aquí no tumba la publicación:
main.py lo envuelve y sigue.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape, quoteattr

import requests

log = logging.getLogger(__name__)
PANEL = "https://cti.carlosvillalbalagos.com/"
NS = uuid.uuid5(uuid.NAMESPACE_URL, PANEL)
SENALES = (("explotada", "Ya se explota"), ("dia_cero", "Día cero"), ("sin_parche", "Sin parche"),
           ("critica", "Crítica"), ("exploit_publico", "Exploit público"))


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def _senales(a: dict) -> list[str]:
    return [n for k, n in SENALES if a.get(k)]


# ── Atom ─────────────────────────────────────────────────────────────────────
def atom_avisos(bloque: dict, maximo: int = 60) -> str:
    """Feed Atom 1.0 con los avisos que ya se explotan, de día cero o críticos."""
    nombres = {f["id"]: f["nombre"] for f in bloque.get("fuentes") or []}
    importantes = [a for a in bloque.get("avisos") or []
                   if a.get("explotada") or a.get("dia_cero") or a.get("critica")][:maximo]
    actualizado = (bloque.get("generado_utc") or _ahora().strftime("%Y-%m-%d %H:%M")).replace(" ", "T") + ":00Z"
    yo = PANEL + "data/avisos.xml"
    lineas = ['<?xml version="1.0" encoding="utf-8"?>',
              '<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="es">',
              "  <title>News CTI · fallos de seguridad importantes</title>",
              "  <subtitle>Avisos de fabricantes, CERT, exploits y noticias que ya se explotan, son de día cero o críticos"
              "</subtitle>",
              f"  <id>{escape(yo)}</id>",
              f'  <link rel="self" type="application/atom+xml" href={quoteattr(yo)}/>',
              f'  <link rel="alternate" type="text/html" href={quoteattr(PANEL)}/>',
              f"  <updated>{escape(actualizado)}</updated>",
              "  <author><name>News CTI</name><uri>https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI</uri></author>"]
    for a in importantes:
        fecha = a["fecha"].replace("Z", ":00Z")
        etiquetas = _senales(a)
        resumen = " · ".join(filter(None, [
            nombres.get(a["fuente"], a["fuente"]),
            ", ".join(etiquetas),
            ("CVE: " + ", ".join(a["cves"]) + (f" y {a['cves_total'] - len(a['cves'])} más"
                                                 if a.get("cves_total", 0) > len(a["cves"]) else "")) if a["cves"] else "",
            f"KEV: {', '.join(a['kev'])}" if a.get("kev") else "",
            f"EPSS máx. {a['epss_max'] * 100:.1f} %" if a.get("epss_max") is not None else "",
        ]))
        titulo = (f"[{etiquetas[0]}] " if etiquetas else "") + a["titulo"]
        lineas += ["  <entry>",
                   f"    <title>{escape(titulo)}</title>",
                   f'    <link rel="alternate" href={quoteattr(a["enlace"])}/>',
                   f"    <id>{escape('urn:uuid:' + str(uuid.uuid5(NS, a['fuente'] + '|' + a['enlace'])))}</id>",
                   f"    <updated>{escape(fecha)}</updated>",
                   f"    <summary>{escape(resumen)}</summary>",
                   *[f"    <category term={quoteattr(e)}/>" for e in etiquetas],
                   "  </entry>"]
    lineas.append("</feed>")
    return "\n".join(lineas) + "\n"


# ── MISP ─────────────────────────────────────────────────────────────────────
ORG = {"name": "News CTI", "uuid": str(uuid.uuid5(NS, "org"))}
TIPOS_MISP = {
    "url": ("url", "Network activity"),
    "domain": ("domain", "Network activity"),
    "hostname": ("hostname", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ip": ("ip-dst", "Network activity"),
    "ip:port": ("ip-dst|port", "Network activity"),
    "filehash-md5": ("md5", "Payload delivery"),
    "filehash-sha1": ("sha1", "Payload delivery"),
    "filehash-sha256": ("sha256", "Payload delivery"),
}
MAX_ATRIBUTOS = 6000
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$")


def atributo_misp(ioc: dict, evento: str, ts: int) -> dict | None:
    tipo = TIPOS_MISP.get((ioc.get("type") or "").lower())
    valor = (ioc.get("value") or "").strip()
    if not tipo or not valor or len(valor) > 2048:
        return None
    if tipo[0] == "ip-dst|port":
        ip, _, puerto = valor.rpartition(":")
        if not ip or not puerto.isdigit():
            return None
        valor = f"{ip.strip('[]')}|{puerto}"
    fuentes = ", ".join(ioc.get("sources") or [ioc.get("source") or ""])
    comentario = f"{ioc.get('threat') or 'desconocida'} · score {ioc.get('score')} ({ioc.get('level')}) · " \
                 f"gravedad {ioc.get('severity')} · {fuentes}"
    return {"uuid": str(uuid.uuid5(uuid.UUID(evento), f"{tipo[0]}|{valor}")), "type": tipo[0], "category": tipo[1],
            "to_ids": (ioc.get("score") or 0) >= 50, "value": valor, "comment": comentario[:250],
            "timestamp": str(ts), "distribution": "5", "disable_correlation": False}


def _cabecera(evento: dict) -> dict:
    """Lo que manifest.json cuenta de cada evento."""
    e = evento["Event"]
    return {k: e[k] for k in ("info", "date", "analysis", "threat_level_id", "timestamp", "publish_timestamp")} | {
        "Orgc": e["Orgc"], "Tag": e["Tag"]}


def misp_feed(iocs: list[dict], carpeta: str, dias: int = 7, ahora: datetime | None = None) -> dict:
    """Actualiza el evento de hoy con los IOCs de esta ejecución, borra los de hace
    más de `dias` y rehace manifest.json y hashes.csv."""
    ahora = ahora or _ahora()
    os.makedirs(carpeta, exist_ok=True)
    hoy = ahora.strftime("%Y-%m-%d")
    ts = int(ahora.timestamp())
    uid = str(uuid.uuid5(NS, "misp/" + hoy))
    ruta = os.path.join(carpeta, uid + ".json")
    previos: dict[str, dict] = {}
    if os.path.exists(ruta):
        try:
            for a in json.load(open(ruta, encoding="utf-8"))["Event"].get("Attribute") or []:
                previos[a["uuid"]] = a
        except (OSError, ValueError, KeyError, TypeError):
            log.warning("MISP: el evento de hoy no se pudo leer; se rehace")
    nuevos = 0
    for ioc in iocs:
        a = atributo_misp(ioc, uid, ts)
        if a and a["uuid"] not in previos:
            previos[a["uuid"]] = a
            nuevos += 1
    atributos = sorted(previos.values(), key=lambda a: (a["type"], a["value"]))[:MAX_ATRIBUTOS]
    evento = {"Event": {
        "uuid": uid, "info": f"News CTI · IOCs del {hoy}", "date": hoy, "analysis": "1", "threat_level_id": "2",
        "published": True, "timestamp": str(ts), "publish_timestamp": str(ts), "distribution": "3",
        "Orgc": ORG, "Tag": [{"name": "tlp:clear"}, {"name": "source:News CTI"}],
        "Attribute": atributos}}
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(evento, f, ensure_ascii=False, separators=(",", ":"))

    corte = (ahora - timedelta(days=dias)).strftime("%Y-%m-%d")
    manifiesto, hashes, borrados = {}, [], 0
    for nombre in sorted(os.listdir(carpeta)):
        if not UUID_RE.match(nombre):
            continue
        p = os.path.join(carpeta, nombre)
        try:
            ev = json.load(open(p, encoding="utf-8"))
            fecha = ev["Event"]["date"]
        except (OSError, ValueError, KeyError, TypeError):
            os.remove(p)
            borrados += 1
            continue
        if fecha < corte:
            os.remove(p)
            borrados += 1
            continue
        manifiesto[ev["Event"]["uuid"]] = _cabecera(ev)
        hashes += [(hashlib.md5(a["value"].encode()).hexdigest(), ev["Event"]["uuid"])
                   for a in ev["Event"].get("Attribute") or []]
    with open(os.path.join(carpeta, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifiesto, f, ensure_ascii=False, indent=1)
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(hashes)
    with open(os.path.join(carpeta, "hashes.csv"), "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    log.info("MISP: evento %s con %d atributos (%d nuevos), %d eventos en el feed, %d retirados",
             hoy, len(atributos), nuevos, len(manifiesto), borrados)
    return {"eventos": len(manifiesto), "atributos_hoy": len(atributos), "nuevos": nuevos}


# ── Histórico ────────────────────────────────────────────────────────────────
def historico(ruta: str, vulns: dict | None, avisos: dict | None, iocs: list[dict], kev: list[dict],
              ahora: datetime | None = None, dias: int = 180) -> dict:
    """Una fila por día (la última ejecución del día manda); se guardan `dias` días."""
    ahora = ahora or _ahora()
    try:
        datos = json.load(open(ruta, encoding="utf-8"))
        filas = datos.get("dias") if isinstance(datos, dict) else None
        filas = filas if isinstance(filas, dict) else {}
    except (OSError, ValueError):
        filas = {}
    r = (vulns or {}).get("resumen") or {}
    ra = (avisos or {}).get("resumen") or {}
    fila = {
        "iocs": len(iocs),
        "iocs_alta": sum(1 for i in iocs if i.get("level") == "alta"),
        "iocs_critica": sum(1 for i in iocs if i.get("severity") == "critica"),
        "kev_14d": len(kev),
    }
    if r:
        fila |= {"cves_7d": r.get("cves", 0), "cves_explotados": r.get("explotados", 0),
                 "cves_urgentes": r.get("urgentes", 0), "paquetes_maliciosos": r.get("paquetes_maliciosos", 0)}
    if ra:
        fila |= {"avisos_7d": ra.get("avisos", 0), "avisos_explotados": ra.get("explotados", 0),
                 "avisos_dia_cero": ra.get("dia_cero", 0)}
    filas[ahora.strftime("%Y-%m-%d")] = fila
    corte = (ahora - timedelta(days=dias)).strftime("%Y-%m-%d")
    filas = {d: v for d, v in sorted(filas.items()) if d >= corte and isinstance(v, dict)}
    salida = {"generado_utc": ahora.strftime("%Y-%m-%d %H:%M"), "dias": filas}
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(salida, f, ensure_ascii=False, indent=1)
    return salida


# ── Alertas ──────────────────────────────────────────────────────────────────
def terminos(texto: str | None) -> list[str]:
    """«fortinet, palo alto ; splunk» -> ['fortinet', 'palo alto', 'splunk']."""
    return [t.strip().lower() for t in re.split(r"[,;\n]", texto or "") if len(t.strip()) >= 3][:50]


def vigilado(a: dict, vigilar: list[str]) -> list[str]:
    texto = f"{a.get('titulo', '')} {' '.join(a.get('cves') or [])}".lower()
    return [t for t in vigilar if t in texto]


def novedades(bloque: dict, previos: list, vigilar: list[str], maximo: int = 20) -> list[dict]:
    """Avisos que no estaban en la ejecución anterior y que ya se explotan, son de
    día cero o tocan la lista de vigilancia. Sin ejecución anterior no se avisa de
    nada: el primer día mandaría la semana entera."""
    if not previos:
        return []
    vistos = {(a.get("fuente"), a.get("enlace")) for a in previos if isinstance(a, dict)}
    nombres = {f["id"]: f["nombre"] for f in bloque.get("fuentes") or []}
    out = []
    for a in bloque.get("avisos") or []:
        if (a["fuente"], a["enlace"]) in vistos:
            continue
        coincide = vigilado(a, vigilar)
        if not (a.get("explotada") or a.get("dia_cero") or coincide):
            continue
        out.append({"titulo": a["titulo"], "enlace": a["enlace"], "fuente": nombres.get(a["fuente"], a["fuente"]),
                    "fecha": a["fecha"], "cves": a["cves"], "kev": a.get("kev") or [], "senales": _senales(a),
                    "epss_max": a.get("epss_max"), "vigilado": coincide})
    return out[:maximo]


def texto_alerta(n: dict) -> str:
    cabeza = " · ".join(n["senales"] + ([f"en tu lista: {', '.join(n['vigilado'])}"] if n["vigilado"] else []))
    return "\n".join(filter(None, [f"⚠️ {cabeza}" if cabeza else "", n["titulo"], f"Fuente: {n['fuente']}",
                                   f"CVE: {', '.join(n['cves'])}" if n["cves"] else "", n["enlace"]]))


def notificar(lista: list[dict], url: str | None, token: str | None = None) -> bool:
    """POST JSON al webhook (n8n). Solo https. Nunca tumba el pipeline."""
    if not lista or not url:
        return False
    if not url.startswith("https://"):
        log.warning("Alertas: el webhook no es https; no se envía nada")
        return False
    cuerpo = {"origen": "News CTI", "panel": PANEL, "generado_utc": _ahora().strftime("%Y-%m-%d %H:%M"),
              "total": len(lista), "novedades": lista,
              "texto": "\n\n".join(texto_alerta(n) for n in lista)}
    cab = {"Content-Type": "application/json", "User-Agent": "ScriptNewsCTI"}
    if token:
        cab["Authorization"] = f"Bearer {token}"
    try:
        r = requests.post(url, data=json.dumps(cuerpo, ensure_ascii=False).encode(), headers=cab, timeout=15)
        r.raise_for_status()
        log.info("Alertas: %d novedades enviadas al webhook", len(lista))
        return True
    except requests.RequestException as exc:
        # Sin la URL en el log: es un secreto
        log.warning("Alertas: el webhook no respondió bien (%s)", type(exc).__name__)
        return False
