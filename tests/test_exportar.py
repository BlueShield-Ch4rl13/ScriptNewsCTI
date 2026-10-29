"""Salidas para otras herramientas: Atom, feed MISP, histórico y alertas."""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import exportar as X  # noqa: E402

AHORA = datetime(2026, 10, 29, 22, 0, tzinfo=timezone.utc)


def aviso(enlace="https://www.incibe.es/a", titulo="Vulnerabilidad en Fortinet", **k):
    base = {"fuente": "incibe", "titulo": titulo, "enlace": enlace, "fecha": "2026-10-29T10:00Z",
            "cves": ["CVE-2026-1500"], "cves_total": 1, "kev": [], "explotada": False, "dia_cero": False,
            "sin_parche": False, "critica": False, "exploit_publico": False, "epss_max": None}
    return base | k


def bloque(*avisos):
    return {"generado_utc": "2026-10-29 22:00", "fuentes": [{"id": "incibe", "nombre": "INCIBE-CERT"}],
            "avisos": list(avisos)}


# ── Atom ─────────────────────────────────────────────────────────────────────
def test_atom_solo_lo_importante_y_bien_escapado():
    xml = X.atom_avisos(bloque(
        aviso(enlace="https://x.example/1?a=1&b=2", titulo="Fallo <crítico> & explotado", explotada=True,
              kev=["CVE-2026-1500"], epss_max=0.42),
        aviso(enlace="https://x.example/2", titulo="Aviso informativo"),
        aviso(enlace="https://x.example/3", titulo="Zero-day", dia_cero=True)))
    raiz = ET.fromstring(xml.encode())
    ns = {"a": "http://www.w3.org/2005/Atom"}
    entradas = raiz.findall("a:entry", ns)
    assert len(entradas) == 2, "el aviso sin señales no entra"
    assert entradas[0].find("a:title", ns).text == "[Ya se explota] Fallo <crítico> & explotado"
    assert entradas[0].find("a:link", ns).get("href") == "https://x.example/1?a=1&b=2"
    assert entradas[0].find("a:updated", ns).text == "2026-10-29T10:00:00Z"
    assert "KEV: CVE-2026-1500" in entradas[0].find("a:summary", ns).text
    assert "EPSS máx. 42.0 %" in entradas[0].find("a:summary", ns).text
    assert raiz.find("a:updated", ns).text == "2026-10-29T22:00:00Z"
    ids = [e.find("a:id", ns).text for e in entradas]
    assert len(set(ids)) == 2 and all(i.startswith("urn:uuid:") for i in ids)


# ── MISP ─────────────────────────────────────────────────────────────────────
IOCS = [
    {"value": "85.137.54.178:18082", "type": "ip:port", "threat": "Remcos", "score": 80, "level": "alta",
     "severity": "alta", "sources": ["ThreatFox"]},
    {"value": "https://c.bb69.org/m/", "type": "url", "threat": "Vidar", "score": 56, "level": "media",
     "severity": "alta", "sources": ["ThreatFox", "URLhaus"]},
    {"value": "b00417929e836f65e871c18de230ef301064f98b6b3b6166b8888079907aa04e", "type": "filehash-sha256",
     "threat": "AMOS", "score": 40, "level": "media", "severity": "alta", "sources": ["ThreatFox"]},
    {"value": "algo", "type": "tipo-desconocido", "score": 90},
    {"value": "sin-puerto:", "type": "ip:port", "score": 90},
]


def test_atributos_misp():
    uid = "8f6ea6a1-0000-5000-8000-000000000000"
    ip = X.atributo_misp(IOCS[0], uid, 1)
    assert ip["type"] == "ip-dst|port" and ip["value"] == "85.137.54.178|18082" and ip["to_ids"]
    assert X.atributo_misp(IOCS[2], uid, 1)["to_ids"] is False, "score < 50: no va a IDS"
    assert X.atributo_misp(IOCS[3], uid, 1) is None and X.atributo_misp(IOCS[4], uid, 1) is None
    ipv6 = X.atributo_misp({"value": "[2001:db8::1]:443", "type": "ip:port", "score": 60}, uid, 1)
    assert ipv6["value"] == "2001:db8::1|443"


def test_feed_misp_acumula_el_dia_y_retira_lo_viejo(tmp_path):
    carpeta = tmp_path / "misp"
    r1 = X.misp_feed(IOCS[:2], str(carpeta), ahora=AHORA)
    assert r1 == {"eventos": 1, "atributos_hoy": 2, "nuevos": 2}
    # un evento de hace 8 días y un fichero corrupto: se retiran los dos
    viejo = X.misp_feed(IOCS[:1], str(carpeta), ahora=AHORA - timedelta(days=8))
    assert viejo["eventos"] == 2
    (carpeta / "00000000-0000-0000-0000-000000000000.json").write_text("{no es json")
    r2 = X.misp_feed(IOCS, str(carpeta), ahora=AHORA + timedelta(hours=1))
    assert r2 == {"eventos": 1, "atributos_hoy": 3, "nuevos": 1}, "el mismo día se suma sin repetir"
    manifiesto = json.loads((carpeta / "manifest.json").read_text())
    [(uid, cab)] = manifiesto.items()
    assert cab["date"] == "2026-10-29" and cab["Orgc"]["name"] == "News CTI"
    assert {t["name"] for t in cab["Tag"]} == {"tlp:clear", "source:News CTI"}
    evento = json.loads((carpeta / f"{uid}.json").read_text())["Event"]
    assert evento["uuid"] == uid and evento["info"] == "News CTI · IOCs del 2026-10-29"
    assert {a["type"] for a in evento["Attribute"]} == {"ip-dst|port", "url", "sha256"}
    lineas = (carpeta / "hashes.csv").read_text().splitlines()
    assert len(lineas) == 3 and all(l.endswith("," + uid) for l in lineas)
    assert sorted(p.name for p in carpeta.iterdir()) == sorted(["manifest.json", "hashes.csv", f"{uid}.json"])


def test_feed_misp_lo_lee_pymisp(tmp_path):
    pymisp = pytest.importorskip("pymisp")
    X.misp_feed(IOCS, str(tmp_path), ahora=AHORA)
    uid = next(iter(json.loads((tmp_path / "manifest.json").read_text())))
    ev = pymisp.MISPEvent()
    ev.load_file(str(tmp_path / f"{uid}.json"))
    assert len(ev.attributes) == 3 and ev.info.startswith("News CTI")


# ── Histórico ────────────────────────────────────────────────────────────────
def test_historico(tmp_path):
    ruta = tmp_path / "historico.json"
    ruta.write_text("{roto")
    vulns = {"resumen": {"cves": 3200, "explotados": 2, "urgentes": 19, "paquetes_maliciosos": 300}}
    avs = {"resumen": {"avisos": 290, "explotados": 60, "dia_cero": 5}}
    iocs = [{"level": "alta", "severity": "critica"}, {"level": "media", "severity": "alta"}]
    X.historico(str(ruta), vulns, avs, iocs, [1, 2, 3], ahora=AHORA - timedelta(days=200))
    X.historico(str(ruta), vulns, avs, iocs, [1, 2, 3], ahora=AHORA)
    d = X.historico(str(ruta), None, None, iocs[:1], [], ahora=AHORA + timedelta(hours=1))
    assert list(d["dias"]) == ["2026-10-29"], "lo de hace 200 días se va; el mismo día se sobrescribe"
    assert d["dias"]["2026-10-29"] == {"iocs": 1, "iocs_alta": 1, "iocs_critica": 1, "kev_14d": 0}


# ── Alertas ──────────────────────────────────────────────────────────────────
def test_terminos_y_novedades():
    assert X.terminos("Fortinet, palo alto ;splunk\nab") == ["fortinet", "palo alto", "splunk"]
    previo = aviso(enlace="https://www.incibe.es/viejo", explotada=True)
    b = bloque(previo, aviso(enlace="https://n/1", explotada=True), aviso(enlace="https://n/2"),
               aviso(enlace="https://n/3", titulo="Fallo en Palo Alto PAN-OS"))
    assert X.novedades(b, [], ["palo alto"]) == [], "sin ejecución anterior no se avisa de la semana entera"
    nov = X.novedades(b, [previo], ["palo alto"])
    assert [n["enlace"] for n in nov] == ["https://n/1", "https://n/3"]
    assert nov[0]["senales"] == ["Ya se explota"] and nov[1]["vigilado"] == ["palo alto"]
    assert "en tu lista: palo alto" in X.texto_alerta(nov[1]) and "https://n/3" in X.texto_alerta(nov[1])


def test_notificar(monkeypatch, caplog):
    enviados = []

    class R:
        def raise_for_status(self):
            pass

    def post(url, data, headers, timeout):
        enviados.append((url, json.loads(data), headers))
        return R()

    monkeypatch.setattr(X.requests, "post", post)
    nov = [{"titulo": "t", "enlace": "https://n/1", "fuente": "CISA", "fecha": "", "cves": [], "kev": [],
            "senales": ["Ya se explota"], "epss_max": None, "vigilado": []}]
    assert X.notificar(nov, None) is False and X.notificar([], "https://h/w") is False
    assert X.notificar(nov, "http://h/w") is False, "solo https"
    assert X.notificar(nov, "https://h/w", "secreto") is True
    url, cuerpo, cab = enviados[0]
    assert cuerpo["total"] == 1 and "Ya se explota" in cuerpo["texto"] and cab["Authorization"] == "Bearer secreto"

    def falla(*a, **k):
        raise X.requests.ConnectionError("https://h/w?token=secreto no responde")

    monkeypatch.setattr(X.requests, "post", falla)
    assert X.notificar(nov, "https://h/w?token=secreto") is False
    assert "secreto" not in caplog.text, "la URL del webhook es un secreto: no va al log"
