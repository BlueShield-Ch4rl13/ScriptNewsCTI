"""Pruebas del enriquecimiento: fusión, edad, gravedad y depuración."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import enrich  # noqa: E402


def ioc(value, tipo, source="ThreatFox", threat="unknown", first_seen=None, **extra):
    return {"value": value, "type": tipo, "threat": threat, "confidence": 50,
            "first_seen": first_seen, "source": source, "reference": "", **extra}


def test_ip_con_y_sin_puerto_son_el_mismo_ioc_y_suman_fuentes():
    m = enrich.merge_sources([ioc("1.2.3.4:443", "ip:port", "ThreatFox"), ioc("1.2.3.4", "IPv4", "OTX")])
    assert len(m) == 1
    assert sorted(m[0]["sources"]) == ["OTX", "ThreatFox"]
    score_dos, _, _ = enrich.compute_score(m[0], {})
    score_una, _, _ = enrich.compute_score(enrich.merge_sources([ioc("1.2.3.4:443", "ip:port")])[0], {})
    assert score_dos > score_una, "la bonificación por varias fuentes ahora se aplica"


def test_la_edad_sale_del_feed_y_el_decaimiento_actua():
    hace_60 = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S UTC")
    nuevo = ioc("a.example", "domain", first_seen=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    viejo = ioc("b.example", "domain", first_seen=hace_60)
    estado = {"last_seen_local": enrich._now_iso(), "first_seen_local": enrich._now_iso()}
    s_nuevo, _, edad_nuevo = enrich.compute_score(nuevo, estado)
    s_viejo, _, edad_viejo = enrich.compute_score(viejo, estado)
    assert edad_nuevo == 0 and edad_viejo == 60
    assert s_viejo < s_nuevo


def test_rat_como_palabra_y_no_como_subcadena():
    assert enrich.classify_severity("Operation Strategic Harvest", None) == "media"
    assert enrich.classify_severity("Unknown RAT", None) == "alta"
    assert enrich.classify_severity("Some stealers", None) == "alta"


def test_tipos_normalizados_y_cve_fuera():
    m = enrich.merge_sources([ioc("ab" * 32, "sha256_hash"), ioc("CVE-2026-0001", "cve"),
                              ioc("cd" * 32, "FileHash-SHA256", "OTX"), ioc("Malo.Example.", "hostname")])
    tipos = sorted(i["type"] for i in m)
    assert tipos == ["domain", "filehash-sha256", "filehash-sha256"]
    assert all(i["value"] != "CVE-2026-0001" for i in m)


def test_dominios_de_proveedores_y_ptr_de_la_nube():
    m = enrich.merge_sources([ioc("www.google.com", "domain"),
                              ioc("241.50.97.34.bc.googleusercontent.com", "domain"),
                              ioc("https://docs.google.com/x/malo", "url")])
    valores = sorted((i["value"], i["type"]) for i in m)
    assert valores == [("34.97.50.241", "ipv4"), ("https://docs.google.com/x/malo", "url")]


def test_el_titulo_de_un_pulse_no_hace_critico_cada_indicador(monkeypatch, tmp_path):
    monkeypatch.setattr(enrich, "STATE_PATH", str(tmp_path / "estado.json"))
    monkeypatch.setattr(enrich, "_ensure_geodb", lambda: None)
    monkeypatch.setattr(enrich, "VT_API_KEY", "")
    monkeypatch.setattr(enrich, "ABUSEIPDB_API_KEY", "")
    iocs = enrich.merge_sources([ioc("x.example", "domain", "OTX",
                                     threat="INC and The Gentlemen Ransomware: Exposed AI Infrastructure",
                                     threat_from_title=True)])
    out = enrich.enrich(iocs)
    assert out[0]["severity"] == "media"
