"""Avisos: lectura de RSS/Atom/RDF, señales de explotación, cruce con KEV y EPSS,
acumulación entre ejecuciones y seguridad de los enlaces.

Los feeds de ejemplo siguen la forma de los reales (comprobados desde un runner
de Actions el 28/10/2026: INCIBE, CISA, Chrome Releases, Debian, ZDI…), recortados."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import avisos as A  # noqa: E402

AHORA = datetime.now(timezone.utc)


def rfc822(d: datetime) -> str:
    return d.strftime("%a, %d %b %Y %H:%M:%S +0000")


def rss(*items) -> bytes:
    cuerpo = "".join(
        f"<item><title>{t}</title><link>{l}</link><pubDate>{rfc822(f)}</pubDate>"
        f"<description><![CDATA[{d}]]></description></item>" for t, l, f, d in items)
    return f'<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel><title>x</title>{cuerpo}</channel></rss>'.encode()


ATOM = f"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>tag:blogger.com,1999:blog-1.post-2</id>
    <published>{(AHORA - timedelta(hours=5)).isoformat()}</published>
    <title type="text">Stable Channel Update for Desktop</title>
    <content type="html">&lt;p&gt;[$NA][N/A] High CVE-2026-118306: Use after free in V8.&lt;/p&gt;
      &lt;p&gt;Google is aware that an exploit for CVE-2026-118306 exists in the wild.&lt;/p&gt;</content>
    <link rel="replies" type="text/html" href="https://chromereleases.googleblog.com/2026/10/x.html#comment-form"/>
    <link rel="self" type="application/atom+xml" href="https://www.blogger.com/feeds/1/posts/default/2"/>
    <link rel="alternate" type="text/html" href="https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_27.html"/>
  </entry>
  <entry>
    <published>{(AHORA - timedelta(hours=6)).isoformat()}</published>
    <title>Beta Channel Update for Desktop</title>
    <content type="html">Beta, sin correcciones de seguridad</content>
    <link rel="alternate" href="https://chromereleases.googleblog.com/2026/10/beta.html"/>
  </entry>
</feed>""".encode()

RDF = f"""<?xml version="1.0" encoding="utf-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
         xmlns:dc="http://purl.org/dc/elements/1.1/">
  <item rdf:about="https://www.debian.org/security/2026/dsa-6588">
    <title>DSA-6588-1 openjdk-21 - security update</title>
    <link>https://www.debian.org/security/2026/dsa-6588</link>
    <description>Several vulnerabilities have been discovered in OpenJDK (CVE-2026-1111, CVE-2026-1112).</description>
    <dc:date>{(AHORA - timedelta(days=1)).strftime("%Y-%m-%d")}</dc:date>
  </item>
</rdf:RDF>""".encode()


# ── lectura ──────────────────────────────────────────────────────────────────
def test_rss_2():
    datos = rss(("Múltiples vulnerabilidades en productos de Citrix", "https://www.incibe.es/aviso/1",
                 AHORA - timedelta(hours=2), "<p>CVE-2026-109618 y <b>cve-2026-109619</b></p>"))
    [e] = A.leer_feed(datos)
    assert e["titulo"] == "Múltiples vulnerabilidades en productos de Citrix"
    assert e["enlace"] == "https://www.incibe.es/aviso/1" and e["fecha"].tzinfo
    assert A.cves_de(e["titulo"], e["texto"]) == ["CVE-2026-109618", "CVE-2026-109619"]


def test_atom_prefiere_el_enlace_alternate_y_lee_el_html_del_contenido():
    entradas = A.leer_feed(ATOM)
    assert entradas[0]["enlace"].endswith("stable-channel-update-for-desktop_27.html"), "ni replies ni self"
    assert "exists in the wild" in entradas[0]["texto"] and "<p>" not in entradas[0]["texto"]


def test_rdf_con_dc_date():
    [e] = A.leer_feed(RDF)
    assert e["fecha"] and e["enlace"] == "https://www.debian.org/security/2026/dsa-6588"
    assert A.cves_de(e["texto"]) == ["CVE-2026-1111", "CVE-2026-1112"]


def test_un_feed_con_entidades_se_rechaza():
    bomba = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss><channel/></rss>'
    with pytest.raises(ValueError):
        A.leer_feed(bomba)


@pytest.mark.parametrize("url, ok", [
    ("https://www.incibe.es/aviso", True), ("http://ejemplo.com/x", True),
    ("javascript:alert(1)", False), ("data:text/html,x", False), ("/relativa", False), ("https://", False), ("", False),
])
def test_enlace_seguro(url, ok):
    assert bool(A.enlace_seguro(url)) is ok


def test_cves_sin_repetir_y_en_orden():
    assert A.cves_de("CVE-2026-2 y cve-2026-0001", "CVE-2026-0001, CVE-2025-12345") == \
        ["CVE-2026-0001", "CVE-2025-12345"], "CVE-2026-2 no es un id válido (4 cifras mínimo)"


# ── señales ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("titulo, cuerpo", [
    ("Cisco Expressway Series Security Hardening Release: October 2026",
     "A vulnerability could allow unauthenticated attackers to exploit the device remotely."),
    ("SSA-887643: Account Hijacking Vulnerability in Mendix SAML module", "could allow attackers to hijack accounts"),
    ("Cisco Unified Communications Products Security Hardening Release",
     "This vulnerability could be exploited by an attacker. The Cisco PSIRT is not aware of any public announcements"
     " or exploitation in the wild of the vulnerabilities that are described in this advisory."),
    ("Vulnerabilidad en Apache Tika", "No se tiene constancia de que esté siendo explotada activamente."),
    ("Ivanti EPMM", "We are not aware of any customers being exploited in the wild at the time of disclosure."),
])
def test_la_formula_hipotetica_del_fabricante_no_es_explotacion(titulo, cuerpo):
    assert not A.senal_explotada(titulo, cuerpo)


@pytest.mark.parametrize("texto, explotada, cero, parche", [
    ("ZDI-26-829: (0Day) (Pwn2Own) Alpine iLX-F511 Bluetooth OBEX Heap-based Buffer Overflow", False, False, True),
    ("Google fixes Chrome zero-day exploited in attacks", True, True, False),
    ("Google is aware that an exploit for CVE-2026-118306 exists in the wild.", True, True, False),
    ("Hackers Target Critical Oracle E-Business Suite RCE Flaw Days After Security Patch", True, False, False),
    ("China-Linked Hackers Exploit PHP2Shell to Root Firewalls", True, False, False),
    ("Fortinet warns of FortiWeb flaw exploited in attacks", True, False, False),
    ("Not a zero-day. Patched last year.", False, False, False),
    ("Explotación efectiva de PHP2Shell confirmada", True, False, False),
    ("Vulnerabilidad explotada activamente en Fortinet", True, False, False),
    ("Une vulnérabilité activement exploitée dans Ivanti", True, False, False),
    ("New zero-day in WinRAR, no patch available", False, True, True),
    ("Stable Channel Update for Desktop", False, False, False),
    ("Multiples vulnérabilités dans Google Chrome", False, False, False),
])
def test_senales(texto, explotada, cero, parche):
    assert A.senal_explotada(texto) is explotada
    assert A._afirma(A.DIA_CERO_RE, texto) is cero
    assert bool(A.SIN_PARCHE_RE.search(texto)) is parche


@pytest.mark.parametrize("filtro, titulo, cves, pasa", [
    ("vuln", "Critical 16-Year-Old UEFI Flaw Can Run Code Before Secure Boot", [], True),
    ("vuln", "Claude Security incorpora análisis continuo de repositorios", [], False),
    ("vuln", "Nueva campaña: CVE-2026-1234 en routers", ["CVE-2026-1234"], True),
    ("cve", "Beta Channel Update for Desktop", [], False),
    ("cve", "Stable Channel Update for Desktop", ["CVE-2026-118306"], True),
    ("todo", "Cisco Informational for Emergency Distrust of eMudhra", [], True),
])
def test_filtros(filtro, titulo, cves, pasa):
    assert A.pasa_filtro(filtro, titulo, cves) is pasa


def test_de_fuente_filtra_por_fecha_y_por_cve(monkeypatch):
    monkeypatch.setattr(A, "descargar", lambda url: ATOM)
    chrome = next(f for f in A.FUENTES if f["id"] == "chrome")
    [a] = A.de_fuente(chrome, AHORA - timedelta(days=7))
    assert a["titulo"] == "Stable Channel Update for Desktop", "la beta no cita CVE: fuera"
    assert a["cves"] == ["CVE-2026-118306"] and a["texto_explotada"] and a["dia_cero"]
    assert A.de_fuente(chrome, AHORA - timedelta(hours=1)) == [], "fuera de la ventana"


# ── acumulación entre ejecuciones ────────────────────────────────────────────
def guardado(fuente="incibe", horas=30, enlace="https://www.incibe.es/viejo", **extra):
    return {"fuente": fuente, "titulo": "Aviso anterior", "enlace": enlace,
            "fecha": (AHORA - timedelta(hours=horas)).strftime("%Y-%m-%dT%H:%MZ"), "cves": ["CVE-2026-0001"],
            "cves_total": 1, "texto_explotada": False, "texto_critica": False, "dia_cero": False, "sin_parche": False,
            **extra}


def test_fusionar_conserva_lo_anterior_que_sigue_en_la_ventana():
    nuevo = guardado(horas=1, enlace="https://www.incibe.es/nuevo")
    previos = [guardado(), guardado(enlace="https://www.incibe.es/nuevo", titulo="versión vieja"),
               guardado(horas=24 * 9, enlace="https://www.incibe.es/antiguo"),
               guardado(enlace="javascript:alert(1)"), guardado(fuente="desconocida", enlace="https://x.example/1"),
               {"fuente": "incibe", "titulo": 3}, "basura"]
    out = A.fusionar(previos, [nuevo], AHORA - timedelta(days=7))
    assert [a["enlace"] for a in out] == ["https://www.incibe.es/nuevo", "https://www.incibe.es/viejo"]
    assert out[0]["titulo"] == "Aviso anterior", "lo descargado ahora manda sobre lo guardado"


def test_fusionar_limita_cada_fuente():
    muchos = [guardado(fuente="msrc", horas=h, enlace=f"https://msrc.microsoft.com/{h}") for h in range(1, 100)]
    out = A.fusionar(muchos, [], AHORA - timedelta(days=7))
    assert len(out) == A.MAX_POR_FUENTE_VENTANA and out[0]["enlace"].endswith("/1"), "se quedan los más recientes"


# ── cruce y construcción ─────────────────────────────────────────────────────
def test_cruzar_con_kev_cvss_y_epss():
    a = guardado(cves=["CVE-2026-0001", "CVE-2026-0002"])
    b = guardado(cves=["CVE-2026-0003"], texto_critica=True)
    c = guardado(cves=["CVE-2024-4577"])
    info = {"CVE-2026-0002": {"cvss": 9.8, "exploit_publico": "exploitdb", "exploitdb": 52704},
            "CVE-2026-0003": {"cvss": 4.0, "exploit_publico": "github"}}
    A.cruzar([a, b, c], {"CVE-2026-0001"}, info, {"CVE-2026-0001": (0.4, 0.99), "CVE-2026-0002": (0.01, 0.5)},
             exploits={"CVE-2024-4577": {"edb": 52047}})
    assert a["explotada"] and a["kev"] == ["CVE-2026-0001"], "explotada porque su CVE está en KEV"
    assert a["critica"] and a["cvss_max"] == 9.8 and a["epss_max"] == 0.4
    assert a["exploit_publico"] and a["exploitdb"] == 52704
    assert not b["explotada"] and b["critica"], "crítico porque lo dice el título"
    assert not b["exploit_publico"], "una PoC de GitHub no es un exploit público verificado"
    assert c["exploit_publico"] and c["exploitdb"] == 52047, "CVE antiguo (fuera de la semana) con exploit en Exploit-DB"


def test_mas_citados_cuenta_fuentes_distintas():
    avs = [guardado(fuente="siemens", enlace=f"https://cert-portal.siemens.com/{i}", cves=["CVE-2026-0009"])
           for i in range(3)]
    avs += [guardado(fuente="incibe", cves=["CVE-2026-0001"]), guardado(fuente="cisa", enlace="https://cisa.gov/1",
                                                                        cves=["CVE-2026-0001"])]
    citados = A.mas_citados(A.citas_por_cve(avs), {"CVE-2026-0001"}, {}, {})
    assert [c["cve"] for c in citados] == ["CVE-2026-0001"], "tres avisos de Siemens son una sola fuente"
    assert citados[0]["fuentes"] == ["cisa", "incibe"] and citados[0]["kev"]


def test_construir_sigue_si_cae_una_fuente_y_anota_la_tabla_de_cve(monkeypatch):
    feeds = {
        "incibe": rss(("Múltiples vulnerabilidades en WatchGuard", "https://www.incibe.es/watchguard",
                       AHORA - timedelta(hours=3), "CVE-2026-1500")),
        "chrome": ATOM,
    }

    def descargar(url):
        fuente = next(f["id"] for f in A.FUENTES if f["url"] == url)
        if fuente not in feeds:
            raise A.requests.ConnectionError("403")
        return feeds[fuente]

    monkeypatch.setattr(A, "descargar", descargar)
    vulns = {"cves": [{"cve": "CVE-2026-1500", "cvss": 9.1, "epss": 0.2, "epss_percentil": 0.95},
                      {"cve": "CVE-2026-0404", "cvss": 5.0}]}
    pedidos = []

    def epss_fn(ids):
        pedidos.extend(ids)
        return {"CVE-2026-118306": (0.05, 0.9)}

    out = A.construir(dias=7, kev_cat=[{"cveID": "CVE-2026-118306"}], vulns=vulns,
                      previos=[guardado(fuente="cisa", enlace="https://www.cisa.gov/viejo")], epss_fn=epss_fn)
    estado = {f["id"]: f["estado"] for f in out["fuentes"]}
    assert estado["incibe"] == "ok" and estado["chrome"] == "ok" and estado["cisa"] == "error"
    assert [a["fuente"] for a in out["avisos"]] == ["incibe", "chrome", "cisa"], "lo de CISA de antes se mantiene"
    assert set(pedidos) == {"CVE-2026-118306", "CVE-2026-0001"}, "EPSS solo de los CVE que no traía la semana"
    incibe, chrome, _ = out["avisos"]
    assert incibe["critica"] and incibe["cvss_max"] == 9.1 and not incibe["explotada"]
    assert chrome["explotada"] and chrome["kev"] == ["CVE-2026-118306"] and chrome["epss_max"] == 0.05
    r = out["resumen"]
    assert r["avisos"] == 3 and r["explotados"] == 1 and r["fuentes_ok"] == 2 and r["fuentes_total"] == len(A.FUENTES)

    A.anotar(vulns, out)
    assert vulns["cves"][0]["avisos"] == [{"fuente": "incibe", "nombre": "INCIBE-CERT",
                                           "enlace": "https://www.incibe.es/watchguard"}]
    assert vulns["cves"][0]["avisos_total"] == 1 and vulns["cves"][1]["avisos"] == []


def test_las_fuentes_estan_bien_definidas():
    ids = [f["id"] for f in A.FUENTES]
    assert len(ids) == len(set(ids))
    for f in A.FUENTES:
        assert f["tipo"] in A.TIPOS and f["filtro"] in ("todo", "vuln", "cve") and f["url"].startswith("https://")
