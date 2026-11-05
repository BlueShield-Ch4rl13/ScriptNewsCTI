"""El panel publico (index.html y assets/): estructura y reglas de seguridad."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


class Etiquetas(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.estilos, self.ids = [], [], set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self.scripts.append(a.get("src"))
        if "style" in a or tag == "style":
            self.estilos.append(tag)
        if a.get("id"):
            self.ids.add(a["id"])


def _pagina():
    e = Etiquetas()
    e.feed((RAIZ / "index.html").read_text(encoding="utf-8"))
    return e


def test_scripts_propios_en_orden_y_sin_codigo_ni_estilos_en_linea():
    e = _pagina()
    # buscar.js usa lo que publica app.js: va detras
    assert e.scripts == ["assets/app.js", "assets/buscar.js"]
    assert not e.estilos, "la CSP (style-src 'self') bloquearia estilos en linea"


def test_el_buscador_y_las_secciones_existen():
    e = _pagina()
    for i in ("q", "q-resultados", "q-sugerencias", "g-prioridad", "g-dias", "g-sistemas", "g-amenazas",
              "s-avisos", "s-cves", "s-iocs", "f-mas", "sync-time", "stat-avisos", "stat-cves", "stat-iocs"):
        assert i in e.ids, i
    # cada enlace del menu de secciones lleva a una seccion que existe
    html = (RAIZ / "index.html").read_text(encoding="utf-8")
    for destino in re.findall(r'<a href="#(s-[a-z]+)"', html):
        assert destino in e.ids, destino


def test_el_javascript_no_mete_html_de_los_feeds():
    for f in ("app.js", "buscar.js"):
        codigo = (RAIZ / "assets" / f).read_text(encoding="utf-8")
        sin_comentarios = re.sub(r"/\*.*?\*/|//[^\n]*", "", codigo, flags=re.S)
        for prohibido in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert prohibido not in sin_comentarios, f"{f}: {prohibido}"
