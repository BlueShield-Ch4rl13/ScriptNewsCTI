"""README y CSV: lo que llega de un feed no puede cambiar el README ni ejecutarse en una hoja."""
from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import utils  # noqa: E402


def test_md_no_deja_meter_imagenes_html_ni_romper_la_tabla():
    malo = "Ransom|ware\n![x](https://t.example/p.png) <img src=x onerror=y> [enlace](https://e.example) `c`"
    fuera = utils._md(malo)
    assert "\n" not in fuera and "<img" not in fuera
    assert "![" not in fuera and "](" not in fuera.replace("\\](", "")
    assert "\\|" in fuera and "|" not in fuera.replace("\\|", "")
    assert utils._md(None) == "" and utils._md(9.8) == "9.8" and utils._md("2026-11-05") == "2026-11-05"


def test_md_codigo_no_sale_del_bloque():
    assert utils._md_codigo("evil[.]com`<b>|x\ny") == "evil[.]com'<b>\\|x y"


def test_md_url_solo_http():
    assert utils._md_url("https://a.example/x(1)") == "https://a.example/x%281%29"
    for u in ("javascript:alert(1)", "data:text/html,x", "https://a.example/x y", "", None, "//a.example"):
        assert utils._md_url(u) == ""


def test_readme_con_avisos_maliciosos(tmp_path, monkeypatch):
    readme = tmp_path / "README.md"
    readme.write_text("antes\n<!-- CTI:START -->\nviejo\n<!-- CTI:END -->\ndespues\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    avisos = {"avisos": [{"titulo": "Fallo\n| inyectado | ![p](https://t.example/p.png)", "fecha": "2026-11-05T00:00:00Z",
                          "fuente": "x", "enlace": "javascript:alert(1)", "explotada": True}]}
    iocs = [{"value": "evil.com`|x", "type": "domain", "threat": "<script>", "source": "OTX",
             "score": 90, "level": "alta", "severity": "alta", "first_seen": "2026-11-05"}]
    utils.update_readme(iocs, [], avisos=avisos)
    texto = readme.read_text(encoding="utf-8")
    bloque = texto.split("<!-- CTI:START -->")[1].split("<!-- CTI:END -->")[0]
    assert "<script>" not in bloque and "javascript:" not in bloque and "![p]" not in bloque
    filas = [l for l in bloque.splitlines() if l.startswith("|") and "evil" in l]
    assert filas and all(l.replace("\\|", "").count("|") == 8 for l in filas), filas
    assert texto.startswith("antes") and texto.rstrip().endswith("despues")


def test_csv_sin_formulas(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "DATA_DIR", str(tmp_path))
    iocs = [{"value": "1.2.3.4", "type": "ip", "threat": "=HYPERLINK(\"http://x\",\"y\")", "source": "+cmd",
             "reference": "@SUM(1)", "score": -5, "sources": ["-x"]}]
    utils.save_outputs(iocs, [])
    [fila] = list(csv.DictReader(open(tmp_path / "iocs_latest.csv", encoding="utf-8")))
    assert fila["threat"].startswith("'=") and fila["source"] == "'+cmd" and fila["reference"] == "'@SUM(1)"
    assert fila["sources"] == "'-x" and fila["score"] == "-5", "los numeros no se tocan"
