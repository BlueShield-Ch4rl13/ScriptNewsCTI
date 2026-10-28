"""Utilidades: defang, exportación y README autogenerado."""
import csv
import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DATA_DIR = "data"
README_PATH = "README.md"
MARK_START = "<!-- CTI:START -->"
MARK_END = "<!-- CTI:END -->"


def defang(value: str) -> str:
    """Defanguea IPs, dominios y URLs (los hashes no se ven afectados)."""
    if not value:
        return ""
    v = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return v.replace(".", "[.]")


def save_outputs(iocs: list[dict], kev: list[dict]) -> None:
    """Guarda data/iocs_latest.json y data/iocs_latest.csv."""
    os.makedirs(DATA_DIR, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    enriched = [{**i, "defanged": defang(i.get("value", ""))} for i in iocs]
    levels = {"alta": 0, "media": 0, "baja": 0}
    for i in enriched:
        if i.get("level") in levels:
            levels[i["level"]] += 1
    payload = {
        "generated_utc": now,
        "ioc_count": len(enriched),
        "kev_count": len(kev),
        "levels": levels,
        "iocs": enriched,
        "cisa_kev_recent": kev,
    }
    with open(os.path.join(DATA_DIR, "iocs_latest.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    columns = ["score", "level", "severity", "value", "defanged", "type", "threat",
               "sources", "country", "vt_detections", "abuse_score",
               "age_days", "confidence", "first_seen", "source", "reference"]
    with open(os.path.join(DATA_DIR, "iocs_latest.csv"), "w",
              newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {**i, "sources": ", ".join(i.get("sources") or [])} for i in enriched
        )

    log.info("Guardados %d IOCs y %d CVEs en %s/", len(enriched), len(kev), DATA_DIR)


def save_vulns(vulns: dict) -> None:
    """Guarda data/vulns_latest.json (CVE priorizados, lenguajes y sistemas)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "vulns_latest.json"), "w", encoding="utf-8") as f:
        json.dump(vulns, f, indent=1, ensure_ascii=False)
    r = vulns.get("resumen", {})
    log.info("Guardados %d CVE (de %d) y %d lenguajes en %s/vulns_latest.json",
             vulns.get("cves_publicados", 0), r.get("cves", 0), len(vulns.get("lenguajes", [])), DATA_DIR)


def load_previous_avisos() -> list:
    """Avisos publicados en la ejecución anterior (data/avisos_latest.json), para no
    perder los que ya no salen en feeds cortos. avisos.fusionar() los revalida."""
    try:
        with open(os.path.join(DATA_DIR, "avisos_latest.json"), encoding="utf-8") as f:
            datos = json.load(f)
        return datos.get("avisos") or [] if isinstance(datos, dict) else []
    except (OSError, ValueError):
        return []


def save_avisos(avisos: dict) -> None:
    """Guarda data/avisos_latest.json (avisos de fabricantes, CERT, exploits y noticias)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "avisos_latest.json"), "w", encoding="utf-8") as f:
        json.dump(avisos, f, indent=1, ensure_ascii=False)
    r = avisos.get("resumen", {})
    log.info("Guardados %d avisos (%d/%d fuentes) en %s/avisos_latest.json", r.get("avisos", 0),
             r.get("fuentes_ok", 0), r.get("fuentes_total", 0), DATA_DIR)


ESTADO_LENGUAJE = {"runtime_explotado": "🔴 el lenguaje se explota", "maliciosos": "🔴 paquetes maliciosos", "critico": "🟠 avisos críticos",
                   "alto": "🟡 avisos altos", "sin_alertas": "🟢 sin alertas"}
ESTADO_SISTEMA = {"explotacion_activa": "🔴 explotación activa", "riesgo_alto": "🟠 riesgo alto",
                  "vigilar": "🟢 vigilar"}


def _bloque_vulns(vulns: dict, max_rows: int) -> list[str]:
    r = vulns.get("resumen") or {}
    dias = vulns.get("ventana_dias", 7)
    lines = [
        "",
        f"### Vulnerabilidades de los últimos {dias} días",
        "",
        f"**{r.get('cves', 0)}** CVE publicados · **{r.get('explotados', 0)}** ya explotados · "
        f"**{r.get('urgentes', 0)}** urgentes · **{r.get('criticos', 0)}** con CVSS ≥ 9 · "
        f"**{r.get('paquetes_maliciosos', 0)}** paquetes maliciosos en los registros · "
        f"**{r.get('exploit_publico', 0)}** con exploit en Exploit-DB · "
        f"**{r.get('dia_cero', 0)}** explotados desde el primer día",
        "",
        "Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 %"
        " o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB"
        " cuenta como prueba de concepto.",
        "",
        "| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |",
        "|---|---|---|---|---|---|",
    ]
    for c in [c for c in vulns.get("cves", []) if c.get("prioridad") in ("explotada", "urgente", "alta")][:max_rows]:
        e = c.get("epss")
        lines.append(f"| {_md(c.get('prioridad'))} | {_md(c.get('cve'))} | {_md(c.get('fabricante') or '—')} "
                     f"| {_md(c.get('cvss') if c.get('cvss') is not None else '—')} "
                     f"| {_md(f'{e * 100:.1f} %' if e is not None else '—')} | {_md(c.get('publicado'))} |")
    lines += ["", "### Lenguajes (registros de paquetes, últimos "
              f"{dias} días)", "", "| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |",
              "|---|---|---|---|"]
    for x in vulns.get("lenguajes", []):
        if x.get("error"):
            lines.append(f"| {_md(x['lenguaje'])} ({_md(x['registro'])}) | sin datos | — | — |")
            continue
        mas = "+" if x.get("maliciosos_mas") else ""
        lines.append(f"| {_md(x['lenguaje'])} ({_md(x['registro'])}) | {ESTADO_LENGUAJE.get(x['estado'], x['estado'])} "
                     f"| {x['maliciosos']}{mas} | {x['criticos']} / {x['altos']} |")
    lines += ["", "### Sistemas", "", "| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |",
              "|---|---|---|---|---|"]
    for s_ in vulns.get("sistemas", []):
        lines.append(f"| {_md(s_['nombre'])} | {ESTADO_SISTEMA.get(s_['estado'], s_['estado'])} | {s_['cves']} "
                     f"| {s_['criticos']} | {s_['kev_recientes_total']} |")
    return lines


def _bloque_avisos(avisos: dict, max_rows: int) -> list[str]:
    r = avisos.get("resumen") or {}
    nombres = {f["id"]: f["nombre"] for f in avisos.get("fuentes") or []}
    lines = [
        "",
        f"### Avisos de seguridad de los últimos {avisos.get('ventana_dias', 7)} días",
        "",
        f"**{r.get('avisos', 0)}** avisos de {r.get('fuentes_ok', 0)}/{r.get('fuentes_total', 0)} fuentes "
        f"(fabricantes, CERT, exploits y noticias) · **{r.get('explotados', 0)}** de algo que ya se explota · "
        f"**{r.get('dia_cero', 0)}** de día cero · **{r.get('sin_parche', 0)}** sin parche",
        "",
    ]
    citados = avisos.get("mas_citados") or []
    if citados:
        lines += ["**Lo más citado:** " + " · ".join(
            f"{_md(c['cve'])} ({len(c['fuentes'])} fuentes{', KEV' if c.get('kev') else ''})" for c in citados[:8]), ""]
    lines += ["| Fecha | Fuente | Aviso | Señales |", "|---|---|---|---|"]
    graves = [a for a in avisos.get("avisos") or [] if a.get("explotada") or a.get("dia_cero") or a.get("critica")]
    for a in graves[:max_rows]:
        senales = ", ".join(n for n, k in (("explotada", "explotada"), ("día cero", "dia_cero"),
                                            ("sin parche", "sin_parche"), ("crítica", "critica")) if a.get(k))
        titulo = _md(a["titulo"][:110]).replace("[", "\\[").replace("]", "\\]")
        lines.append(f"| {_md(a['fecha'][:10])} | {_md(nombres.get(a['fuente'], a['fuente']))} "
                     f"| [{titulo}]({_md(a['enlace']).replace('(', '%28').replace(')', '%29')}) | {senales} |")
    return lines


def _md(value) -> str:
    """Escapa pipes para tablas markdown."""
    return str(value if value is not None else "").replace("|", "\\|")


def update_readme(iocs: list[dict], kev: list[dict], vulns: dict | None = None, max_rows: int = 25,
                  avisos: dict | None = None) -> None:
    """Reescribe la sección entre los marcadores CTI:START/END del README."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    lines = [
        f"**Última actualización:** {now} UTC · "
        f"**IOCs recolectados:** {len(iocs)} · "
        f"**CVEs KEV recientes:** {len(kev)}",
        "",
        f"### Últimos IOCs (defangueados, máx. {max_rows})",
        "",
        "| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |",
        "|---|---|---|---|---|---|---|",
    ]
    for i in iocs[:max_rows]:
        lines.append(
            f"| {_md(i.get('score', '—'))} ({_md(i.get('level', '—'))}) "
            f"| {_md(i.get('severity', '—'))} "
            f"| `{_md(defang(i.get('value', '')))}` | {_md(i.get('type'))} "
            f"| {_md(i.get('threat'))} | {_md(i.get('source'))} "
            f"| {_md(i.get('first_seen'))} |"
        )

    lines += [
        "",
        "### CVEs explotados activamente (CISA KEV, últimos 14 días)",
        "",
        "| CVE | Producto | Añadido | Ransomware |",
        "|---|---|---|---|",
    ]
    for v in kev[:max_rows]:
        lines.append(
            f"| {_md(v.get('cve'))} | {_md(v.get('vendor'))} {_md(v.get('product'))} "
            f"| {_md(v.get('date_added'))} | {_md(v.get('ransomware'))} |"
        )

    if avisos:
        lines += _bloque_avisos(avisos, max_rows)
    if vulns:
        lines += _bloque_vulns(vulns, max_rows)

    block = "\n".join(lines)

    try:
        with open(README_PATH, encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        content = f"# CTI Feed Aggregator\n\n{MARK_START}\n{MARK_END}\n"

    if MARK_START in content and MARK_END in content:
        pre, _, rest = content.partition(MARK_START)
        _, _, post = rest.partition(MARK_END)
        content = f"{pre}{MARK_START}\n{block}\n{MARK_END}{post}"
    else:
        content += f"\n{MARK_START}\n{block}\n{MARK_END}\n"

    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    log.info("README actualizado")
