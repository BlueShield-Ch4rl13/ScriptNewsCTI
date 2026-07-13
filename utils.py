"""Utilidades: defang, deduplicado, exportación y README autogenerado."""
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


def dedupe(iocs: list[dict]) -> list[dict]:
    """Elimina duplicados conservando la primera aparición de cada valor."""
    seen, unique = set(), []
    for i in iocs:
        v = i.get("value")
        if v and v not in seen:
            seen.add(v)
            unique.append(i)
    return unique


def save_outputs(iocs: list[dict], kev: list[dict]) -> None:
    """Guarda data/iocs_latest.json y data/iocs_latest.csv."""
    os.makedirs(DATA_DIR, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    enriched = [{**i, "defanged": defang(i.get("value", ""))} for i in iocs]
    payload = {
        "generated_utc": now,
        "ioc_count": len(enriched),
        "kev_count": len(kev),
        "iocs": enriched,
        "cisa_kev_recent": kev,
    }
    with open(os.path.join(DATA_DIR, "iocs_latest.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    columns = ["value", "defanged", "type", "threat", "confidence",
               "first_seen", "source", "reference"]
    with open(os.path.join(DATA_DIR, "iocs_latest.csv"), "w",
              newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(enriched)

    log.info("Guardados %d IOCs y %d CVEs en %s/", len(enriched), len(kev), DATA_DIR)


def _md(value) -> str:
    """Escapa pipes para tablas markdown."""
    return str(value if value is not None else "").replace("|", "\\|")


def update_readme(iocs: list[dict], kev: list[dict], max_rows: int = 25) -> None:
    """Reescribe la sección entre los marcadores CTI:START/END del README."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    lines = [
        f"**Última actualización:** {now} UTC · "
        f"**IOCs recolectados:** {len(iocs)} · "
        f"**CVEs KEV recientes:** {len(kev)}",
        "",
        f"### Últimos IOCs (defangueados, máx. {max_rows})",
        "",
        "| IOC | Tipo | Amenaza | Fuente | Visto |",
        "|---|---|---|---|---|",
    ]
    for i in iocs[:max_rows]:
        lines.append(
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
