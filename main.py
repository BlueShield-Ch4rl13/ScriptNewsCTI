"""Orquestador: recolecta feeds, fusiona fuentes, enriquece con scoring y publica."""
import logging

from collectors import cisa_kev, otx_pulses, threatfox, urlhaus
from enrich import enrich, merge_sources
from utils import save_outputs, save_vulns, update_readme
from vulnerabilidades import construir, kev_catalogo

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cti")


def main() -> None:
    iocs = []
    iocs += threatfox(days=1)
    iocs += urlhaus(limit=100)
    iocs += otx_pulses(limit=10)
    iocs = merge_sources(iocs)

    try:
        kev_cat = kev_catalogo()
    except Exception as exc:
        log.error("CISA KEV falló: %s", exc)
        kev_cat = None
    kev = cisa_kev(days=14, catalogo=kev_cat)

    iocs = enrich(iocs)

    # Vulnerabilidades: CVE de la última semana priorizados (KEV, EPSS, CVSS, SSVC),
    # lenguajes (paquetes maliciosos y avisos) y sistemas. Va aparte de los IOCs:
    # si alguna de sus fuentes cae, los IOCs se publican igual.
    vulns = construir(dias=7, kev_cat=kev_cat)

    log.info("Total publicado: %d IOCs · %d CVEs KEV · %d CVE nuevos", len(iocs), len(kev),
             vulns["resumen"]["cves"])
    save_outputs(iocs, kev)
    save_vulns(vulns)
    update_readme(iocs, kev, vulns)


if __name__ == "__main__":
    main()
