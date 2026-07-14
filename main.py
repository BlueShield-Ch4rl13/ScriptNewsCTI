"""Orquestador: recolecta feeds, fusiona fuentes, enriquece con scoring y publica."""
import logging

from collectors import cisa_kev, otx_pulses, threatfox, urlhaus
from enrich import enrich, merge_sources
from utils import save_outputs, update_readme

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cti")


def main() -> None:
    iocs = []
    iocs += threatfox(days=1)
    iocs += urlhaus(limit=100)
    iocs += otx_pulses(limit=10)
    iocs = merge_sources(iocs)

    kev = cisa_kev(days=14)

    iocs = enrich(iocs)

    log.info("Total publicado: %d IOCs · %d CVEs KEV", len(iocs), len(kev))
    save_outputs(iocs, kev)
    update_readme(iocs, kev)


if __name__ == "__main__":
    main()
