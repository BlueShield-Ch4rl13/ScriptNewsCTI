"""Orquestador: recolecta feeds, normaliza, deduplica y publica resultados."""
import logging

from collectors import cisa_kev, otx_pulses, threatfox, urlhaus
from utils import dedupe, save_outputs, update_readme

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cti")


def main() -> None:
    iocs = []
    iocs += threatfox(days=1)
    iocs += urlhaus(limit=100)
    iocs += otx_pulses(limit=10)
    iocs = dedupe(iocs)

    kev = cisa_kev(days=14)

    log.info("Total tras dedupe: %d IOCs · %d CVEs KEV", len(iocs), len(kev))
    save_outputs(iocs, kev)
    update_readme(iocs, kev)


if __name__ == "__main__":
    main()
