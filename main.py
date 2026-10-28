"""Orquestador: recolecta feeds, fusiona fuentes, enriquece con scoring y publica."""
import logging

import avisos
from collectors import cisa_kev, otx_pulses, threatfox, urlhaus
from enrich import enrich, merge_sources
from utils import load_previous_avisos, save_avisos, save_outputs, save_vulns, update_readme
from vulnerabilidades import construir, epss, exploitdb, kev_catalogo

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
    # Exploit-DB se descarga una vez (~10 MB) y sirve para los CVE y para los avisos
    try:
        edb = exploitdb()
    except Exception as exc:
        log.error("Exploit-DB falló: %s", exc)
        edb = {}
    vulns = construir(dias=7, kev_cat=kev_cat, edb=edb)

    # Avisos de fabricantes, CERT, exploits y noticias, cruzados con lo anterior.
    # Si algo falla aquí, se conserva el fichero de la ejecución anterior.
    try:
        avs = avisos.construir(dias=7, kev_cat=kev_cat, vulns=vulns, previos=load_previous_avisos(), epss_fn=epss,
                               exploits=edb)
        avisos.anotar(vulns, avs)
    except Exception as exc:
        log.error("Avisos falló entero: %s", exc)
        avs = None

    log.info("Total publicado: %d IOCs · %d CVEs KEV · %d CVE nuevos · %s avisos", len(iocs), len(kev),
             vulns["resumen"]["cves"], avs["resumen"]["avisos"] if avs else "sin")
    save_outputs(iocs, kev)
    save_vulns(vulns)
    if avs:
        save_avisos(avs)
    update_readme(iocs, kev, vulns, avisos=avs)


if __name__ == "__main__":
    main()
