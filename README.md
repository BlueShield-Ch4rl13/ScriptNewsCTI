# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Plataforma ligera de **Cyber Threat Intelligence** que se actualiza sola cada 6 horas mediante GitHub Actions. Recolecta IOCs de feeds públicos, los **fusiona entre fuentes**, los enriquece (GeoIP, VirusTotal, AbuseIPDB), calcula un **score de confianza** y una **gravedad** por indicador, y publica los resultados en un dashboard estático, en este README y en `data/` (JSON + CSV).

🌐 **Dashboard en vivo:** https://cti.carlosvillalbalagos.com

> ⚠️ Uso exclusivamente defensivo (TLP:CLEAR). Los IOCs se muestran defangueados.

## Fuentes

| Feed | Datos | API key |
|---|---|---|
| ThreatFox (abuse.ch) | IOCs de malware (IP, dominios, URLs, hashes) | Gratuita, obligatoria |
| URLhaus (abuse.ch) | URLs de distribución de malware | Gratuita, obligatoria |
| AlienVault OTX | Indicadores de pulses suscritos | Gratuita, opcional |
| CISA KEV | CVEs explotados activamente | No requiere |
| VirusTotal | Reputación de hashes, dominios, URLs e IPs | Gratuita, opcional |
| AbuseIPDB | Reputación, país e ISP de IPs | Gratuita, opcional |
| DB-IP Country Lite | GeoIP offline para todas las IPs | No requiere |

## Arquitectura

```
feeds públicos ──> collectors.py ──> fusión multi-fuente (enrich.py)
                                             │
                            estado histórico (data/ioc_state.json)
                                             │
              enriquecimiento: GeoIP · VirusTotal · AbuseIPDB (caché + presupuesto)
                                             │
                              score de confianza + gravedad
                                             │
GitHub Actions (cron 6h) <── main.py ──> data/*.json|csv + README + dashboard
```

El frontend no realiza ninguna llamada externa: todo el enriquecimiento ocurre en el backend del pipeline y el dashboard solo lee `data/iocs_latest.json`.

## Score de confianza

Cada IOC recibe un score de 0 a 100 combinando señales del propio feed y validación externa, con decaimiento por antigüedad:

| Señal | Aporte |
|---|---|
| Fuente base | ThreatFox / URLhaus 40 · OTX 25 (se toma el máximo) |
| Multi-fuente | +10 por cada fuente adicional (máx. +20) |
| Confianza del feed | `confidence` × 0,15 (hasta +15) |
| AbuseIPDB | `abuseConfidenceScore` × 0,20 (hasta +20) |
| VirusTotal | ratio de detecciones × 25 (hasta +25) |


Niveles: **alta** ≥70 · **media** 40–69 · **baja** <40.

## Gravedad

Dimensión independiente del score: el score mide *cuánto fiarse del indicador*; la gravedad, *el impacto de la amenaza si es real*. Un IOC puede ser score bajo + gravedad crítica (mención única y antigua de LockBit) o score alto + gravedad media (URL de payload confirmadísima).

| Gravedad | Criterio |
|---|---|
| **crítica** | ransomware (LockBit, Akira, RansomHub…) y frameworks C2 (Cobalt Strike, Sliver, Havoc, AdaptixC2…) |
| **alta** | RATs, stealers, loaders y botnets — familias conocidas o categoría genérica en el nombre («X Stealer», «Unknown RAT»…) |
| **media** | resto de amenazas identificadas, o desconocidas con ratio de detecciones VT ≥ 0,3 |
| **baja** | sin familia identificada ni señal externa |

Las listas viven en `SEV_CRITICA` / `SEV_ALTA` / `SEV_ALTA_GENERICAS` de `enrich.py` y se amplían según aparecen familias nuevas en los feeds.

## Enriquecimiento externo y límites

- **GeoIP**: base [DB-IP Country Lite](https://db-ip.com) (CC BY 4.0), sin registro ni clave. Se descarga bajo demanda (~10 MB) al directorio temporal del runner y los lookups son offline: sin límites, cubre todas las IPs.
- **VirusTotal** (4 req/min · 500/día en plan gratuito): 40 lookups por ejecución con pausa de 15,5 s.
- **AbuseIPDB** (1.000 checks/día): 150 IPs por ejecución.
- Los resultados se **cachean 7 días** en `data/ioc_state.json` y siempre se prioriza lo nuevo. Sin claves, el pipeline sigue funcionando con fusión + confianza del feed + frescura + gravedad + GeoIP.

Ajustable vía variables de entorno en el workflow: `VT_BUDGET`, `ABUSEIPDB_BUDGET`, `CTI_RECHECK_DAYS`, `CTI_RETENTION_DAYS`, `CTI_MAX_STATE`.

## Puesta en marcha

1. Crea un repo en GitHub y sube este contenido.
2. Consigue las claves gratuitas:
   - **abuse.ch**: regístrate en https://auth.abuse.ch y genera tu *Auth-Key* (sirve para ThreatFox y URLhaus).
   - **OTX** (opcional): crea cuenta en https://otx.alienvault.com y copia tu API key del perfil.
   - **VirusTotal** (opcional): cuenta en https://virustotal.com → tu perfil → *API key*.
   - **AbuseIPDB** (opcional): cuenta en https://abuseipdb.com → *Account → API*.
3. En el repo: *Settings → Secrets and variables → Actions → New repository secret*:
   - `ABUSECH_API_KEY`
   - `OTX_API_KEY` (opcional)
   - `VT_API_KEY` (opcional)
   - `ABUSEIPDB_API_KEY` (opcional)
4. Pestaña **Actions** → workflow *CTI Update* → **Run workflow** para la primera ejecución manual.
5. Listo: el cron lo ejecutará cada 6 h (hora UTC) y el bot hará commit de los cambios.

### Ejecución local

```bash
pip install -r requirements.txt
export ABUSECH_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"          # opcional
export VT_API_KEY="tu_clave"           # opcional
export ABUSEIPDB_API_KEY="tu_clave"    # opcional
python main.py
```

## Estructura

```
├── .github/workflows/cti-update.yml   # cron + auto-commit (concurrency + rebase anti-carreras)
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── enrich.py                          # fusión, estado histórico, GeoIP, reputación, score y gravedad
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
└── data/                              # iocs_latest.json / .csv + ioc_state.json (estado)
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-09-21 22:03 UTC · **IOCs recolectados:** 1060 · **CVEs KEV recientes:** 22

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `221[.]236[.]125[.]241:8081` | ip:port | Unknown malware | ThreatFox | 2026-09-21 21:05:08 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:80` | ip:port | Unknown malware | ThreatFox | 2026-09-21 21:05:06 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:8080` | ip:port | Unknown malware | ThreatFox | 2026-09-21 21:05:06 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:5900` | ip:port | Unknown malware | ThreatFox | 2026-09-21 21:05:05 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:443` | ip:port | Unknown malware | ThreatFox | 2026-09-21 21:05:05 UTC |
| 73 (alta) | media | `165[.]154[.]227[.]8:22` | ip:port | XMRIG | ThreatFox | 2026-09-21 07:10:53 UTC |
| 73 (alta) | media | `165[.]154[.]162[.]74:22` | ip:port | XMRIG | ThreatFox | 2026-09-21 07:10:53 UTC |
| 73 (alta) | media | `106[.]12[.]70[.]210:8829` | ip:port | Payload  | ThreatFox | 2026-09-21 07:10:52 UTC |
| 72 (alta) | alta | `176[.]65[.]139[.]206:3778` | ip:port | Mirai | ThreatFox | 2026-09-21 09:19:39 UTC |
| 72 (alta) | media | `95[.]220[.]193[.]183:22` | ip:port | Payload  | ThreatFox | 2026-09-21 07:10:52 UTC |
| 72 (alta) | media | `79[.]36[.]29[.]167:22` | ip:port | Payload  | ThreatFox | 2026-09-21 07:10:52 UTC |
| 72 (alta) | critica | `81[.]70[.]21[.]163:8443` | ip:port | Cobalt Strike | ThreatFox | 2026-09-21 00:05:05 UTC |
| 71 (alta) | alta | `46[.]151[.]182[.]67:56002` | ip:port | PureRAT | ThreatFox | 2026-09-21 19:46:27 UTC |
| 71 (alta) | media | `45[.]198[.]224[.]184:80` | ip:port | Tsunami | ThreatFox | 2026-09-21 07:10:37 UTC |
| 70 (alta) | alta | `89ab7c1ae6dc1958d16133f4fd95caa9bcdbfbbdf785fdff7b79f45595d11522` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:37:04 UTC |
| 70 (alta) | alta | `4e278ef31f83894d66424e155d10b698be8806bc8a5d92e6688e65f34c870b26` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:37:02 UTC |
| 70 (alta) | alta | `e792ab78675a7d11daad2bed3b1cbca2eff9c32390d0a9f64d989c36b5d96476` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:37:01 UTC |
| 70 (alta) | alta | `b1f1b197882e2b6547bd2bea358bf949a12724fb024bbe8899e912e066ce2e16` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:36:57 UTC |
| 70 (alta) | alta | `d1c8c16dbf50b833a39469cbc48227605689c570af871b4be25a80fb08e3ba72` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:36:57 UTC |
| 70 (alta) | alta | `d291584f990425964b057e62a4eeba5b383153959ac8257e7a66a5cadc077f64` | sha256_hash | Mirai | ThreatFox | 2026-09-21 02:44:08 UTC |
| 70 (alta) | alta | `de5e52a010cb1a88b64c410dda44d56d03cfed8aded705cbb3b305ee7b9245a8` | sha256_hash | Mirai | ThreatFox | 2026-09-21 02:43:59 UTC |
| 69 (media) | alta | `149[.]56[.]206[.]68:80` | ip:port | Mirai | ThreatFox | 2026-09-21 19:43:47 UTC |
| 69 (media) | alta | `188[.]166[.]158[.]18:8080` | ip:port | Aisuru | ThreatFox | 2026-09-21 11:29:16 UTC |
| 69 (media) | alta | `82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:37:05 UTC |
| 69 (media) | alta | `2ab69a4ccb50354c271b887c951c7628ec8183c478462dd816acffa316e21313` | sha256_hash | Mirai | ThreatFox | 2026-09-21 03:37:03 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-7273 | Zyxel GS1900 Series Switches | 2026-09-21 | Unknown |
| CVE-2025-39964 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-53266 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2025-39682 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-58704 | Google Pixel | 2026-09-16 | Unknown |
| CVE-2026-76460 | Cisco Identity Services Engine | 2026-09-16 | Unknown |
| CVE-2026-87886 | Acronis Backup | 2026-09-16 | Unknown |
| CVE-2026-76461 | Cisco Secure Email Gateway | 2026-09-14 | Unknown |
| CVE-2026-84869 | ConnectWise ScreenConnect | 2026-09-11 | Unknown |
| CVE-2026-42016 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-42018 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition | 2026-09-11 | Unknown |
| CVE-2026-86060 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-67277 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-19490 | Citrix NetScaler | 2026-09-09 | Unknown |
| CVE-2025-25249 | Fortinet Multiple Products | 2026-09-09 | Unknown |
| CVE-2026-87491 | Google Chromium V8 | 2026-09-09 | Unknown |
| CVE-2026-20079 | Cisco Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management | 2026-09-09 | Unknown |
| CVE-2026-75650 | Adobe Commerce and Magento | 2026-09-08 | Unknown |
| CVE-2026-81963 | Microsoft Windows | 2026-09-08 | Unknown |
| CVE-2026-86218 | N-able N-central | 2026-09-08 | Unknown |
| CVE-2026-85880 | Microsoft Windows | 2026-09-08 | Unknown |
<!-- CTI:END -->
