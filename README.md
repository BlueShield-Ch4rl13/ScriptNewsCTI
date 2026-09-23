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
**Última actualización:** 2026-09-23 04:25 UTC · **IOCs recolectados:** 1588 · **CVEs KEV recientes:** 22

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | critica | `81[.]70[.]21[.]163:8899` | ip:port | Cobalt Strike | ThreatFox | 2026-09-23 04:05:19 UTC |
| 72 (alta) | critica | `81[.]70[.]21[.]163:389` | ip:port | Cobalt Strike | ThreatFox | 2026-09-22 20:05:08 UTC |
| 72 (alta) | critica | `81[.]70[.]21[.]163:8888` | ip:port | Cobalt Strike | ThreatFox | 2026-09-22 19:05:06 UTC |
| 71 (alta) | media | `80[.]87[.]206[.]86:18082` | ip:port | Unknown malware | ThreatFox | 2026-09-22 17:57:26 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]12:33` | ip:port | Mirai | ThreatFox | 2026-09-22 05:29:45 UTC |
| 70 (alta) | alta | `9017f68b9ef0c1f5954e3b50c1984d88e1e49449f1b7afd220b6931fecfe0430` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:24 UTC |
| 70 (alta) | alta | `4deefc89b2046999f1a6ea578950dab891579dfa5032b6d1d534f88aa000b7e5` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:58:02 UTC |
| 69 (media) | alta | `5e6582e44fa8f5f671f8ed5c83e9c20f91c8ef1a44cbaef06e9c1f65c890d6ff` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:25 UTC |
| 69 (media) | alta | `fd66a2fe2fe980c283d6efe8209d075a4f0bc1e4c684757c58f12b1ad7189550` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:25 UTC |
| 69 (media) | alta | `cb7e46569d44d677abacb2e7725f585a92d026b75136d3c912b6edeaf4a7bc42` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:23 UTC |
| 69 (media) | alta | `b144e93c2a241f85346f7f2ed54c61d43d3d054e34383452bc94e4ae96dafccf` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:21 UTC |
| 69 (media) | media | `8c17745d754c000fc2bf4aed9ed42aa414cd11c473c2fc8d3c72c6593ea2f371` | sha256_hash | Bashlite | ThreatFox | 2026-09-23 03:37:20 UTC |
| 69 (media) | alta | `2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:19 UTC |
| 69 (media) | alta | `504cb139bbc3d10dc2febee86d854db2b59c5aa55c6a5c49619dea4d37e1fc11` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:18 UTC |
| 69 (media) | alta | `0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:17 UTC |
| 69 (media) | alta | `bb08fd9ce1f3508bc30a33646aeb66df3024e5c7da843cabd09ed19ae07bd8d1` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:16 UTC |
| 69 (media) | alta | `1b9afb8283c6396129ffd23aa89cc0321b7a12e995eaf0f98d4d478afb84e2ce` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:15 UTC |
| 69 (media) | alta | `dcda5ec54ae2a736249894992a6cab2c5cfe65acd07c9e59c92d86fbd0564ce4` | sha256_hash | Mirai | ThreatFox | 2026-09-23 03:37:14 UTC |
| 69 (media) | alta | `526e532170acbc980bf41c48d1886b592a871c852d5ea86f98db4296bbbe85b6` | sha256_hash | KrBanker | ThreatFox | 2026-09-22 04:58:01 UTC |
| 69 (media) | media | `586960df8bf559ffbba600f11917a99baed4a875cb7faa5eabc060bcde67277b` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:58 UTC |
| 69 (media) | alta | `bcfbd1d0c98844ddd4795a6df4e6431a494a0320c72413f188b50140cd30f506` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:58 UTC |
| 69 (media) | media | `97eaa49999cbcc866fc30ca2ba20f2a1d4e9b01d1c824d3924a185683d2b87c5` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:57 UTC |
| 69 (media) | media | `7aac36e30a811f7463cfb882ee6ff76834a60428c436b0b3fa15ff8f94b8db51` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:57 UTC |
| 69 (media) | media | `f407f10ce043dce0f4a8aeed21912f20f21f613ec0fe495394451097dc8ced0b` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:55 UTC |
| 69 (media) | media | `3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:54 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-93952 | Arista VeloCloud Orchestrator | 2026-09-22 | Unknown |
| CVE-2026-94127 | F5 BIG-IP APM | 2026-09-22 | Unknown |
| CVE-2026-93616 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-85102 | Check Point Multiple Products | 2026-09-22 | Unknown |
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
<!-- CTI:END -->
