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
**Última actualización:** 2026-09-24 04:20 UTC · **IOCs recolectados:** 3321 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | alta | `178[.]16[.]54[.]35:8848` | ip:port | DCRat | ThreatFox | 2026-09-23 09:44:20 UTC |
| 73 (alta) | critica | `81[.]70[.]21[.]163:18080` | ip:port | Cobalt Strike | ThreatFox | 2026-09-23 20:05:09 UTC |
| 71 (alta) | critica | `81[.]70[.]21[.]163:5985` | ip:port | Cobalt Strike | ThreatFox | 2026-09-23 13:05:06 UTC |
| 71 (alta) | alta | `156[.]225[.]17[.]60:113` | ip:port | Ghost RAT | ThreatFox | 2026-09-23 08:22:50 UTC |
| 71 (alta) | alta | `156[.]225[.]17[.]60:2014` | ip:port | Ghost RAT | ThreatFox | 2026-09-23 08:22:50 UTC |
| 71 (alta) | critica | `81[.]70[.]21[.]163:8012` | ip:port | Cobalt Strike | ThreatFox | 2026-09-23 07:05:05 UTC |
| 70 (alta) | alta | `0de0aa09779fc1dc5339d362dcfc40453a0b8747d52913487088f54b45798af9` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:35 UTC |
| 70 (alta) | alta | `02040009ebcecfee14b8ab21e737d154a7bf8c89641b4b8d54733ee82a8d80db` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:34 UTC |
| 70 (alta) | alta | `cd226b634e8dcefbf72f2465a922a9f33f235fa8fafa0d41bd1206bb56b5d475` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:33 UTC |
| 70 (alta) | alta | `718d1345ec4633350c6f36e892b372d433dc66bd4befaa2139e0e70afe04bd88` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:30 UTC |
| 70 (alta) | alta | `9017f68b9ef0c1f5954e3b50c1984d88e1e49449f1b7afd220b6931fecfe0430` | sha256_hash | Mirai | ThreatFox | 2026-09-23 06:34:15 UTC |
| 69 (media) | media | `ccb05e8e1b680a6766c9cfffe71e5543f0b9b0432d2ea10d8f4661188ec5b951` | sha256_hash | Meterpreter | ThreatFox | 2026-09-24 03:37:31 UTC |
| 69 (media) | alta | `517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:29 UTC |
| 69 (media) | media | `a7682d1edc81925c3d7d2738db2283c742144d8321cfaf1888cdb66c1cd6ae83` | sha256_hash | Tsunami | ThreatFox | 2026-09-24 03:37:28 UTC |
| 69 (media) | alta | `5411d557b2ad40f6b0b3ce68662897a98e54b4fc845a9c17dd9a347b43ee9388` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:27 UTC |
| 69 (media) | alta | `5eee93f3d069efa6afab084ffc59d2df4b1d9eafe33c379d6c094c065bc44a67` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:26 UTC |
| 69 (media) | alta | `52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:25 UTC |
| 69 (media) | alta | `e8309eb806c81ecdb99c121da6a85e44e66b6f1858fcb7bcf7eb1892decaf107` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:24 UTC |
| 69 (media) | alta | `b88cb5aa2aed19216d269e7cd08348ab1e1017af6a9a8e39375715d0c0705a89` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:22 UTC |
| 69 (media) | alta | `6cdc6333fb83f8dd8e4d86498122ff1845fdc0da46f616ed0e51a140f8d6eed9` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:21 UTC |
| 69 (media) | alta | `6538f85f76b7fa8fd43ffec779f02a58b89e42b34af45d630af387a78b2a2616` | sha256_hash | Mirai | ThreatFox | 2026-09-24 03:37:20 UTC |
| 69 (media) | alta | `dcda5ec54ae2a736249894992a6cab2c5cfe65acd07c9e59c92d86fbd0564ce4` | sha256_hash | Mirai | ThreatFox | 2026-09-23 06:34:24 UTC |
| 69 (media) | alta | `0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1` | sha256_hash | Mirai | ThreatFox | 2026-09-23 06:34:24 UTC |
| 69 (media) | alta | `1b9afb8283c6396129ffd23aa89cc0321b7a12e995eaf0f98d4d478afb84e2ce` | sha256_hash | Mirai | ThreatFox | 2026-09-23 06:34:23 UTC |
| 69 (media) | alta | `bb08fd9ce1f3508bc30a33646aeb66df3024e5c7da843cabd09ed19ae07bd8d1` | sha256_hash | Mirai | ThreatFox | 2026-09-23 06:34:22 UTC |

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
<!-- CTI:END -->
