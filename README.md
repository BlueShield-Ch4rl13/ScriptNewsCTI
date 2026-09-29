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
**Última actualización:** 2026-09-29 12:42 UTC · **IOCs recolectados:** 871 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | media | `2beb79fc1bd0d64f6e582ebd4326cec4689e32e07e4ca63563d8e0d4a70990eb` | sha256_hash | VShell | ThreatFox | 2026-09-28 12:51:08 UTC |
| 72 (alta) | media | `7d99a996c6a1e5d1295b6fc9cc4958d5501ea32700f39b5f3787fe38dd89757a` | sha256_hash | VShell | ThreatFox | 2026-09-29 12:10:46 UTC |
| 72 (alta) | alta | `176[.]65[.]148[.]49:45` | ip:port | Mirai | ThreatFox | 2026-09-28 18:39:13 UTC |
| 70 (alta) | alta | `941efe52eb858311653bf2c1e855555cf735896d500f11ea90aaf7e93d1faa3f` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:38 UTC |
| 70 (alta) | media | `5b9c569ed427882d17d347ed511ce60e1a20f5876609e14eba6e44423ccc33d9` | sha256_hash | Bashlite | ThreatFox | 2026-09-29 12:10:38 UTC |
| 70 (alta) | alta | `0bbece3dc42199a2cc3db4e7685e5e6078084203e51e9ef6df657038cf79b306` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:30 UTC |
| 70 (alta) | media | `ab1ae861b41f856ad304e965385d44eb4286e385943b83dda6f47e419c63071c` | sha256_hash | VShell | ThreatFox | 2026-09-29 06:28:04 UTC |
| 69 (media) | alta | `d1d398c1a8e4822fca6fa00e0cb60e8360884d59a8a64fcde24d4027d6d39d08` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:51 UTC |
| 69 (media) | media | `hxxps://pevrix[.]com/curl/42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a` | url | MacSync | ThreatFox, URLhaus | 2026-09-29 12:10:47 UTC |
| 69 (media) | alta | `e759a73f9d73a6c2d72b537a31294fcbc78fcc36139ad7c97597aac8568f07ae` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:32 UTC |
| 69 (media) | alta | `93d8b8ecae2f71494ff55c642236a8cf29b1bef976631ec64345b7dde0fede69` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:32 UTC |
| 69 (media) | alta | `0116035ec7b3089b35231c75dc558547337e99bb99319c52241905a2c968f341` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:31 UTC |
| 69 (media) | alta | `0aa485506ebf9f1fb8c3931f0834875f1284776e86ef6d7d34e381df68f1d9dd` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:31 UTC |
| 69 (media) | alta | `9ea665fe5d5d4c705d31d81918bccdec8038257fa316aaa10a97995c0e4d2c99` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:30 UTC |
| 69 (media) | alta | `73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:30 UTC |
| 69 (media) | alta | `3a2b62a3794370f1b0a4d714356e2ff44610c30ac464c43ad1fb3ca4d687a419` | sha256_hash | Mirai | ThreatFox | 2026-09-28 12:51:08 UTC |
| 69 (media) | alta | `db5ebbdf9f17e0c98a24e8f7055aa160e3dd57518b1db99b8e2056b2605a64d2` | sha256_hash | Mirai | ThreatFox | 2026-09-28 12:51:07 UTC |
| 69 (media) | media | `9cca3b4a8fe06e29d4683b448dac14be142eb3b14ed7a5b5ccf8bcf37ce80318` | sha256_hash | Bashlite | ThreatFox | 2026-09-28 12:51:07 UTC |
| 68 (media) | alta | `ce09b63cd78f45022473b9c401c067096436b025d427cd8251e9e9c7d2b59630` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:52 UTC |
| 68 (media) | alta | `3bc182cd50a25ea6c9adceb7f327c11ddbe18c28cf87a7f40c56a1562bea91ea` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:52 UTC |
| 68 (media) | alta | `99c8a5433fb68c939767326a94cd385167a75071c65e2bc90f1dfcdf0c179ea5` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:51 UTC |
| 68 (media) | alta | `b0abdcf8f5a17770dc6f0198a7c551fa9181765af4cc03ead04220377623ef2f` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:46 UTC |
| 68 (media) | alta | `457ea8168a4e0f86b0b29237350d31ab744bd7bf3c923ca83a3f0676bb55f199` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:44 UTC |
| 68 (media) | alta | `2fa86f74d22e3a1cd5db46b8528030b5660f3386f0ae9807a921273092db3ace` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:43 UTC |
| 68 (media) | alta | `38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:39 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-88772 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-88771 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-67279 | MikroTik RouterOS | 2026-09-25 | Unknown |
| CVE-2026-65660 | Microsoft SharePoint | 2026-09-25 | Unknown |
| CVE-2026-87902 | WordPress Core | 2026-09-25 | Unknown |
| CVE-2026-5430 | WSO2 Multiple Products | 2026-09-24 | Unknown |
| CVE-2026-71362 | Adobe Commerce and Magento  | 2026-09-24 | Unknown |
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
<!-- CTI:END -->
