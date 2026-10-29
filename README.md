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
              estado histórico (data/ioc_state.json, en la caché de Actions)
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
| Frescura | ×1,0 ≤7 días · ×0,85 ≤30 · ×0,6 ≤90 · ×0,3 resto, contando desde el `first_seen` del feed |

Sin claves de VirusTotal ni AbuseIPDB, el score refleja sobre todo la fuente y la confianza que da el propio feed, así que la mayoría de los IOCs quedan en la franja 40-59: la diferencia real la ponen las validaciones externas.

Antes de fusionar, cada indicador se normaliza: `1.2.3.4` y `1.2.3.4:443` cuentan como el mismo (y suman la bonificación multi-fuente), los tipos se unifican (`sha256_hash` y `FileHash-SHA256` → `filehash-sha256`), los CVE salen de la lista de IOCs (van en la lista KEV), los dominios de grandes proveedores (google.com, microsoft.com…) se descartan y los PTR de máquinas de Google Cloud se convierten en su IP.

Niveles: **alta** ≥70 · **media** 40–69 · **baja** <40.

## Gravedad

Dimensión independiente del score: el score mide *cuánto fiarse del indicador*; la gravedad, *el impacto de la amenaza si es real*. Un IOC puede ser score bajo + gravedad crítica (mención única y antigua de LockBit) o score alto + gravedad media (URL de payload confirmadísima).

| Gravedad | Criterio |
|---|---|
| **crítica** | ransomware (LockBit, Akira, RansomHub…) y frameworks C2 (Cobalt Strike, Sliver, Havoc, AdaptixC2…) |
| **alta** | RATs, stealers, loaders y botnets — familias conocidas o categoría genérica como palabra completa en el nombre («X Stealer», «Unknown RAT»…; «Operation» ya no cuenta como «rat») |
| **media** | resto de amenazas identificadas, o desconocidas con ratio de detecciones VT ≥ 0,3 |
| **baja** | sin familia identificada ni señal externa |

Las listas viven en `SEV_CRITICA` / `SEV_ALTA` / `SEV_ALTA_GENERICAS` de `enrich.py` y se amplían según aparecen familias nuevas en los feeds.

En OTX la amenaza sale de las familias de malware del pulse. Si el pulse no tiene ninguna y solo queda su título, la gravedad se limita a **media**: el título describe la campaña, no cada uno de sus indicadores.

## Enriquecimiento externo y límites

- **GeoIP**: base [DB-IP Country Lite](https://db-ip.com) (CC BY 4.0), sin registro ni clave. Se descarga bajo demanda (~10 MB) al directorio temporal del runner y los lookups son offline: sin límites, cubre todas las IPs.
- **VirusTotal** (4 req/min · 500/día en plan gratuito): 40 lookups por ejecución con pausa de 15,5 s.
- **AbuseIPDB** (1.000 checks/día): 150 IPs por ejecución.
- Los resultados se **cachean 7 días** en `data/ioc_state.json`, que vive en la caché de GitHub Actions y no en el repositorio (subirlo en cada ejecución hacía crecer el repo ~100 MB al año). Siempre se prioriza lo nuevo. Sin claves, el pipeline sigue funcionando con fusión + confianza del feed + frescura + gravedad + GeoIP.

Ajustable vía variables de entorno en el workflow: `VT_BUDGET`, `ABUSEIPDB_BUDGET`, `CTI_RECHECK_DAYS`, `CTI_RETENTION_DAYS`, `CTI_MAX_STATE`. `CTI_MAX_STATE` (6.000) es el tope del **estado** interno; lo que se publica en cada ejecución son los IOCs de las últimas 24 h de los feeds, normalmente unos 2.000.

### Seguridad del workflow

- Dos jobs: `generar` ejecuta el pipeline con permisos de solo lectura y sin el token de GitHub en el runner (`persist-credentials: false`); `publicar` solo copia los ficheros generados y hace commit.
- Acciones fijadas por SHA y dependencias instaladas con `--require-hashes` (`requirements.txt` sale de `requirements.in` con `pip-compile --generate-hashes`).

### Licencias de los datos

El código es MIT (`LICENSE`). Los datos republicados tienen sus propias condiciones: abuse.ch (ThreatFox, URLhaus) y CISA KEV permiten la redistribución; DB-IP Country Lite exige atribución (CC BY 4.0); **AlienVault OTX, VirusTotal y AbuseIPDB tienen términos de uso propios que hay que revisar antes de republicar sus resultados** (en particular, el plan gratuito de VirusTotal no permite uso comercial).

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
pip install --require-hashes -r requirements.txt
export ABUSECH_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"          # opcional
export VT_API_KEY="tu_clave"           # opcional
export ABUSEIPDB_API_KEY="tu_clave"    # opcional
python main.py
```

## Estructura

```
├── .github/workflows/cti-update.yml   # cron: generar (solo lectura) + publicar (commit)
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── enrich.py                          # fusión, estado histórico, GeoIP, reputación, score y gravedad
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
├── tests/                             # pruebas de fusión, edad, gravedad y depuración
└── data/                              # iocs_latest.json / .csv (el estado va en la caché de Actions)
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-10-29 05:25 UTC · **IOCs recolectados:** 2351 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | alta | `176[.]65[.]139[.]131:3912` | ip:port | Mirai | ThreatFox | 2026-10-28 06:35:36 UTC |
| 73 (alta) | alta | `5a03d2c82ad633cb72087849e816177d499683ac56acae7bc7ded0ab8cef9991` | filehash-sha256 | Quasar RAT | ThreatFox | 2026-10-28 12:32:09 UTC |
| 68 (media) | alta | `157[.]66[.]225[.]224:8808` | ip:port | AsyncRAT | ThreatFox | 2026-10-28 07:21:31 UTC |
| 63 (media) | alta | `177c91e9bb65953c3e45efc08550bd3e2c739b4d793d26914b833ac88ae03268` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 11:55:47 UTC |
| 61 (media) | alta | `22fb4197c22e1caa7b17b727bd9daec786e43ad8564b07c29a1e7ff87158a52f` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:07 UTC |
| 61 (media) | alta | `5da5a63da101d3890766c0a4d603078282cb4cb540f9d8af1e931da02d4b5b3c` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:06 UTC |
| 61 (media) | alta | `f3c774928f70f5c925cee89372bd178e45340e72e980f17f4b320628f012404c` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:05 UTC |
| 61 (media) | alta | `5f3ebb3a003a6de99681f12da237bacdcf1e795bb5803310dad72787ac313d2a` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:05 UTC |
| 61 (media) | alta | `0c51bd1ff27adb40196e0d0f573c9466f2f84df59414b5faa00d5d5dfbfc1b85` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:03 UTC |
| 61 (media) | alta | `04bb54b68600cdb6e6949cdcdfa54284ec629dc1cff910bed7b3c663fdc9a7a6` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:03 UTC |
| 61 (media) | alta | `7103dd5f95bdbb985cdf9692e97c5c0322860746ade53e3f847856e6c814e08f` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:02 UTC |
| 60 (media) | alta | `7afd90ad598cd6f23015cd9552ed7de77f0854be874215629823615b0e1164f8` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:04 UTC |
| 60 (media) | alta | `6d92fed31dda9dc02d52ce1c3c32403f0e29b4556d39e3ff15b8a811d7c2ce3e` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:03 UTC |
| 60 (media) | alta | `3343bc0e390fd74b53966ea235970de4fcb3bfc9166fdc9d1843fbddce5c359d` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:02 UTC |
| 60 (media) | alta | `1b387e71de84b6e3645d14282f80732b97c61999bfc1cbbd78b146b9c40c80c2` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:02 UTC |
| 60 (media) | alta | `e4c06ccb0fbba7ac6282769c7cff777426006981d615c9b4f48df6b70570050e` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:01 UTC |
| 60 (media) | alta | `deb0cdd422ff5a4736f32d0f1fe8cb7593bc63c26cdc0748801e7edc9e6dbe79` | filehash-sha256 | Mirai | ThreatFox | 2026-10-28 06:36:01 UTC |
| 59 (media) | media | `138[.]68[.]134[.]9:23004` | ip:port | Drifter | ThreatFox | 2026-10-28 05:41:13 UTC |
| 58 (media) | media | `103[.]39[.]79[.]102:8443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 05:05:06 UTC |
| 58 (media) | alta | `hxxp://176[.]65[.]139[.]135/bot[.]armv6l` | url | Unknown Loader | ThreatFox | 2026-10-28 06:35:46 UTC |
| 58 (media) | alta | `hxxp://176[.]65[.]139[.]135/bot[.]armv5l` | url | Unknown Loader | ThreatFox | 2026-10-28 06:35:46 UTC |
| 58 (media) | alta | `hxxp://176[.]65[.]139[.]135/bot[.]armv4l` | url | Unknown Loader | ThreatFox | 2026-10-28 06:35:46 UTC |
| 58 (media) | alta | `hxxp://176[.]65[.]139[.]135/bot[.]i486` | url | Unknown Loader | ThreatFox | 2026-10-28 06:35:45 UTC |
| 58 (media) | alta | `hxxp://176[.]65[.]139[.]135/bot[.]mips` | url | Unknown Loader | ThreatFox | 2026-10-28 06:35:44 UTC |
| 58 (media) | alta | `hxxp://176[.]65[.]139[.]135/bot[.]i686` | url | Unknown Loader | ThreatFox | 2026-10-28 06:35:44 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-41709 | Broadcom VMware ESX | 2026-10-28 | Unknown |
| CVE-2026-46300 | Linux Kernel | 2026-10-28 | Unknown |
| CVE-2026-48356 | Adobe Commerce and Magento | 2026-10-27 | Unknown |
| CVE-2026-111497 | Google Brotli | 2026-10-27 | Unknown |
| CVE-2026-109618 | PHP Group PHP | 2026-10-26 | Unknown |
| CVE-2026-109619 | PHP Group PHP | 2026-10-26 | Unknown |
| CVE-2026-114625 | Arista VeloCloud Orchestrator | 2026-10-23 | Unknown |
| CVE-2026-110447 | Collabora Collabora Online – Built-in CODE Server | 2026-10-23 | Unknown |
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | 2026-10-20 | Unknown |
| CVE-2026-96656 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96655 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96654 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96652 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-110936 | Siemens Software Center | 2026-10-20 | Unknown |
| CVE-2026-102764 | BeyondTrust Remote Support | 2026-10-16 | Unknown |
| CVE-2025-61624 | Fortinet Multiple Products | 2026-10-16 | Unknown |
| CVE-2026-21589 | Atlassian Multiple Products | 2026-10-15 | Unknown |
<!-- CTI:END -->
