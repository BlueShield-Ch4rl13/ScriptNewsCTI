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
**Última actualización:** 2026-10-18 20:35 UTC · **IOCs recolectados:** 2038 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `168[.]220[.]248[.]106:9087` | ip:port | Unknown malware | ThreatFox | 2026-10-18 14:51:00 UTC |
| 73 (alta) | media | `45[.]198[.]224[.]91:6541` | ip:port | Unknown malware | ThreatFox | 2026-10-18 17:53:14 UTC |
| 71 (alta) | media | `85[.]215[.]45[.]36:80` | ip:port | Unknown malware | ThreatFox | 2026-10-18 06:09:58 UTC |
| 66 (media) | media | `184[.]174[.]96[.]216:2121` | ip:port | Unknown malware | ThreatFox | 2026-10-18 17:37:56 UTC |
| 66 (media) | media | `184[.]174[.]96[.]216:80` | ip:port | Unknown malware | ThreatFox | 2026-10-18 17:37:18 UTC |
| 66 (media) | critica | `91[.]201[.]115[.]193:443` | ip:port | Cobalt Strike | ThreatFox | 2026-10-18 14:05:05 UTC |
| 66 (media) | critica | `91[.]201[.]115[.]193:80` | ip:port | Cobalt Strike | ThreatFox | 2026-10-18 14:05:05 UTC |
| 66 (media) | critica | `91[.]201[.]115[.]193:8080` | ip:port | Cobalt Strike | ThreatFox | 2026-10-18 14:05:05 UTC |
| 66 (media) | critica | `91[.]201[.]115[.]193:22` | ip:port | Cobalt Strike | ThreatFox | 2026-10-18 14:05:04 UTC |
| 64 (media) | alta | `hxxp://33841-28554[.]dchost[.]com/vDsuzsiIMAiwv69[.]bin` | url | GUIDLOADER | ThreatFox, URLhaus | 2026-10-18 13:06:10 UTC |
| 62 (media) | media | `74[.]208[.]19[.]244:576` | ip:port | Unknown malware | ThreatFox | 2026-10-18 06:10:21 UTC |
| 62 (media) | alta | `c3f27fa88aada79400d7a0ad373347b9b4c0493f2734d68f950019a389cd5123` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 03:53:55 UTC |
| 61 (media) | alta | `df7d917f62ca520b735dbdf2ebafc79a74fc57581d34bdb755c83e002bd39d09` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 09:54:01 UTC |
| 61 (media) | alta | `9bc7fd6c0f392b367d76e1f617e60978760b54acc14e40a54ef0d39f7d067a61` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 03:53:56 UTC |
| 61 (media) | alta | `0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 02:53:55 UTC |
| 60 (media) | alta | `74c6f27ce2a20dd393e72bb54293cfece0cb05e599ff0010607f29e7c8a0f5dc` | sha256_hash | Mirai | ThreatFox | 2026-10-18 19:54:04 UTC |
| 60 (media) | alta | `eae054b5afd8d1e49222ecaeafb9a753579c9b3ed1e0f543883cfdcb50f56c8d` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 09:54:02 UTC |
| 60 (media) | alta | `3f5af066d85830b838143fabc577221c93db3b5abc2c2057901463cbed6936cc` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 02:53:57 UTC |
| 59 (media) | alta | `9bd0fcad7e6ca59c3caeed5b9fae6ecb499d274bfff2042a855f7b9f5b3b1657` | sha256_hash | Mirai | ThreatFox | 2026-10-18 19:54:03 UTC |
| 59 (media) | alta | `26f91ce3d8ee20dd027d4de026d6e5dd08604b6bec6b3142b55749150493285c` | sha256_hash | Mirai | ThreatFox | 2026-10-18 19:54:01 UTC |
| 59 (media) | critica | `185[.]165[.]171[.]21:31337` | ip:port | Sliver | ThreatFox | 2026-10-18 16:13:08 UTC |
| 59 (media) | media | `47e9e1bf4296b651d4d5d3bd066a0e3ceb44c4f897aa1edac79197d1ec680e6c` | sha256_hash | AMOS | ThreatFox | 2026-10-18 10:28:47 UTC |
| 59 (media) | alta | `c24ae3aef86d4ce54942f811bbc9bc2620131f340a4de4bf3fd1eb00f57341c9` | sha256_hash | Mirai | ThreatFox | 2026-10-18 03:53:54 UTC |
| 59 (media) | alta | `43ee067ed40abe2c65ff03138d986cdd43d7ba4ba66b1316f8009795096eba04` | sha256_hash | Mirai | ThreatFox | 2026-10-18 02:53:54 UTC |
| 58 (media) | alta | `345fd6e63c2c817ff28ac5e4fc6792e8ada4efadebe6a3692f334300fb35b187` | sha256_hash | Mirai | ThreatFox | 2026-10-18 19:54:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-102764 | BeyondTrust Remote Support | 2026-10-16 | Unknown |
| CVE-2025-61624 | Fortinet Multiple Products | 2026-10-16 | Unknown |
| CVE-2026-21589 | Atlassian Multiple Products | 2026-10-15 | Unknown |
| CVE-2026-105134 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-76519 | Cisco Secure Email Gateway | 2026-10-14 | Unknown |
| CVE-2026-105133 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-0322 | Palo Alto Networks PAN-OS | 2026-10-14 | Unknown |
| CVE-2026-104935 | Ivanti Connect Secure | 2026-10-13 | Unknown |
| CVE-2026-96951 | Microsoft Windows | 2026-10-13 | Unknown |
| CVE-2015-5477 | ISC BIND | 2026-10-08 | Unknown |
| CVE-2016-3081 | Apache Struts | 2026-10-08 | Unknown |
| CVE-2023-22894 | Strapi Strapi | 2026-10-08 | Unknown |
| CVE-2021-3199 | ONLYOFFICE Docs | 2026-10-08 | Unknown |
| CVE-2015-3306 | ProFTPD ProFTPD | 2026-10-08 | Unknown |
| CVE-2026-88779 | Citrix NetScaler | 2026-10-04 | Unknown |
<!-- CTI:END -->
