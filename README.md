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
**Última actualización:** 2026-10-12 05:33 UTC · **IOCs recolectados:** 1196 · **CVEs KEV recientes:** 11

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 78 (alta) | alta | `71[.]15[.]96[.]217:23` | ip:port | Mirai | ThreatFox | 2026-10-12 04:18:46 UTC |
| 77 (alta) | alta | `178[.]16[.]53[.]56:9034` | ip:port | Aisuru | ThreatFox | 2026-10-12 05:02:09 UTC |
| 77 (alta) | alta | `178[.]16[.]53[.]59:8080` | ip:port | Aisuru | ThreatFox | 2026-10-11 07:02:53 UTC |
| 76 (alta) | alta | `211[.]43[.]97[.]233:23` | ip:port | Mirai | ThreatFox | 2026-10-12 04:18:50 UTC |
| 75 (alta) | alta | `34[.]22[.]226[.]31:23` | ip:port | Mirai | ThreatFox | 2026-10-12 04:18:54 UTC |
| 75 (alta) | media | `31[.]59[.]220[.]26:5900` | ip:port | DarkVNC | ThreatFox | 2026-10-12 04:18:39 UTC |
| 75 (alta) | media | `165[.]245[.]171[.]220:5900` | ip:port | DarkVNC | ThreatFox | 2026-10-12 04:18:32 UTC |
| 75 (alta) | media | `165[.]245[.]160[.]178:5900` | ip:port | DarkVNC | ThreatFox | 2026-10-12 04:16:22 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]37:1999` | ip:port | Mirai | ThreatFox | 2026-10-11 07:02:52 UTC |
| 71 (alta) | alta | `130[.]12[.]180[.]212:80` | ip:port | Mirai | ThreatFox | 2026-10-11 08:17:05 UTC |
| 71 (alta) | alta | `38[.]253[.]224[.]56:8080` | ip:port | Mirai | ThreatFox | 2026-10-11 08:17:04 UTC |
| 71 (alta) | media | `176[.]65[.]139[.]231:4444` | ip:port | Unknown malware | ThreatFox | 2026-10-11 07:02:43 UTC |
| 71 (alta) | media | `38[.]253[.]224[.]56:3778` | ip:port | Bashlite | ThreatFox | 2026-10-11 07:02:42 UTC |
| 69 (media) | alta | `113[.]254[.]122[.]139:23` | ip:port | Mirai | ThreatFox | 2026-10-12 04:18:43 UTC |
| 69 (media) | alta | `2def5f3586564612e03fa8b57bf3e8f2c4aede6f3be47001890c472b87ff79ee` | sha256_hash | SmartLoader | ThreatFox | 2026-10-11 11:12:45 UTC |
| 68 (media) | critica | `176[.]65[.]148[.]54:31337` | ip:port | Sliver | ThreatFox | 2026-10-11 17:19:39 UTC |
| 68 (media) | alta | `365d1b01cd5e605f6e7d39b192aaf56040176f2bce6eaec0fc11584850793a83` | sha256_hash | SmartLoader | ThreatFox | 2026-10-11 11:12:47 UTC |
| 68 (media) | alta | `ad7ae1df63dc9f6ee4eabbeb4e9c0f98b2a1b1d69ad8bde9b564e998678310c4` | sha256_hash | HijackLoader | ThreatFox | 2026-10-11 07:02:28 UTC |
| 67 (media) | alta | `57d5c2569a10c07529ed7fb18699095a53d9be342f612b8230e39a48312a6281` | sha256_hash | SmartLoader | ThreatFox | 2026-10-11 12:12:46 UTC |
| 67 (media) | alta | `d069c2eae59a5c7ad0c5de361220ff91ff228137812ed5cfd465df1a120ac3ea` | sha256_hash | SmartLoader | ThreatFox | 2026-10-11 12:12:43 UTC |
| 66 (media) | alta | `bd6fc7755b14d207046e4edf7a455ea8bc40b514bfc9257b925a8b08cb3677d0` | sha256_hash | Mirai | ThreatFox | 2026-10-11 21:12:45 UTC |
| 66 (media) | media | `162[.]243[.]162[.]107:443` | ip:port | Unknown malware | ThreatFox | 2026-10-11 16:57:16 UTC |
| 66 (media) | alta | `5ce83f99eff295ab626b8f6dacc18a34708a30ac9a95fd23067d71b820283a71` | sha256_hash | SmartLoader | ThreatFox | 2026-10-11 12:12:45 UTC |
| 66 (media) | alta | `3ab5ae6e34d35977cf218c785b184425851f94202092d1bcfb1a2cc44a30bfe5` | sha256_hash | SmartLoader | ThreatFox | 2026-10-11 12:12:42 UTC |
| 66 (media) | alta | `103[.]170[.]217[.]170:1312` | ip:port | Mirai | ThreatFox | 2026-10-11 07:02:52 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2015-5477 | ISC BIND | 2026-10-08 | Unknown |
| CVE-2016-3081 | Apache Struts | 2026-10-08 | Unknown |
| CVE-2023-22894 | Strapi Strapi | 2026-10-08 | Unknown |
| CVE-2021-3199 | ONLYOFFICE Docs | 2026-10-08 | Unknown |
| CVE-2015-3306 | ProFTPD ProFTPD | 2026-10-08 | Unknown |
| CVE-2026-88779 | Citrix NetScaler | 2026-10-04 | Unknown |
| CVE-2026-102490 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-102489 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-104286 | Fortinet FortiMail | 2026-10-01 | Unknown |
| CVE-2026-76504 | Cisco Catalyst SD-WAN Manager | 2026-09-30 | Unknown |
| CVE-2026-86950 | Apple Multiple Products | 2026-09-29 | Unknown |
<!-- CTI:END -->
