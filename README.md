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
**Última actualización:** 2026-10-15 04:15 UTC · **IOCs recolectados:** 2140 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `103[.]170[.]217[.]170:80` | ip:port | Unknown malware | ThreatFox | 2026-10-15 00:52:45 UTC |
| 73 (alta) | alta | `159[.]203[.]28[.]151:8443` | ip:port | Aisuru | ThreatFox | 2026-10-14 22:28:18 UTC |
| 73 (alta) | alta | `159[.]203[.]28[.]151:8001` | ip:port | Aisuru | ThreatFox | 2026-10-14 20:09:39 UTC |
| 72 (alta) | critica | `2[.]27[.]248[.]209:31337` | ip:port | Sliver | ThreatFox | 2026-10-14 20:54:14 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]127:1999` | ip:port | Mirai | ThreatFox | 2026-10-14 05:40:37 UTC |
| 71 (alta) | media | `45[.]198[.]224[.]158:17691` | ip:port | MooBot | ThreatFox | 2026-10-14 09:22:42 UTC |
| 68 (media) | alta | `176[.]65[.]139[.]40:21` | ip:port | Mirai | ThreatFox | 2026-10-14 05:42:45 UTC |
| 68 (media) | alta | `176[.]65[.]139[.]40:44565` | ip:port | Mirai | ThreatFox | 2026-10-14 05:40:42 UTC |
| 66 (media) | alta | `158[.]94[.]211[.]251:443` | ip:port | AsyncRAT | ThreatFox | 2026-10-14 19:43:44 UTC |
| 65 (media) | media | `hxxps://therapygeorgia[.]com/curl/6bab7f3072580dd7a8fc3bf0ca52c98d3136ed0839e61c7e7794494b3b8c03ac` | url | MacSync | ThreatFox, URLhaus | 2026-10-15 00:52:45 UTC |
| 65 (media) | alta | `157[.]230[.]108[.]74:8001` | ip:port | Aisuru | ThreatFox | 2026-10-14 20:09:39 UTC |
| 64 (media) | critica | `158[.]94[.]208[.]218:31337` | ip:port | Sliver | ThreatFox | 2026-10-14 15:38:46 UTC |
| 63 (media) | alta | `1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5` | sha256_hash | Agent Tesla | ThreatFox | 2026-10-15 03:53:25 UTC |
| 63 (media) | alta | `64[.]89[.]160[.]185:80` | ip:port | Mirai | ThreatFox | 2026-10-14 15:38:09 UTC |
| 63 (media) | media | `159[.]203[.]20[.]34:443` | ip:port | Jackskid | ThreatFox | 2026-10-14 14:04:51 UTC |
| 63 (media) | alta | `64[.]89[.]160[.]185:8060` | ip:port | Mirai | ThreatFox | 2026-10-14 05:40:54 UTC |
| 61 (media) | alta | `213[.]152[.]162[.]19:25674` | ip:port | Remcos | ThreatFox | 2026-10-14 21:10:20 UTC |
| 61 (media) | alta | `176[.]65[.]139[.]196:80` | ip:port | Mirai | ThreatFox | 2026-10-14 15:38:09 UTC |
| 61 (media) | alta | `192[.]145[.]124[.]6:62927` | ip:port | Remcos | ThreatFox | 2026-10-14 09:03:49 UTC |
| 61 (media) | alta | `216[.]9[.]224[.]115:1246` | ip:port | AsyncRAT | ThreatFox | 2026-10-14 06:05:06 UTC |
| 60 (media) | media | `68[.]183[.]26[.]138:443` | ip:port | Jackskid | ThreatFox | 2026-10-14 14:04:52 UTC |
| 59 (media) | media | `a9cd105e5cdf8b3cafb0fe9ffb886ab7becd7dbafa7c4cf0ce214d2d5e5686c8` | sha256_hash | AMOS | ThreatFox | 2026-10-15 03:44:36 UTC |
| 59 (media) | media | `eb5a4df6986f8534413178add3444a5fe58af16e8f500ab122b3096eb24646de` | sha256_hash | AMOS | ThreatFox | 2026-10-15 03:37:46 UTC |
| 59 (media) | media | `1de24789010bcf294a1fa3c8a982d924ba5d212ada16a30dc8e16532293886c9` | sha256_hash | AMOS | ThreatFox | 2026-10-15 03:34:33 UTC |
| 59 (media) | media | `35b1308baa0c0a79f8431aca3988c4389c0e0f9fa3ecd4243295cd1707f53683` | sha256_hash | AMOS | ThreatFox | 2026-10-15 03:30:34 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-102490 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-102489 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-104286 | Fortinet FortiMail | 2026-10-01 | Unknown |
<!-- CTI:END -->
