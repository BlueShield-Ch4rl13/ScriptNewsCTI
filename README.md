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
**Última actualización:** 2026-10-14 11:43 UTC · **IOCs recolectados:** 2547 · **CVEs KEV recientes:** 12

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | media | `89[.]32[.]41[.]49:23789` | ip:port | Potassium | ThreatFox | 2026-10-14 03:51:56 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]127:1999` | ip:port | Mirai | ThreatFox | 2026-10-14 05:40:37 UTC |
| 71 (alta) | media | `45[.]198[.]224[.]158:17691` | ip:port | MooBot | ThreatFox | 2026-10-14 09:22:42 UTC |
| 70 (alta) | alta | `176[.]65[.]139[.]41:8001` | ip:port | Aisuru | ThreatFox | 2026-10-13 14:12:26 UTC |
| 68 (media) | alta | `176[.]65[.]139[.]40:21` | ip:port | Mirai | ThreatFox | 2026-10-14 05:42:45 UTC |
| 68 (media) | alta | `176[.]65[.]139[.]40:44565` | ip:port | Mirai | ThreatFox | 2026-10-14 05:40:42 UTC |
| 65 (media) | media | `hxxps://chantcompass9[.]com/curl/ltlmtyrcu/3idd7eprmh6is0juh3[.]json` | url | AMOS | ThreatFox, URLhaus | 2026-10-14 05:41:11 UTC |
| 65 (media) | media | `hxxps://chantcompass9[.]com/f/yhzuuxkyytoc-pr6sqaaqa/lvitjpau` | url | AMOS | ThreatFox, URLhaus | 2026-10-14 05:41:10 UTC |
| 64 (media) | media | `89[.]32[.]41[.]128:23789` | ip:port | Potassium | ThreatFox | 2026-10-14 03:51:56 UTC |
| 63 (media) | alta | `64[.]89[.]160[.]185:8060` | ip:port | Mirai | ThreatFox | 2026-10-14 05:40:54 UTC |
| 63 (media) | media | `89[.]32[.]41[.]128:15987` | ip:port | Potassium | ThreatFox | 2026-10-13 23:50:29 UTC |
| 61 (media) | alta | `192[.]145[.]124[.]6:62927` | ip:port | Remcos | ThreatFox | 2026-10-14 09:03:49 UTC |
| 61 (media) | alta | `216[.]9[.]224[.]115:1246` | ip:port | AsyncRAT | ThreatFox | 2026-10-14 06:05:06 UTC |
| 61 (media) | media | `hxxp://23[.]94[.]252[.]153/68993` | url | Unknown malware | ThreatFox, URLhaus | 2026-10-14 05:41:17 UTC |
| 60 (media) | alta | `236809733e2fa25d24db2a92ec21c02f1346b248f164809a5641ff7d8a636125` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:18 UTC |
| 60 (media) | alta | `82d73a45f4319ce7f0ef05cabb6e9c786d3199ee9e200deedc86c277f639da14` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:17 UTC |
| 60 (media) | alta | `9fa42ae1ade9a75405c53e51da8de114d5570c2c9bc91cdf85b1df4bbc7cc660` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:16 UTC |
| 60 (media) | alta | `b0fac14fe13898d1a398ce70d34440005608abfb605b8b15533b5d187994d522` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:15 UTC |
| 60 (media) | alta | `7d3402244b10e3870761ad3d504e58314b4e32104dd4c861760a3986cffecded` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:11 UTC |
| 60 (media) | alta | `9506ad006b7e16a7369ebfef676132054547788714f1cfad2b7ebe7c0e6de7bf` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:10 UTC |
| 60 (media) | alta | `775dd595995abc0b4571ceafdad653a34538f448eb2a90ef1578f7ca4785953b` | sha256_hash | Mirai | ThreatFox | 2026-10-13 13:53:09 UTC |
| 60 (media) | media | `stormfangridge[.]top` | domain | magecart | ThreatFox | 2026-10-13 13:43:06 UTC |
| 59 (media) | alta | `167[.]99[.]179[.]106:8001` | ip:port | Aisuru | ThreatFox | 2026-10-13 18:58:58 UTC |
| 58 (media) | alta | `216[.]9[.]224[.]115:1244` | ip:port | AsyncRAT | ThreatFox | 2026-10-14 09:44:52 UTC |
| 58 (media) | alta | `publisher99[.]com` | domain | WARDENStealer | ThreatFox | 2026-10-14 05:42:06 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-76504 | Cisco Catalyst SD-WAN Manager | 2026-09-30 | Unknown |
<!-- CTI:END -->
