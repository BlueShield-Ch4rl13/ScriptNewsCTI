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
**Última actualización:** 2026-08-16 12:59 UTC · **IOCs recolectados:** 1124 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 69 (media) | alta | `f9c60eb51354ab07885428d7b868ade6` | md5_hash | Vidar | ThreatFox | 2026-08-15 17:17:40 UTC |
| 69 (media) | alta | `63eedb85b370d3d55a6023987dc1ca36c49074b364804b3187aa9db9eac2dd33` | sha256_hash | Vidar | ThreatFox | 2026-08-15 17:17:39 UTC |
| 69 (media) | alta | `89dba32d78049d5650f10eb53173461a4969b673` | sha1_hash | Vidar | ThreatFox | 2026-08-15 17:17:39 UTC |
| 69 (media) | alta | `9327108ce3c50647935244813d506f4d` | md5_hash | Vidar | ThreatFox | 2026-08-15 17:17:33 UTC |
| 65 (media) | media | `56160fa06b16e3822879e77aa47f0764` | md5_hash | Kuiper | ThreatFox | 2026-08-15 17:17:39 UTC |
| 65 (media) | media | `dc33f06c86f021af72cc89e1feafa16dad624d43a79242ab738518480a0aef88` | sha256_hash | Kuiper | ThreatFox | 2026-08-15 17:17:38 UTC |
| 65 (media) | media | `6e6db8bfff48fb23ca12b33a4c0272d787633e06` | sha1_hash | Kuiper | ThreatFox | 2026-08-15 17:17:38 UTC |
| 65 (media) | media | `f3d99d574240983bcf016ef1c477d2d3c764966a` | sha1_hash | Coinminer | ThreatFox | 2026-08-15 17:17:37 UTC |
| 65 (media) | media | `57dacba3658cf6df28ae9d54c10c98c9` | md5_hash | Coinminer | ThreatFox | 2026-08-15 17:17:37 UTC |
| 65 (media) | media | `958f41d1487994caa3cacb8e52176712efa9d13115ea95587c6dec3658bbcee3` | sha256_hash | Coinminer | ThreatFox | 2026-08-15 17:17:36 UTC |
| 63 (media) | media | `154[.]91[.]180[.]246:18081` | ip:port | VShell | ThreatFox | 2026-08-15 22:51:12 UTC |
| 61 (media) | critica | `101[.]42[.]255[.]92:8001` | ip:port | Cobalt Strike | ThreatFox | 2026-08-16 05:05:06 UTC |
| 61 (media) | media | `40ee71fb1e584d320db1dcbc71e8b00a2b1b0cac` | sha1_hash | stealler | ThreatFox | 2026-08-15 17:17:42 UTC |
| 61 (media) | media | `84412c10b460870f3f9a5db8df5c4fb1` | md5_hash | stealler | ThreatFox | 2026-08-15 17:17:42 UTC |
| 61 (media) | media | `d4aaf92e411b242f454647d7a6d1b3657a4699e419b273e7e4b63ce4d2cccb3c` | sha256_hash | stealler | ThreatFox | 2026-08-15 17:17:41 UTC |
| 61 (media) | alta | `fb837122ffb8b7041986db79fdd5e908d8ec38c8` | sha1_hash | Vidar | ThreatFox | 2026-08-15 17:17:34 UTC |
| 61 (media) | alta | `4d4dad091692dc25b7ab60efab9fc5e3` | md5_hash | Vidar | ThreatFox | 2026-08-15 17:17:34 UTC |
| 61 (media) | alta | `f2b7f869036f558eabe71d5f73820dd56a58269d3db1435f26daeeb687c49f9d` | sha256_hash | Vidar | ThreatFox | 2026-08-15 17:17:33 UTC |
| 60 (media) | critica | `108[.]165[.]147[.]244:8081` | ip:port | Cobalt Strike | ThreatFox | 2026-08-16 06:05:05 UTC |
| 60 (media) | alta | `6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba` | sha256_hash | ClearFake | ThreatFox | 2026-08-16 01:52:58 UTC |
| 60 (media) | alta | `hxxps://soft-update[.]dev` | url | Unknown Loader | ThreatFox | 2026-08-15 23:00:52 UTC |
| 60 (media) | alta | `hxxps://admetricslab[.]org` | url | Unknown Loader | ThreatFox | 2026-08-15 23:00:51 UTC |
| 60 (media) | alta | `admetricslab[.]org` | domain | Unknown Loader | ThreatFox | 2026-08-15 22:59:52 UTC |
| 59 (media) | alta | `soft-update[.]dev` | domain | Unknown Loader | ThreatFox | 2026-08-15 22:59:52 UTC |
| 58 (media) | media | `2[.]27[.]63[.]244:443` | ip:port | Unknown malware | ThreatFox | 2026-08-16 05:05:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-20349 | Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD)  | 2026-08-11 | Unknown |
| CVE-2026-68820 | Microsoft Windows Ancillary Function Driver for WinSock  | 2026-08-11 | Unknown |
| CVE-2026-72898 | Metabase Metabase | 2026-08-11 | Unknown |
| CVE-2026-8037 | Progress LoadMaster | 2026-08-07 | Unknown |
| CVE-2026-63077 | JetBrains TeamCity | 2026-08-05 | Unknown |
| CVE-2026-18556 | N-able N-central | 2026-08-04 | Unknown |
| CVE-2026-34486 | Apache Tomcat | 2026-08-04 | Unknown |
| CVE-2026-9198 | IBM Langflow | 2026-08-04 | Unknown |
| CVE-2026-18577 | N-able N-central | 2026-08-03 | Unknown |
<!-- CTI:END -->
