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
**Última actualización:** 2026-10-10 21:35 UTC · **IOCs recolectados:** 1138 · **CVEs KEV recientes:** 13

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `178[.]16[.]53[.]59:8080` | ip:port | Aisuru | ThreatFox | 2026-10-10 21:15:22 UTC |
| 75 (alta) | media | `8[.]213[.]238[.]72:443` | ip:port | Jackskid | ThreatFox | 2026-10-10 06:21:14 UTC |
| 73 (alta) | media | `cf03c5920933f4c0f79c71e52edb28d238bb8396e71558ecc9b33a595fc0a9ae` | sha256_hash | Coinminer | ThreatFox | 2026-10-10 21:09:12 UTC |
| 73 (alta) | media | `0c77484252a50e76e06efd8d53cbec7a71397c2e` | sha1_hash | Coinminer | ThreatFox | 2026-10-10 21:09:12 UTC |
| 73 (alta) | media | `31525df166ed1ca0a0da57f68b2fbb3e` | md5_hash | Coinminer | ThreatFox | 2026-10-10 21:09:12 UTC |
| 73 (alta) | alta | `77[.]90[.]57[.]20:8080` | ip:port | Mirai | ThreatFox | 2026-10-10 06:02:02 UTC |
| 73 (alta) | alta | `78eda3158bc47d7d0982c476486b12faaf6e46195e0bfc457c8ed43690f0de82` | sha256_hash | SVCStealer | ThreatFox | 2026-10-09 22:12:29 UTC |
| 71 (alta) | alta | `ae5ed7c741695e76561ef0b66b1792fc95a5d1d4` | sha1_hash | DeltaStealer | ThreatFox | 2026-10-10 21:09:20 UTC |
| 71 (alta) | alta | `2ce0c7b067339c33da3ae88154d0a6b2` | md5_hash | DeltaStealer | ThreatFox | 2026-10-10 21:09:20 UTC |
| 71 (alta) | alta | `d61419108785340e5b48fb4ef5fec85f46bbeaa86636bdfa9706b7df16a2e0f4` | sha256_hash | DeltaStealer | ThreatFox | 2026-10-10 21:09:19 UTC |
| 71 (alta) | critica | `94[.]154[.]43[.]64:4321` | ip:port | AdaptixC2 | ThreatFox | 2026-10-10 19:45:55 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]12:23` | ip:port | Mirai | ThreatFox | 2026-10-10 05:59:12 UTC |
| 70 (alta) | media | `d2b5f4ff9ccf98b4ebff54c8bf85e242bcf2b6387c10c451fe8c21d73c5d24fc` | sha256_hash | MoriAgent | ThreatFox | 2026-10-10 21:09:07 UTC |
| 70 (alta) | media | `8d925835f2eb0d742d098b2a4ed92f8d19f1ba41` | sha1_hash | MoriAgent | ThreatFox | 2026-10-10 21:09:07 UTC |
| 70 (alta) | media | `f0af25e9b2ac985a1ba4eba7ca321806` | md5_hash | MoriAgent | ThreatFox | 2026-10-10 21:09:07 UTC |
| 69 (media) | alta | `c4bb3e578b038fdd3986e5edb6b9a09e475c2cdf` | sha1_hash | Venus Stealer | ThreatFox | 2026-10-10 21:09:09 UTC |
| 69 (media) | alta | `fc2f1cdd2fbb4061a8f9e909c64b7f54` | md5_hash | Venus Stealer | ThreatFox | 2026-10-10 21:09:09 UTC |
| 69 (media) | alta | `9fe84328554e02c9aae80f9fda0fb6c06e8b16bde91f6070a991a619bfc61238` | sha256_hash | Venus Stealer | ThreatFox | 2026-10-10 21:09:08 UTC |
| 69 (media) | media | `82967b6c24f52664a3b9399f853ea812` | md5_hash | Coinminer | ThreatFox | 2026-10-10 21:09:06 UTC |
| 69 (media) | media | `fedaf63f737fd855505e9c11fb0458f765df4fa5` | sha1_hash | TinyMet | ThreatFox | 2026-10-10 21:09:05 UTC |
| 69 (media) | media | `8c37e43091ae6750e9dd459f81f0f32c` | md5_hash | TinyMet | ThreatFox | 2026-10-10 21:09:05 UTC |
| 69 (media) | media | `064e83897c545f71f2f6a879ea0845f6d23ec9b9` | sha1_hash | Coinminer | ThreatFox | 2026-10-10 21:09:05 UTC |
| 69 (media) | alta | `2b263e84b679f604988922f3ad5928c68be97e3ffe305d1fad4e2b7623815b9d` | sha256_hash | SmartLoader | ThreatFox | 2026-10-09 22:12:26 UTC |
| 68 (media) | alta | `a79c713bfb2f0ca6c6eed68466723a5d24d2fcead39b7d2aeff262083909efd0` | sha256_hash | Ghost RAT | ThreatFox | 2026-10-10 21:09:14 UTC |
| 68 (media) | alta | `97dbb5bf65426b00a0e42ca86519018a2982c0b1` | sha1_hash | Ghost RAT | ThreatFox | 2026-10-10 21:09:14 UTC |

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
| CVE-2026-88772 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-88771 | Citrix NetScaler | 2026-09-27 | Unknown |
<!-- CTI:END -->
