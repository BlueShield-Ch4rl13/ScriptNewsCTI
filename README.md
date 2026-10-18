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
**Última actualización:** 2026-10-18 04:08 UTC · **IOCs recolectados:** 1755 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `54[.]215[.]31[.]113:8312` | ip:port | Remus | ThreatFox | 2026-10-17 15:21:46 UTC |
| 75 (alta) | media | `130[.]12[.]180[.]32:7001` | ip:port | Unknown malware | ThreatFox | 2026-10-17 15:21:10 UTC |
| 75 (alta) | media | `54[.]215[.]31[.]113:5621` | ip:port | Remus | ThreatFox | 2026-10-17 13:10:12 UTC |
| 75 (alta) | media | `54[.]215[.]31[.]113:5930` | ip:port | Remus | ThreatFox | 2026-10-17 13:02:27 UTC |
| 73 (alta) | alta | `38[.]43[.]93[.]61:80` | ip:port | Mirai | ThreatFox | 2026-10-17 19:44:48 UTC |
| 71 (alta) | media | `85[.]215[.]45[.]36:80` | ip:port | Unknown malware | ThreatFox | 2026-10-17 21:34:50 UTC |
| 71 (alta) | media | `130[.]12[.]180[.]42:12312` | ip:port | Unknown malware | ThreatFox | 2026-10-17 05:33:11 UTC |
| 71 (alta) | media | `130[.]12[.]180[.]42:25565` | ip:port | Unknown malware | ThreatFox | 2026-10-17 05:32:48 UTC |
| 66 (media) | alta | `3264c945adf2545c8f10320a519f42dcf53b279d11048f4670edb6b83d7ab813` | sha256_hash | Mirai | ThreatFox | 2026-10-17 09:53:49 UTC |
| 66 (media) | media | `104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7` | sha256_hash | AMOS | ThreatFox | 2026-10-17 05:33:13 UTC |
| 66 (media) | alta | `157[.]230[.]108[.]74:8080` | ip:port | Aisuru | ThreatFox | 2026-10-17 05:04:58 UTC |
| 63 (media) | alta | `85[.]215[.]45[.]36:4115` | ip:port | Mirai | ThreatFox | 2026-10-17 11:05:26 UTC |
| 62 (media) | alta | `c3f27fa88aada79400d7a0ad373347b9b4c0493f2734d68f950019a389cd5123` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 03:53:55 UTC |
| 62 (media) | media | `74[.]208[.]19[.]244:576` | ip:port | Unknown malware | ThreatFox | 2026-10-17 16:45:19 UTC |
| 62 (media) | alta | `a47a7015e8a147b38d1b1a8805abfeba72ce5dc7730fe997eff8b59eff663338` | sha256_hash | Mirai | ThreatFox | 2026-10-17 14:53:50 UTC |
| 62 (media) | alta | `a2ba1efa766e85b0c842d4c3b53c0b41afa492280bddc853cc88c912c9683e2d` | sha256_hash | Mirai | ThreatFox | 2026-10-17 14:53:48 UTC |
| 62 (media) | alta | `679372386b687d4aa79d13af9e2929cdfd1ab1e388eaeac1a31c81f08ad84c37` | sha256_hash | WARDENStealer | ThreatFox | 2026-10-17 05:32:07 UTC |
| 61 (media) | alta | `9bc7fd6c0f392b367d76e1f617e60978760b54acc14e40a54ef0d39f7d067a61` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 03:53:56 UTC |
| 61 (media) | alta | `0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 02:53:55 UTC |
| 61 (media) | media | `102[.]220[.]161[.]63:443` | ip:port | CECbot | ThreatFox | 2026-10-17 16:20:24 UTC |
| 61 (media) | alta | `2b4bb4ab724ee6f0741b9366fb6e8ceda68d4cbbd4bb2aed74a7c21cd28c63cb` | sha256_hash | WARDENStealer | ThreatFox | 2026-10-17 05:32:08 UTC |
| 60 (media) | alta | `3f5af066d85830b838143fabc577221c93db3b5abc2c2057901463cbed6936cc` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-18 02:53:57 UTC |
| 60 (media) | alta | `7cb2a4f29cb1200d1f81b71f189fc40d29bf57376c8a737c0ca3a4522e0aaa2c` | sha256_hash | Mirai | ThreatFox | 2026-10-17 14:53:49 UTC |
| 60 (media) | alta | `227f6b2c16a0be122e817c1688273d6a5aa218e1321a44c9e3efed64c74fec2e` | sha256_hash | Mirai | ThreatFox | 2026-10-17 09:53:45 UTC |
| 60 (media) | media | `hxxp://192[.]162[.]199[.]249/hbspbloprxh3iu2h` | url | AMOS | ThreatFox | 2026-10-17 05:33:13 UTC |

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
