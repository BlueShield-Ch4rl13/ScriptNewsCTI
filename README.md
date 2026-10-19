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
**Última actualización:** 2026-10-19 22:22 UTC · **IOCs recolectados:** 1421 · **CVEs KEV recientes:** 14

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `168[.]220[.]248[.]106:9087` | ip:port | Unknown malware | ThreatFox | 2026-10-19 06:20:54 UTC |
| 73 (alta) | media | `45[.]198[.]224[.]91:6541` | ip:port | Unknown malware | ThreatFox | 2026-10-19 06:20:29 UTC |
| 71 (alta) | media | `45[.]198[.]224[.]89:48986` | ip:port | MooBot | ThreatFox | 2026-10-19 13:06:02 UTC |
| 66 (media) | media | `184[.]174[.]96[.]216:80` | ip:port | Unknown malware | ThreatFox | 2026-10-19 06:20:46 UTC |
| 66 (media) | media | `184[.]174[.]96[.]216:2121` | ip:port | Unknown malware | ThreatFox | 2026-10-19 06:20:44 UTC |
| 65 (media) | media | `hxxps://groverudder12[.]com/f/zpo1fmkdlnwfmgdkv1oi2w/ujdkhkau` | url | AMOS | ThreatFox, URLhaus | 2026-10-19 13:25:03 UTC |
| 65 (media) | media | `2d3c618b21a7e2f8bcd735da188e44a7609ff3f204832dd0781cd09e4388c9db` | sha256_hash | Unknown malware | ThreatFox, OTX | 2026-10-19 06:30:59 UTC |
| 64 (media) | alta | `23[.]132[.]164[.]15:14641` | ip:port | Remcos | ThreatFox | 2026-10-19 08:24:26 UTC |
| 64 (media) | media | `74aaa6b54133bbb2e77b2ae874e9900a907c269058f798a0a1197288ba1f7124` | sha256_hash | CloudEyE | ThreatFox, OTX | 2026-10-19 06:20:55 UTC |
| 63 (media) | alta | `76d4f71afaa6e81b07c3e634e7d2a29540179fd7e096f4bb7fd16c2272c56ea4` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:19 UTC |
| 63 (media) | alta | `f1146624e0dddb086a1e1ddaf134a663241988c9c756a8f79b65606670665980` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:15 UTC |
| 62 (media) | alta | `4d3c088902e6631935c374dfa71fe2ed9ed561502ee1cc8b2947659ebfb3f439` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:17 UTC |
| 62 (media) | alta | `7d479a9f348ca2f64e26a75eb1ac5451cc98d2a2919973b700f4eaabc5678ccc` | sha256_hash | Mirai | ThreatFox | 2026-10-19 12:18:54 UTC |
| 62 (media) | alta | `0f59b664ae66ac3240a396a56c2ad2506b691eac51928f3ef3c0ada18bd5fc4b` | sha256_hash | Mirai | ThreatFox | 2026-10-19 12:18:53 UTC |
| 61 (media) | alta | `c3d01526c311b65c845dece58818c16c445c942e9dbc41795d7516d8f0e52ab3` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:18 UTC |
| 60 (media) | alta | `138[.]68[.]170[.]147:8443` | ip:port | Aisuru | ThreatFox | 2026-10-19 17:24:33 UTC |
| 60 (media) | alta | `138[.]68[.]170[.]147:9035` | ip:port | Aisuru | ThreatFox | 2026-10-19 16:51:45 UTC |
| 60 (media) | alta | `138[.]68[.]170[.]147:8080` | ip:port | Aisuru | ThreatFox | 2026-10-19 15:41:03 UTC |
| 60 (media) | alta | `90d265704bba45a63037136dd348e05221569b6e90033270d4ee1d82f863dce6` | sha256_hash | Mirai | ThreatFox | 2026-10-19 03:54:06 UTC |
| 58 (media) | alta | `82[.]165[.]60[.]187:8080` | ip:port | Mirai | ThreatFox | 2026-10-19 22:08:01 UTC |
| 58 (media) | media | `103[.]249[.]201[.]108:443` | ip:port | Unknown malware | ThreatFox | 2026-10-19 06:20:51 UTC |
| 57 (media) | media | `edcd480853dfa06c03a0f2b555f0187fad9a71782fb1d993701951f4d91173d7` | sha256_hash | AMOS | ThreatFox | 2026-10-19 21:33:14 UTC |
| 57 (media) | media | `28b34e7fe74ecf775a5b15fe1e75a22138d9c68829156c134b19d48e568f2046` | sha256_hash | AMOS | ThreatFox | 2026-10-19 21:32:12 UTC |
| 57 (media) | media | `70e339bcf38b2d79774daa135ec598f2ecd99c6ec1cd9e810bbf005da9aab64d` | sha256_hash | AMOS | ThreatFox | 2026-10-19 21:31:10 UTC |
| 57 (media) | media | `989b86835519fc0354d7ff54d2b5162c639d98b642835bcf4c822188e039e9fa` | sha256_hash | AMOS | ThreatFox | 2026-10-19 21:30:08 UTC |

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
<!-- CTI:END -->
