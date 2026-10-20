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
**Última actualización:** 2026-10-20 16:49 UTC · **IOCs recolectados:** 1869 · **CVEs KEV recientes:** 14

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | media | `45[.]115[.]26[.]23:8012` | ip:port | Unknown malware | ThreatFox | 2026-10-20 05:10:55 UTC |
| 73 (alta) | media | `45[.]115[.]26[.]23:4455` | ip:port | Unknown malware | ThreatFox | 2026-10-20 05:10:54 UTC |
| 73 (alta) | media | `45[.]115[.]26[.]23:4457` | ip:port | Unknown malware | ThreatFox | 2026-10-20 05:10:53 UTC |
| 65 (media) | media | `103[.]97[.]176[.]121:8098` | ip:port | Unknown malware | ThreatFox | 2026-10-20 05:11:07 UTC |
| 63 (media) | alta | `76d4f71afaa6e81b07c3e634e7d2a29540179fd7e096f4bb7fd16c2272c56ea4` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:19 UTC |
| 63 (media) | alta | `f1146624e0dddb086a1e1ddaf134a663241988c9c756a8f79b65606670665980` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:15 UTC |
| 62 (media) | alta | `c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c` | sha256_hash | Mirai | ThreatFox | 2026-10-20 03:54:18 UTC |
| 62 (media) | alta | `4d3c088902e6631935c374dfa71fe2ed9ed561502ee1cc8b2947659ebfb3f439` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:17 UTC |
| 61 (media) | alta | `c3d01526c311b65c845dece58818c16c445c942e9dbc41795d7516d8f0e52ab3` | sha256_hash | Mirai | ThreatFox | 2026-10-19 21:54:18 UTC |
| 60 (media) | alta | `10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42` | sha256_hash | Mirai | ThreatFox | 2026-10-20 10:54:20 UTC |
| 60 (media) | alta | `f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-20 03:54:22 UTC |
| 60 (media) | alta | `c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-20 03:54:21 UTC |
| 60 (media) | alta | `f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-20 03:54:20 UTC |
| 60 (media) | alta | `9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-20 03:54:19 UTC |
| 60 (media) | alta | `138[.]68[.]170[.]147:8443` | ip:port | Aisuru | ThreatFox | 2026-10-19 17:24:33 UTC |
| 60 (media) | alta | `138[.]68[.]170[.]147:9035` | ip:port | Aisuru | ThreatFox | 2026-10-19 16:51:45 UTC |
| 58 (media) | media | `hxxp://popeak[.]biz:8312/products` | url | Remus | ThreatFox | 2026-10-20 16:17:07 UTC |
| 58 (media) | media | `hxxp://echjho[.]biz:7713/tokens` | url | Remus | ThreatFox | 2026-10-20 16:12:27 UTC |
| 58 (media) | alta | `82[.]165[.]60[.]187:8080` | ip:port | Mirai | ThreatFox | 2026-10-20 05:13:46 UTC |
| 57 (media) | media | `8c9e3f6569498056139621c2305beaf8b257d6e60f9e35bd9420554a10a1a47f` | sha256_hash | AMOS | ThreatFox | 2026-10-20 16:35:30 UTC |
| 57 (media) | media | `19dae42087c116ebc870e69bd2d99c8204240d161ccb0aced3f8be86023170c5` | sha256_hash | AMOS | ThreatFox | 2026-10-20 16:32:46 UTC |
| 57 (media) | media | `3bfd884a8d270ae7f42f4b149bbd57c9cc83868b2f7208a8f1d196527a8bd633` | sha256_hash | AMOS | ThreatFox | 2026-10-20 16:21:59 UTC |
| 57 (media) | media | `hxxp://finter28[.]help:5621/settings` | url | Remus | ThreatFox | 2026-10-20 16:17:37 UTC |
| 57 (media) | media | `05e9554b32dbe4b907f85ac3ac22f8d4c09b5554b13ccbde64b34a6ef6e456bb` | sha256_hash | AMOS | ThreatFox | 2026-10-20 10:06:08 UTC |
| 57 (media) | media | `d3f3f3d8a4a8a1e5973646bfb2f0f09c899d8fc6530bc67ab509e62002e11deb` | sha256_hash | AMOS | ThreatFox | 2026-10-20 10:02:22 UTC |

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
