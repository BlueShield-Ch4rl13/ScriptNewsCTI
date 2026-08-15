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
**Última actualización:** 2026-08-15 06:57 UTC · **IOCs recolectados:** 2327 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | media | `104[.]248[.]196[.]119:25001` | ip:port | Kimwolf | ThreatFox | 2026-08-14 12:45:43 UTC |
| 71 (alta) | alta | `178[.]16[.]52[.]136:3009` | ip:port | AsyncRAT | ThreatFox | 2026-08-14 19:44:10 UTC |
| 71 (alta) | alta | `176[.]65[.]139[.]232:80` | ip:port | Mirai | ThreatFox | 2026-08-14 19:44:08 UTC |
| 71 (alta) | alta | `104[.]251[.]180[.]164:55009` | ip:port | PureRAT | ThreatFox | 2026-08-14 09:43:13 UTC |
| 62 (media) | media | `b5248924bb215076323efa59a05a011d6199bbe1` | sha1_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:54 UTC |
| 62 (media) | media | `626e45681bd083f5f85acd0f6aefe5bc` | md5_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:54 UTC |
| 61 (media) | critica | `64[.]227[.]74[.]35:443` | ip:port | AdaptixC2 | ThreatFox | 2026-08-14 19:46:21 UTC |
| 61 (media) | media | `920f619ff80cdf2532571d9a55fe7c4ec79ce02f` | sha1_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:53 UTC |
| 61 (media) | media | `476453e63cf65c3fbe54f9b2cb3cc649` | md5_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:53 UTC |
| 60 (media) | media | `87ac54897c3cb1a2b15f46c5897254f2579e529e` | sha1_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:56 UTC |
| 60 (media) | media | `cdba3f620f58b3283c37ad512452a9d7` | md5_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:56 UTC |
| 60 (media) | media | `2fc0d48f26330997001a2cd70ee5ec504b7985178cee9a9ed16730502db7e42f` | sha256_hash | Kuiper | ThreatFox | 2026-08-14 12:10:55 UTC |
| 60 (media) | media | `ea79f600b22ef30ffac57a4dccecb08142b5380c` | sha1_hash | Kuiper | ThreatFox | 2026-08-14 12:10:55 UTC |
| 60 (media) | media | `3b5870ca6edb52e878ddadcaa9ade7f8` | md5_hash | Kuiper | ThreatFox | 2026-08-14 12:10:55 UTC |
| 60 (media) | media | `a86215689dcc155290c3bbf9cf9e0da4d82681ffccab1a490965805ba26d7d76` | sha256_hash | NetWire RC | ThreatFox | 2026-08-14 12:10:55 UTC |
| 60 (media) | alta | `217[.]60[.]241[.]247:7707` | ip:port | AsyncRAT | ThreatFox | 2026-08-14 09:45:24 UTC |
| 59 (media) | alta | `13[.]248[.]243[.]5:443` | ip:port | Nanocore RAT | ThreatFox | 2026-08-15 05:05:06 UTC |
| 59 (media) | alta | `bedpocket[.]xyz` | domain | Unknown Loader | ThreatFox | 2026-08-14 07:33:34 UTC |
| 58 (media) | alta | `64[.]89[.]161[.]196:4444` | ip:port | DCRat | ThreatFox | 2026-08-14 19:46:22 UTC |
| 58 (media) | alta | `46[.]101[.]133[.]159:8001` | ip:port | Aisuru | ThreatFox | 2026-08-14 18:20:05 UTC |
| 58 (media) | alta | `alvin[.]bet` | domain | ClearFake | ThreatFox | 2026-08-14 12:20:49 UTC |
| 58 (media) | alta | `beardiscovery[.]xyz` | domain | Unknown Loader | ThreatFox | 2026-08-14 07:36:18 UTC |
| 58 (media) | alta | `hxxps://digitalenterprise2026[.]com/ZxC9vBnM7lKjH3gF` | url | ClearFake | ThreatFox | 2026-08-14 07:00:32 UTC |
| 57 (media) | alta | `45[.]38[.]249[.]63:1009` | ip:port | Mirai | ThreatFox | 2026-08-15 06:40:42 UTC |
| 57 (media) | alta | `45[.]38[.]249[.]63:6969` | ip:port | Mirai | ThreatFox | 2026-08-15 06:40:42 UTC |

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
