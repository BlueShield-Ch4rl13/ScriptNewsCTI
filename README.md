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
**Última actualización:** 2026-08-12 02:34 UTC · **IOCs recolectados:** 839 · **CVEs KEV recientes:** 10

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `106[.]13[.]23[.]149:6819` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:44 UTC |
| 75 (alta) | alta | `161[.]35[.]48[.]40:5555` | ip:port | Aisuru | ThreatFox | 2026-08-11 05:46:11 UTC |
| 74 (alta) | alta | `176[.]65[.]139[.]236:1337` | ip:port | Mirai | ThreatFox | 2026-08-11 12:48:51 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]97:1302` | ip:port | Mirai | ThreatFox | 2026-08-11 11:26:37 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]97:4330` | ip:port | Mirai | ThreatFox | 2026-08-11 11:26:37 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]97:44321` | ip:port | Mirai | ThreatFox | 2026-08-11 11:26:36 UTC |
| 71 (alta) | alta | `178[.]16[.]52[.]136:7707` | ip:port | AsyncRAT | ThreatFox | 2026-08-11 09:44:26 UTC |
| 70 (alta) | alta | `130[.]12[.]182[.]39:5444` | ip:port | AsyncRAT | ThreatFox | 2026-08-11 19:43:27 UTC |
| 69 (media) | media | `114[.]67[.]87[.]14:60125` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:44 UTC |
| 68 (media) | media | `222[.]213[.]23[.]56:60134` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:44 UTC |
| 68 (media) | media | `132[.]243[.]225[.]173:7080` | ip:port | Unknown malware | ThreatFox | 2026-08-11 09:39:03 UTC |
| 64 (media) | media | `47[.]236[.]146[.]147:60134` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:44 UTC |
| 63 (media) | media | `8[.]219[.]169[.]170:60119` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:46 UTC |
| 63 (media) | media | `47[.]236[.]70[.]102:60108` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:45 UTC |
| 63 (media) | media | `47[.]236[.]172[.]100:60117` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:44 UTC |
| 62 (media) | media | `hxxp://158[.]255[.]83[.]180:39837/Mozi[.]7` | url | Mozi | ThreatFox, URLhaus | 2026-08-11 19:20:22 UTC |
| 62 (media) | media | `8[.]219[.]241[.]116:60106` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:46 UTC |
| 62 (media) | media | `47[.]237[.]167[.]249:60128` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:45 UTC |
| 61 (media) | alta | `hxxp://77[.]90[.]185[.]66/wget` | url | Mirai | ThreatFox, URLhaus | 2026-08-11 19:20:25 UTC |
| 61 (media) | alta | `hxxp://77[.]90[.]185[.]66/mirai[.]mips` | url | Mirai | ThreatFox, URLhaus | 2026-08-11 19:20:25 UTC |
| 61 (media) | alta | `hxxp://77[.]90[.]185[.]66/mirai[.]mpsl` | url | Mirai | ThreatFox, URLhaus | 2026-08-11 19:20:24 UTC |
| 61 (media) | alta | `hxxp://77[.]90[.]185[.]66/mirai[.]arm` | url | Mirai | ThreatFox, URLhaus | 2026-08-11 19:20:24 UTC |
| 61 (media) | alta | `hxxp://77[.]90[.]185[.]66/mirai[.]arm5` | url | Mirai | ThreatFox, URLhaus | 2026-08-11 19:20:23 UTC |
| 61 (media) | alta | `hxxp://77[.]90[.]185[.]66/mirai[.]arm7` | url | Mirai | ThreatFox, URLhaus | 2026-08-11 19:20:23 UTC |
| 61 (media) | media | `8[.]219[.]210[.]218:60139` | ip:port | P2Pinfect | ThreatFox | 2026-08-11 12:28:46 UTC |

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
| CVE-2026-20316 | Cisco Secure Firewall Management Center (FMC) | 2026-07-29 | Unknown |
<!-- CTI:END -->
