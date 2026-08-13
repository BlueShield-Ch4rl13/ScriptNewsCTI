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
**Última actualización:** 2026-08-13 19:19 UTC · **IOCs recolectados:** 855 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `3966dfc023858b3f3bd6aca6562964838aaa2e31` | sha1_hash | Nanocore RAT | ThreatFox | 2026-08-13 13:09:55 UTC |
| 76 (alta) | alta | `7d4dcace32850c5e3e9d5dff5a6ef08d` | md5_hash | Nanocore RAT | ThreatFox | 2026-08-13 13:09:55 UTC |
| 76 (alta) | alta | `4208d5e8fe67a312095ee467a08bd0d6ec6007f10922d03383e760b40e0e1dc9` | sha256_hash | Nanocore RAT | ThreatFox | 2026-08-13 13:09:54 UTC |
| 69 (media) | media | `687e3c588e1d0482e8aae96a9ee780fe534dde01` | sha1_hash | Void | ThreatFox | 2026-08-13 13:09:48 UTC |
| 69 (media) | media | `36612c13573375fb4c796f3569eb50c0` | md5_hash | Void | ThreatFox | 2026-08-13 13:09:48 UTC |
| 69 (media) | media | `d0319eb0aad677d46a509fdcdf2c03e7c92cee9794cee70a79d3e84c564708c0` | sha256_hash | Void | ThreatFox | 2026-08-13 13:09:47 UTC |
| 69 (media) | alta | `130[.]12[.]182[.]39:2500` | ip:port | AsyncRAT | ThreatFox | 2026-08-13 09:43:32 UTC |
| 68 (media) | alta | `3bb888cb49563f907b4b1305cd3c6a1eff227a5a` | sha1_hash | KrakenKeylogger | ThreatFox | 2026-08-13 13:09:53 UTC |
| 68 (media) | alta | `f0227e480e845b98b91e385b898e9b47` | md5_hash | KrakenKeylogger | ThreatFox | 2026-08-13 13:09:53 UTC |
| 68 (media) | alta | `c9548996fd7c80f449b61ab4706dce3d35307aa7215c8ff82788a513d6789e2d` | sha256_hash | KrakenKeylogger | ThreatFox | 2026-08-13 13:09:52 UTC |
| 67 (media) | critica | `93[.]152[.]223[.]39:9443` | ip:port | Havoc | ThreatFox | 2026-08-13 06:48:22 UTC |
| 67 (media) | critica | `93[.]152[.]223[.]39:8089` | ip:port | Havoc | ThreatFox | 2026-08-12 22:05:07 UTC |
| 66 (media) | alta | `695fe5d40398a4f75c5125cffeb5bb1ab2117040` | sha1_hash | AsyncRAT | ThreatFox | 2026-08-13 13:09:46 UTC |
| 66 (media) | alta | `1bb0a4abcc83dd82f0c7da52ce5d9e8a` | md5_hash | AsyncRAT | ThreatFox | 2026-08-13 13:09:46 UTC |
| 66 (media) | alta | `e87d14fd46969a5a2341482f1e1082f00a84520b9d6fe7138807584c83a25269` | sha256_hash | AsyncRAT | ThreatFox | 2026-08-13 13:09:45 UTC |
| 64 (media) | alta | `8ad256c5b786abb5f1552d906df3482a` | md5_hash | Quasar RAT | ThreatFox | 2026-08-13 13:09:52 UTC |
| 64 (media) | alta | `b3c2f9ac068664bb861d7f8a59db533810032bc26d75fad48dbd0e2ba26413b2` | sha256_hash | Quasar RAT | ThreatFox | 2026-08-13 13:09:51 UTC |
| 64 (media) | alta | `c321593cb3d8e279dfbdcf6d8bb94fac93cdc405` | sha1_hash | Quasar RAT | ThreatFox | 2026-08-13 13:09:51 UTC |
| 63 (media) | critica | `159[.]203[.]165[.]107:8080` | ip:port | AdaptixC2 | ThreatFox | 2026-08-13 14:05:05 UTC |
| 62 (media) | alta | `hxxps://cloud-flare-authenticator[.]link/` | url | Stealc | ThreatFox | 2026-08-13 05:53:09 UTC |
| 61 (media) | critica | `101[.]42[.]255[.]92:8443` | ip:port | Cobalt Strike | ThreatFox | 2026-08-13 17:05:06 UTC |
| 61 (media) | media | `0578ccbe64ee7f6c1f90cf656095dad7059b1587` | sha1_hash | NetWire RC | ThreatFox | 2026-08-13 13:09:50 UTC |
| 61 (media) | media | `6ff68578110de0105fc3a1a1ab635dd3` | md5_hash | NetWire RC | ThreatFox | 2026-08-13 13:09:50 UTC |
| 61 (media) | media | `46da9bf913828dfdc3cbfc435e414285ba5cb715` | sha1_hash | NetWire RC | ThreatFox | 2026-08-13 13:09:49 UTC |
| 61 (media) | media | `ef5b6211a47d0bec3ddb8d77b9c9586a` | md5_hash | NetWire RC | ThreatFox | 2026-08-13 13:09:49 UTC |

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
