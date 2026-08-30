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
**Última actualización:** 2026-08-30 20:55 UTC · **IOCs recolectados:** 678 · **CVEs KEV recientes:** 20

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 71 (alta) | alta | `45[.]225[.]135[.]156:56003` | ip:port | PureRAT | ThreatFox | 2026-08-30 19:45:59 UTC |
| 66 (media) | alta | `a1bde6f032dc7452a8e447e9750a3b14a1e5c7e3803420e8919831fe67b338b7` | sha256_hash | Vidar | ThreatFox | 2026-08-30 01:34:48 UTC |
| 66 (media) | alta | `3dd25cbfe76db155615283f905992030468f3da9` | sha1_hash | Vidar | ThreatFox | 2026-08-30 01:34:48 UTC |
| 66 (media) | alta | `fb472c15a793251aeeb03b38bd4a678f` | md5_hash | Vidar | ThreatFox | 2026-08-30 01:34:48 UTC |
| 66 (media) | alta | `8bbbf6e8040d137c142bbf1775be770c` | md5_hash | Vidar | ThreatFox | 2026-08-30 01:34:45 UTC |
| 66 (media) | alta | `db4a45d88c943be3f60bf216bb6ac8a2d3b70dfa13e9669e402f11e2aaea1b74` | sha256_hash | Vidar | ThreatFox | 2026-08-30 01:34:44 UTC |
| 66 (media) | alta | `0d5f36f78a1cbf922f9e33c348c5693e93e24c06` | sha1_hash | Vidar | ThreatFox | 2026-08-30 01:34:44 UTC |
| 63 (media) | media | `160[.]250[.]128[.]197:80` | ip:port | Unknown malware | ThreatFox | 2026-08-30 14:05:08 UTC |
| 61 (media) | alta | `167[.]99[.]194[.]254:9035` | ip:port | Aisuru | ThreatFox | 2026-08-30 07:09:26 UTC |
| 59 (media) | media | `64[.]89[.]160[.]222:65481` | ip:port | Bashlite | ThreatFox | 2026-08-30 10:43:05 UTC |
| 58 (media) | alta | `165[.]22[.]122[.]89:9034` | ip:port | Aisuru | ThreatFox | 2026-08-30 07:09:35 UTC |
| 57 (media) | media | `106[.]53[.]172[.]234:30092` | ip:port | VShell | ThreatFox | 2026-08-30 14:05:07 UTC |
| 57 (media) | alta | `46[.]101[.]179[.]59:9034` | ip:port | Aisuru | ThreatFox | 2026-08-30 11:55:39 UTC |
| 57 (media) | alta | `104[.]248[.]247[.]126:9034` | ip:port | Aisuru | ThreatFox | 2026-08-30 07:09:28 UTC |
| 57 (media) | alta | `134[.]122[.]185[.]201:6685` | ip:port | ValleyRAT | ThreatFox | 2026-08-30 04:25:13 UTC |
| 57 (media) | alta | `134[.]122[.]185[.]201:6698` | ip:port | ValleyRAT | ThreatFox | 2026-08-30 04:25:09 UTC |
| 56 (media) | alta | `29l1b9y1[.]shop-aeroslim[.]us` | domain | ClearFake | ThreatFox | 2026-08-30 20:40:43 UTC |
| 56 (media) | alta | `hxxp://cc893886[.]tw1[.]ru/L1nc0In[.]php` | url | DCRat | ThreatFox | 2026-08-30 20:05:04 UTC |
| 56 (media) | alta | `167[.]99[.]128[.]245:8080` | ip:port | Aisuru | ThreatFox | 2026-08-30 19:52:17 UTC |
| 56 (media) | alta | `167[.]99[.]128[.]245:8443` | ip:port | Aisuru | ThreatFox | 2026-08-30 17:39:56 UTC |
| 56 (media) | alta | `159[.]89[.]24[.]55:9034` | ip:port | Aisuru | ThreatFox | 2026-08-30 17:39:55 UTC |
| 56 (media) | alta | `hxxps://zca[.]12naga[.]org` | url | Vidar | ThreatFox | 2026-08-30 17:39:54 UTC |
| 56 (media) | media | `hxxp://zonxh[.]shop:7728/reports` | url | Remus | ThreatFox | 2026-08-30 15:55:19 UTC |
| 56 (media) | media | `hxxp://kupzovo[.]shop:7567/reports` | url | Remus | ThreatFox | 2026-08-30 15:55:16 UTC |
| 56 (media) | critica | `121[.]127[.]253[.]146:4444` | ip:port | AdaptixC2 | ThreatFox | 2026-08-30 14:05:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2023-49105 | ownCloud ownCloud | 2026-08-27 | Unknown |
| CVE-2026-53362 | Linux Kernel | 2026-08-27 | Unknown |
| CVE-2026-66384 | JFrog Artifactory | 2026-08-27 | Unknown |
| CVE-2021-23758 | Ajax.NET Professional Ajax.NET Professional | 2026-08-26 | Unknown |
| CVE-2015-3246 | Red Hat Libuser | 2026-08-26 | Unknown |
| CVE-2015-5287 | Red Hat Automatic Bug Reporting Tool | 2026-08-26 | Unknown |
| CVE-2022-0995 | Linux Kernel | 2026-08-26 | Unknown |
| CVE-2026-8452 | Citrix NetScaler ADC and NetScaler Gateway | 2026-08-26 | Unknown |
| CVE-2019-1068 | Microsoft SQL Server | 2026-08-26 | Unknown |
| CVE-2026-60004 | Gitea Gitea | 2026-08-25 | Unknown |
| CVE-2026-21962 | Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in | 2026-08-24 | Unknown |
| CVE-2026-73570 | Synacor Zimbra Collaboration Suite (ZCS) | 2026-08-21 | Unknown |
| CVE-2026-72530 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-72529 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-64849 | MLflow MLflow | 2026-08-19 | Unknown |
| CVE-2026-33824 | Microsoft Internet Key Exchange (IKE) Service Extensions | 2026-08-18 | Unknown |
| CVE-2026-59310 | Broadcom VMware vCenter | 2026-08-18 | Unknown |
| CVE-2026-55040 | Microsoft SharePoint | 2026-08-18 | Unknown |
| CVE-2026-65400 | Apple macOS | 2026-08-18 | Unknown |
| CVE-2025-62593 | Ray-Project Ray | 2026-08-17 | Unknown |
<!-- CTI:END -->
