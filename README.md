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
**Última actualización:** 2026-09-04 20:46 UTC · **IOCs recolectados:** 798 · **CVEs KEV recientes:** 22

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | alta | `94[.]154[.]43[.]88:4330` | ip:port | Mirai | ThreatFox | 2026-09-04 07:19:41 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]88:44321` | ip:port | Mirai | ThreatFox | 2026-09-04 07:19:40 UTC |
| 71 (alta) | media | `94[.]154[.]43[.]107:9111` | ip:port | Unknown malware | ThreatFox | 2026-09-04 11:29:44 UTC |
| 71 (alta) | alta | `213[.]152[.]162[.]118:49006` | ip:port | Remcos | ThreatFox | 2026-09-04 06:42:43 UTC |
| 69 (media) | alta | `e2b4438f72c986add83c9d96d5aa46f7` | md5_hash | Agent Tesla | ThreatFox | 2026-09-04 00:46:11 UTC |
| 68 (media) | alta | `195[.]177[.]94[.]11:56001` | ip:port | PureRAT | ThreatFox | 2026-09-04 19:44:56 UTC |
| 68 (media) | alta | `195[.]177[.]94[.]11:56002` | ip:port | PureRAT | ThreatFox | 2026-09-04 19:44:56 UTC |
| 64 (media) | alta | `ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4` | sha256_hash | Vidar | ThreatFox | 2026-09-04 00:46:12 UTC |
| 64 (media) | alta | `ad630836facc7b850ea1b91dfda96bf1cc2f3803` | sha1_hash | Vidar | ThreatFox | 2026-09-04 00:46:12 UTC |
| 64 (media) | alta | `afee8b1b35405c2cbf5be6ea4d515561` | md5_hash | Vidar | ThreatFox | 2026-09-04 00:46:12 UTC |
| 62 (media) | media | `156[.]247[.]40[.]242:888` | ip:port | Unknown malware | ThreatFox | 2026-09-04 15:08:56 UTC |
| 61 (media) | media | `hxxp://39[.]88[.]200[.]53:34933/Mozi[.]m` | url | Mozi | ThreatFox, URLhaus | 2026-09-04 12:36:58 UTC |
| 61 (media) | alta | `17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1` | sha256_hash | Vidar | ThreatFox | 2026-09-04 00:46:13 UTC |
| 61 (media) | alta | `47d1583b884244b3f0134d7934d3a3a713001d6c` | sha1_hash | Vidar | ThreatFox | 2026-09-04 00:46:13 UTC |
| 61 (media) | alta | `4ccdc8b931c809bbeac91f5f6c682c71` | md5_hash | Vidar | ThreatFox | 2026-09-04 00:46:13 UTC |
| 60 (media) | alta | `2a132bc5b6cb45f2d5c3b12814e638c6` | md5_hash | Vidar | ThreatFox | 2026-09-04 00:46:12 UTC |
| 59 (media) | media | `4d64c5b51a42ffca925de494bc2b1230e98f4b0d6d371554e530ce054d881cdb` | sha256_hash | RemoteAdmin | ThreatFox | 2026-09-04 19:58:30 UTC |
| 59 (media) | media | `immersionzone[.]info` | domain | IClickFix | ThreatFox | 2026-09-04 03:46:06 UTC |
| 57 (media) | alta | `176[.]98[.]182[.]216:12345` | ip:port | Aisuru | ThreatFox | 2026-09-04 06:42:47 UTC |
| 56 (media) | alta | `87[.]120[.]244[.]219:2020` | ip:port | Remcos | ThreatFox | 2026-09-04 20:26:12 UTC |
| 56 (media) | alta | `sla[.]sm188dvlv[.]mom` | domain | Vidar | ThreatFox | 2026-09-04 15:25:45 UTC |
| 56 (media) | alta | `sla[.]13balien[.]org` | domain | Vidar | ThreatFox | 2026-09-04 15:20:45 UTC |
| 56 (media) | alta | `r9chaxy2[.]pura--boost[.]us` | domain | ClearFake | ThreatFox | 2026-09-04 14:49:32 UTC |
| 56 (media) | alta | `wolf[.]albaikmenuonline[.]com` | domain | ClearFake | ThreatFox | 2026-09-04 13:57:42 UTC |
| 56 (media) | alta | `3xoi10iy[.]usen-glucotrust-bites[.]com` | domain | ClearFake | ThreatFox | 2026-09-04 10:48:26 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-85046 | Google Chromium V8 | 2026-09-04 | Unknown |
| CVE-2026-59822 | BerriAI LiteLLM | 2026-09-02 | Unknown |
| CVE-2026-48710 | Kludex Starlette | 2026-09-02 | Unknown |
| CVE-2026-49869 | Kestra Kestra OSS | 2026-09-02 | Unknown |
| CVE-2026-82329 | JFrog Artifactory | 2026-09-02 | Unknown |
| CVE-2026-9586 | Sangoma Switchvox | 2026-09-02 | Unknown |
| CVE-2026-83548 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-83549 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-82078 | PaperCut NG/MF | 2026-08-31 | Unknown |
| CVE-2026-81578 | PaperCut NG/MF | 2026-08-31 | Unknown |
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
<!-- CTI:END -->
