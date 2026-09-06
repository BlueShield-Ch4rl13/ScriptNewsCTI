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
**Última actualización:** 2026-09-06 10:50 UTC · **IOCs recolectados:** 1193 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | alta | `94[.]154[.]43[.]107:1999` | ip:port | Mirai | ThreatFox | 2026-09-05 11:34:50 UTC |
| 68 (media) | alta | `91[.]92[.]42[.]16:5996` | ip:port | AsyncRAT | ThreatFox | 2026-09-05 10:40:08 UTC |
| 65 (media) | alta | `158[.]94[.]208[.]19:4782` | ip:port | Quasar RAT | ThreatFox | 2026-09-05 11:34:56 UTC |
| 63 (media) | alta | `184[.]75[.]208[.]26:48988` | ip:port | Borat RAT | ThreatFox | 2026-09-06 08:20:29 UTC |
| 62 (media) | alta | `83[.]136[.]211[.]230:56001` | ip:port | PureRAT | ThreatFox | 2026-09-05 19:46:44 UTC |
| 61 (media) | media | `hxxp://27[.]222[.]48[.]192:43573/Mozi[.]a` | url | Mozi | ThreatFox, URLhaus | 2026-09-06 06:19:51 UTC |
| 61 (media) | media | `94822534ac0175c1fa967295027dd7d4cec7bc83c4dccc377636356e0a8da45e` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:12 UTC |
| 61 (media) | media | `7589b0489113b4b4a8a923fea0389fd20541fcf1f15000670772a2d2be839a41` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:05 UTC |
| 60 (media) | alta | `141[.]94[.]121[.]162:6672` | ip:port | DCRat | ThreatFox | 2026-09-06 01:05:07 UTC |
| 60 (media) | media | `869b6102fb50c5c6dcb0c03450955620f97d509dfdb57fe4d3dcfa4d3b991d69` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:11 UTC |
| 60 (media) | media | `f8be433cb61ee5129b0dc9849536a38505a0aede4678a092c1ec7472348936cb` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:09 UTC |
| 60 (media) | media | `a98ea13971d165450b31e3e0537eaf1c0ee13a46b1bd583d49ed89ba5ff5c778` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:08 UTC |
| 60 (media) | media | `a59c243fff84214cd84d176348e64449b4660b7c29fe75277b63d10d70a656a7` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:08 UTC |
| 59 (media) | media | `hxxps://jsonserv[.]biz/app-store` | url | Anubis | ThreatFox | 2026-09-05 11:34:45 UTC |
| 59 (media) | media | `4d64c5b51a42ffca925de494bc2b1230e98f4b0d6d371554e530ce054d881cdb` | sha256_hash | RemoteAdmin | ThreatFox | 2026-09-05 11:31:58 UTC |
| 58 (media) | critica | `91[.]92[.]241[.]187:4321` | ip:port | AdaptixC2 | ThreatFox | 2026-09-06 09:47:09 UTC |
| 58 (media) | alta | `31[.]70[.]81[.]171:7707` | ip:port | AsyncRAT | ThreatFox | 2026-09-05 19:45:55 UTC |
| 58 (media) | media | `df09986d46e148afe08c1e34b24ea3b81f67c1c352d387b1afcb93357e669cfb` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:12 UTC |
| 58 (media) | media | `7ed8bb73e85b210ebf8017f86785bc221688ace4321204c3b93856c5a99bf078` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:07 UTC |
| 58 (media) | media | `905b2b3bcd86200c62c4e9aa2b19706da6d437ac208fed930f7ea5d48cd8ab13` | sha256_hash | Coruna | ThreatFox | 2026-09-05 13:52:07 UTC |
| 57 (media) | critica | `91[.]92[.]241[.]184:4321` | ip:port | AdaptixC2 | ThreatFox | 2026-09-06 09:47:08 UTC |
| 57 (media) | media | `38[.]46[.]15[.]206:4141` | ip:port | VShell | ThreatFox | 2026-09-06 09:05:05 UTC |
| 57 (media) | critica | `223[.]109[.]142[.]7:22` | ip:port | Cobalt Strike | ThreatFox | 2026-09-06 01:05:05 UTC |
| 57 (media) | media | `111[.]170[.]148[.]132:5674` | ip:port | Unknown malware | ThreatFox | 2026-09-05 19:05:04 UTC |
| 57 (media) | alta | `58[.]181[.]61[.]142:7746` | ip:port | Ghost RAT | ThreatFox | 2026-09-05 19:00:10 UTC |

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
<!-- CTI:END -->
