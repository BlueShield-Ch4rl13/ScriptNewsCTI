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
**Última actualización:** 2026-09-01 16:33 UTC · **IOCs recolectados:** 950 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | critica | `109[.]233[.]21[.]109:31337` | ip:port | Sliver | ThreatFox | 2026-09-01 13:37:12 UTC |
| 71 (alta) | media | `64[.]89[.]163[.]22:9000` | ip:port | Unknown malware | ThreatFox | 2026-09-01 05:16:22 UTC |
| 70 (alta) | alta | `91[.]92[.]42[.]115:2418` | ip:port | Remcos | ThreatFox | 2026-09-01 05:11:52 UTC |
| 63 (media) | alta | `ea7d601bfe326ab75da0c8f597a2f161b3b23dbc` | sha1_hash | Vidar | ThreatFox | 2026-09-01 01:41:23 UTC |
| 63 (media) | alta | `6ff791183aa5afb344d75f98369a4612` | md5_hash | Vidar | ThreatFox | 2026-09-01 01:41:23 UTC |
| 63 (media) | alta | `5df4e83737ada213b9d0ebd4c10cd133a51a58651eef0c16a6d855427f3f91e2` | sha256_hash | Vidar | ThreatFox | 2026-09-01 01:41:22 UTC |
| 62 (media) | alta | `68bbb1ec14eca9697d31887f35e5d378c40294316273659f766705a7989b5f5a` | sha256_hash | Vidar | ThreatFox | 2026-09-01 01:41:22 UTC |
| 62 (media) | alta | `c1cedc0a39636edb00504b28615cd3f7570e9ef2` | sha1_hash | Vidar | ThreatFox | 2026-09-01 01:41:22 UTC |
| 62 (media) | alta | `71ed0c438010f5a1175e0aecf651f11f` | md5_hash | Vidar | ThreatFox | 2026-09-01 01:41:22 UTC |
| 60 (media) | alta | `64[.]89[.]160[.]127:2891` | ip:port | Remcos | ThreatFox | 2026-09-01 10:52:18 UTC |
| 59 (media) | media | `117[.]72[.]202[.]93:81` | ip:port | Unknown malware | ThreatFox | 2026-09-01 14:05:08 UTC |
| 59 (media) | media | `218[.]244[.]142[.]4:8084` | ip:port | VShell | ThreatFox | 2026-09-01 03:05:05 UTC |
| 58 (media) | alta | `102[.]220[.]160[.]198:5444` | ip:port | AsyncRAT | ThreatFox | 2026-09-01 14:05:06 UTC |
| 58 (media) | alta | `195[.]177[.]94[.]101:110` | ip:port | AsyncRAT | ThreatFox | 2026-09-01 10:05:08 UTC |
| 58 (media) | alta | `134[.]209[.]176[.]36:8080` | ip:port | Aisuru | ThreatFox | 2026-09-01 05:11:49 UTC |
| 58 (media) | alta | `07ddbbe2c71c45577a7a4fbcdba0df91` | md5_hash | ValleyRAT | ThreatFox, OTX | 2026-08-31 17:54:04 UTC |
| 58 (media) | alta | `8a626d844943da3456b044f38deae3a2` | md5_hash | ValleyRAT | ThreatFox, OTX | 2026-08-31 17:54:03 UTC |
| 58 (media) | alta | `c24e99f9437feacaa63766a3cde3fe3d` | md5_hash | ValleyRAT | ThreatFox, OTX | 2026-08-31 17:54:03 UTC |
| 57 (media) | critica | `23[.]94[.]145[.]203:31337` | ip:port | Sliver | ThreatFox | 2026-09-01 13:38:59 UTC |
| 57 (media) | alta | `176[.]98[.]182[.]218:12345` | ip:port | Aisuru | ThreatFox | 2026-09-01 11:33:28 UTC |
| 57 (media) | alta | `104[.]254[.]90[.]162:28471` | ip:port | PureRAT | ThreatFox | 2026-09-01 07:22:54 UTC |
| 57 (media) | alta | `178[.]128[.]201[.]199:8080` | ip:port | Aisuru | ThreatFox | 2026-09-01 05:11:46 UTC |
| 57 (media) | alta | `178[.]128[.]201[.]199:8443` | ip:port | Aisuru | ThreatFox | 2026-09-01 05:11:40 UTC |
| 57 (media) | media | `45[.]221[.]118[.]139:8085` | ip:port | VShell | ThreatFox | 2026-09-01 02:05:06 UTC |
| 57 (media) | critica | `137[.]220[.]151[.]95:2096` | ip:port | Cobalt Strike | ThreatFox | 2026-08-31 21:05:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-72530 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-72529 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-64849 | MLflow MLflow | 2026-08-19 | Unknown |
| CVE-2026-33824 | Microsoft Internet Key Exchange (IKE) Service Extensions | 2026-08-18 | Unknown |
| CVE-2026-59310 | Broadcom VMware vCenter | 2026-08-18 | Unknown |
| CVE-2026-55040 | Microsoft SharePoint | 2026-08-18 | Unknown |
| CVE-2026-65400 | Apple macOS | 2026-08-18 | Unknown |
<!-- CTI:END -->
