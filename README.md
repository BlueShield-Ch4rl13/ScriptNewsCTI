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
**Última actualización:** 2026-09-03 04:04 UTC · **IOCs recolectados:** 1112 · **CVEs KEV recientes:** 23

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `94[.]154[.]43[.]69:7768` | ip:port | Mirai | ThreatFox | 2026-09-02 17:45:10 UTC |
| 73 (alta) | media | `68[.]233[.]116[.]124:22` | ip:port | XMRIG | ThreatFox | 2026-09-02 07:10:52 UTC |
| 73 (alta) | media | `43[.]156[.]71[.]43:22` | ip:port | XMRIG | ThreatFox | 2026-09-02 07:10:52 UTC |
| 72 (alta) | critica | `85[.]120[.]216[.]8:4321` | ip:port | AdaptixC2 | ThreatFox | 2026-09-02 09:46:57 UTC |
| 72 (alta) | alta | `b75ee9270008a9a46f28f0b41738b138bbb7d89cd964acb3570cffb42fc81a05` | sha256_hash | XWorm | ThreatFox | 2026-09-02 09:22:29 UTC |
| 72 (alta) | media | `103[.]105[.]67[.]170:22` | ip:port | XMRIG | ThreatFox | 2026-09-02 07:10:51 UTC |
| 70 (alta) | alta | `51aed28d3468de5e75addc467ba14389356afe896098e4e478efcd7bf79a65b9` | sha256_hash | Ghost RAT | ThreatFox | 2026-09-02 09:22:29 UTC |
| 68 (media) | media | `45[.]148[.]10[.]133:443` | ip:port | Unknown malware | ThreatFox | 2026-09-02 08:18:07 UTC |
| 67 (media) | media | `46c75a86d2493710bd827e4ff84f7d6412d53ba9d8c4fc8e844de8af338c88ee` | sha256_hash | Rozena | ThreatFox | 2026-09-02 09:22:28 UTC |
| 67 (media) | alta | `bd113d6b2cfba5ab2780c313c01d87896c64f91376903efc62ba01a242f59327` | sha256_hash | Ghost RAT | ThreatFox | 2026-09-02 09:22:27 UTC |
| 66 (media) | alta | `2772367ba92f56742707532f951856c2525f31c8ca0a92412e957774b7c90e21` | sha256_hash | PureLogs Stealer | ThreatFox | 2026-09-02 09:22:28 UTC |
| 66 (media) | alta | `213[.]152[.]162[.]116:49006` | ip:port | Remcos | ThreatFox | 2026-09-02 07:10:46 UTC |
| 61 (media) | alta | `91[.]193[.]7[.]186:48988` | ip:port | Unknown RAT | ThreatFox | 2026-09-02 08:12:49 UTC |
| 59 (media) | alta | `217[.]60[.]195[.]33:17545` | ip:port | Remcos | ThreatFox | 2026-09-03 01:11:15 UTC |
| 59 (media) | alta | `54[.]37[.]128[.]55:5000` | ip:port | Remcos | ThreatFox | 2026-09-02 05:49:54 UTC |
| 57 (media) | alta | `178[.]128[.]173[.]150:9034` | ip:port | Aisuru | ThreatFox | 2026-09-03 01:41:19 UTC |
| 57 (media) | alta | `176[.]98[.]182[.]217:5555` | ip:port | Aisuru | ThreatFox | 2026-09-02 19:46:26 UTC |
| 57 (media) | alta | `hxxp://loveher[.]dpdns[.]org` | url | Mirai | ThreatFox | 2026-09-02 18:06:37 UTC |
| 57 (media) | alta | `176[.]98[.]182[.]218:37215` | ip:port | Aisuru | ThreatFox | 2026-09-02 14:52:36 UTC |
| 57 (media) | media | `43[.]155[.]168[.]253:59527` | ip:port | Unknown malware | ThreatFox | 2026-09-02 14:05:05 UTC |
| 56 (media) | alta | `188[.]166[.]146[.]72:8080` | ip:port | Aisuru | ThreatFox | 2026-09-03 03:50:24 UTC |
| 56 (media) | alta | `157[.]245[.]242[.]229:8443` | ip:port | Aisuru | ThreatFox | 2026-09-03 01:56:33 UTC |
| 56 (media) | alta | `shop-heroup[.]com` | domain | ClearFake | ThreatFox | 2026-09-03 01:50:06 UTC |
| 56 (media) | alta | `rpmjgjea[.]usa-denta-vive[.]com` | domain | ClearFake | ThreatFox | 2026-09-03 01:37:52 UTC |
| 56 (media) | alta | `usa-denta-vive[.]com` | domain | ClearFake | ThreatFox | 2026-09-03 01:35:42 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-72530 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-72529 | TrueConf Server | 2026-08-20 | Unknown |
<!-- CTI:END -->
