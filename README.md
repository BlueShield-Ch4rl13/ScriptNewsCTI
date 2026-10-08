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
**Última actualización:** 2026-10-08 23:20 UTC · **IOCs recolectados:** 1500 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `178[.]16[.]53[.]56:8443` | ip:port | Aisuru | ThreatFox | 2026-10-08 05:34:09 UTC |
| 75 (alta) | alta | `178[.]16[.]53[.]59:8443` | ip:port | Aisuru | ThreatFox | 2026-10-08 05:34:18 UTC |
| 75 (alta) | alta | `178[.]16[.]53[.]59:9034` | ip:port | Aisuru | ThreatFox | 2026-10-08 05:33:56 UTC |
| 75 (alta) | alta | `178[.]16[.]53[.]56:34567` | ip:port | Aisuru | ThreatFox | 2026-10-08 05:33:56 UTC |
| 75 (alta) | alta | `178[.]16[.]53[.]59:34567` | ip:port | Aisuru | ThreatFox | 2026-10-08 05:33:53 UTC |
| 75 (alta) | alta | `62[.]212[.]79[.]67:2404` | ip:port | Remcos | ThreatFox | 2026-10-08 05:33:53 UTC |
| 74 (alta) | alta | `45[.]9[.]149[.]168:8001` | ip:port | Mirai | ThreatFox | 2026-10-08 05:33:52 UTC |
| 71 (alta) | alta | `36[.]50[.]134[.]86:80` | ip:port | Mirai | ThreatFox | 2026-10-08 19:44:56 UTC |
| 63 (media) | alta | `46[.]151[.]182[.]67:56003` | ip:port | PureRAT | ThreatFox | 2026-10-08 19:45:14 UTC |
| 62 (media) | alta | `176[.]65[.]139[.]217:1999` | ip:port | Mirai | ThreatFox | 2026-10-08 07:13:08 UTC |
| 61 (media) | media | `93[.]152[.]221[.]45:37610` | ip:port | Drifter | ThreatFox | 2026-10-08 22:52:20 UTC |
| 61 (media) | alta | `198[.]251[.]89[.]220:443` | ip:port | Unknown Stealer | ThreatFox | 2026-10-08 05:34:32 UTC |
| 60 (media) | alta | `141[.]98[.]10[.]127:14641` | ip:port | Remcos | ThreatFox | 2026-10-08 21:11:08 UTC |
| 60 (media) | media | `176[.]97[.]117[.]157:443` | ip:port | VShell | ThreatFox | 2026-10-08 21:05:13 UTC |
| 60 (media) | media | `161[.]35[.]203[.]167:7061` | ip:port | Drifter | ThreatFox | 2026-10-08 16:53:50 UTC |
| 60 (media) | media | `161[.]35[.]151[.]100:7061` | ip:port | Drifter | ThreatFox | 2026-10-08 16:53:50 UTC |
| 60 (media) | alta | `198[.]135[.]49[.]110:4489` | ip:port | Remcos | ThreatFox | 2026-10-08 05:34:31 UTC |
| 60 (media) | alta | `101[.]99[.]95[.]124:1312` | ip:port | Mirai | ThreatFox | 2026-10-08 05:33:51 UTC |
| 59 (media) | media | `93[.]152[.]221[.]45:44308` | ip:port | Drifter | ThreatFox | 2026-10-08 18:52:44 UTC |
| 59 (media) | media | `93[.]152[.]221[.]45:7061` | ip:port | Drifter | ThreatFox | 2026-10-08 15:50:39 UTC |
| 59 (media) | media | `93[.]152[.]221[.]45:36605` | ip:port | Drifter | ThreatFox | 2026-10-08 15:04:28 UTC |
| 59 (media) | critica | `120[.]76[.]143[.]184:8000` | ip:port | Cobalt Strike | ThreatFox | 2026-10-08 13:05:05 UTC |
| 59 (media) | media | `f05eea5f3134477c4b892677aea0600255b3351e9b69211f023f3d366b0b12f6` | sha256_hash | AMOS | ThreatFox | 2026-10-08 05:34:13 UTC |
| 59 (media) | media | `1b564478966dea1b542c33b6076f7b1c14eed16c558e8b25e3d9f3b84286a4ec` | sha256_hash | AMOS | ThreatFox | 2026-10-08 05:34:08 UTC |
| 59 (media) | alta | `138[.]68[.]135[.]200:8080` | ip:port | Aisuru | ThreatFox | 2026-10-08 02:47:39 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2015-5477 | ISC BIND | 2026-10-08 | Unknown |
| CVE-2016-3081 | Apache Struts | 2026-10-08 | Unknown |
| CVE-2023-22894 | Strapi Strapi | 2026-10-08 | Unknown |
| CVE-2021-3199 | ONLYOFFICE Docs | 2026-10-08 | Unknown |
| CVE-2015-3306 | ProFTPD ProFTPD | 2026-10-08 | Unknown |
| CVE-2026-88779 | Citrix NetScaler | 2026-10-04 | Unknown |
| CVE-2026-102490 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-102489 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-104286 | Fortinet FortiMail | 2026-10-01 | Unknown |
| CVE-2026-76504 | Cisco Catalyst SD-WAN Manager | 2026-09-30 | Unknown |
| CVE-2026-86950 | Apple Multiple Products | 2026-09-29 | Unknown |
| CVE-2026-88772 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-88771 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-67279 | MikroTik RouterOS | 2026-09-25 | Unknown |
| CVE-2026-65660 | Microsoft SharePoint | 2026-09-25 | Unknown |
| CVE-2026-87902 | WordPress Core | 2026-09-25 | Unknown |
| CVE-2026-5430 | WSO2 Multiple Products | 2026-09-24 | Unknown |
| CVE-2026-71362 | Adobe Commerce and Magento  | 2026-09-24 | Unknown |
<!-- CTI:END -->
