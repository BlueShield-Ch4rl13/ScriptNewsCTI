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
**Última actualización:** 2026-10-01 05:25 UTC · **IOCs recolectados:** 1273 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `94[.]154[.]43[.]84:8900` | ip:port | Unknown malware | ThreatFox | 2026-09-30 14:49:48 UTC |
| 75 (alta) | media | `94[.]154[.]43[.]84:7000` | ip:port | Unknown malware | ThreatFox | 2026-09-30 14:49:47 UTC |
| 75 (alta) | media | `94[.]154[.]43[.]84:9000` | ip:port | Unknown malware | ThreatFox | 2026-09-30 14:49:47 UTC |
| 75 (alta) | critica | `158[.]94[.]209[.]12:8444` | ip:port | AdaptixC2 | ThreatFox | 2026-09-30 06:02:27 UTC |
| 73 (alta) | alta | `176[.]65[.]139[.]196:18129` | ip:port | Mirai | ThreatFox | 2026-10-01 04:15:29 UTC |
| 72 (alta) | alta | `209[.]126[.]103[.]97:1791` | ip:port | Mirai | ThreatFox | 2026-09-30 14:49:39 UTC |
| 72 (alta) | media | `0f4f26d4e4b73735e19f147751fb0cc3678aa74b2113f8f1405f3ab0145238fd` | sha256_hash | VShell | ThreatFox | 2026-09-30 12:21:51 UTC |
| 71 (alta) | media | `91[.]92[.]40[.]130:9999` | ip:port | Unknown malware | ThreatFox | 2026-10-01 03:39:44 UTC |
| 71 (alta) | alta | `160[.]119[.]66[.]206:25565` | ip:port | Mirai | ThreatFox | 2026-09-30 23:12:57 UTC |
| 70 (alta) | alta | `3797d5082f3612a2493ce6430ed09a61922573f6871401f95b0d2e735a12ada1` | sha256_hash | Remcos | ThreatFox | 2026-09-30 11:08:14 UTC |
| 69 (media) | alta | `05167be9a9fb578c118ac1e19e50f0d6aa000f5b89ee75d3ad17659743b6e720` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:15 UTC |
| 69 (media) | alta | `c45d173921af4cf37428f2b7421ddbce53edb50984cec2c8253acab50886a9c8` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:13 UTC |
| 69 (media) | alta | `9b81c8610579aaf75abc4e0fb27facd5d28d8c653529c2a78836db384dc881cb` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:03 UTC |
| 69 (media) | media | `d135fd8610833b6961936ba31f8feb2fd97efd1a0f5b6d4e333301e94531a3ba` | sha256_hash | VShell | ThreatFox | 2026-09-30 11:08:12 UTC |
| 69 (media) | alta | `3fd8de4fd28f7bdc4b5d428693f45d2a867bb6177e9b0f5c6f59cc8a71c75363` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:48:40 UTC |
| 69 (media) | alta | `6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:48:39 UTC |
| 68 (media) | alta | `0fa67b39ead99a4f38e615c3a826a9b2c475447f13551f1fbe74bca1d400fe0a` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:14 UTC |
| 68 (media) | alta | `9e76638abff0771722e96a36d325cc0d79415afa78c94e3574bdc56823676a50` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:11 UTC |
| 68 (media) | alta | `2f20d4fa8ddd61b5db84c4522c7fee71814451b2e92da1ad1ed602f7c736ca8a` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:10 UTC |
| 68 (media) | alta | `6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:08 UTC |
| 68 (media) | alta | `4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:06 UTC |
| 68 (media) | alta | `a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:05 UTC |
| 68 (media) | alta | `f887fa2ee5b9a665ae0431430ef8ee7d10732dcc93650d1d93bc471cddef7e12` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:02 UTC |
| 68 (media) | alta | `e30c68a5d14048c44c94676561a0fa2d15bc2fc205daad34da42ac3ee8c263ca` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:01 UTC |
| 68 (media) | alta | `addadfa7b754b16fc51effb4110a9e6e2f8f9f9b62689a70a7492ced18b0ad29` | sha256_hash | Mirai | ThreatFox | 2026-10-01 03:39:26 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-76504 | Cisco Catalyst SD-WAN Manager | 2026-09-30 | Unknown |
| CVE-2026-86950 | Apple Multiple Products | 2026-09-29 | Unknown |
| CVE-2026-88772 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-88771 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-67279 | MikroTik RouterOS | 2026-09-25 | Unknown |
| CVE-2026-65660 | Microsoft SharePoint | 2026-09-25 | Unknown |
| CVE-2026-87902 | WordPress Core | 2026-09-25 | Unknown |
| CVE-2026-5430 | WSO2 Multiple Products | 2026-09-24 | Unknown |
| CVE-2026-71362 | Adobe Commerce and Magento  | 2026-09-24 | Unknown |
| CVE-2026-93952 | Arista VeloCloud Orchestrator | 2026-09-22 | Unknown |
| CVE-2026-94127 | F5 BIG-IP APM | 2026-09-22 | Unknown |
| CVE-2026-93616 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-85102 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-7273 | Zyxel GS1900 Series Switches | 2026-09-21 | Unknown |
| CVE-2025-39964 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-53266 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2025-39682 | Linux Kernel | 2026-09-18 | Unknown |
<!-- CTI:END -->
