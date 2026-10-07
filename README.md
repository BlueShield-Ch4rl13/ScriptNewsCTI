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
**Última actualización:** 2026-10-07 05:32 UTC · **IOCs recolectados:** 292 · **CVEs KEV recientes:** 13

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 44 (media) | media | `hxxp://95[.]9[.]35[.]137:40441/i` | url | malware_download | URLhaus | 2026-10-07 04:55:51 UTC |
| 44 (media) | media | `hxxp://123[.]12[.]245[.]227:36522/bin[.]sh` | url | malware_download | URLhaus | 2026-10-07 04:41:16 UTC |
| 43 (media) | media | `hxxp://185[.]89[.]156[.]101:35112/bin[.]sh` | url | malware_download | URLhaus | 2026-10-07 04:55:36 UTC |
| 42 (media) | media | `hxxps://stellaspicy[.]org/2026scrill/client[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:53 UTC |
| 42 (media) | media | `hxxps://donutclients[.]st/Shulker_Box_Tooltip-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:31 UTC |
| 42 (media) | media | `hxxp://182[.]121[.]16[.]69:49873/Mozi[.]m` | url | malware_download | URLhaus | 2026-10-07 04:41:28 UTC |
| 42 (media) | media | `hxxps://donutclients[.]st/Mouse_Tweaks-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:13 UTC |
| 42 (media) | media | `hxxps://donutclients[.]st/appleskin-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:12 UTC |
| 42 (media) | media | `hxxps://donutclients[.]st/ZincAddons-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:11 UTC |
| 42 (media) | media | `hxxps://donutclients[.]st/Sodium-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:11 UTC |
| 42 (media) | media | `hxxps://donutdupe[.]com/DonutDupe-1[.]21[.]11[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:10 UTC |
| 41 (media) | media | `hxxp://119[.]187[.]197[.]115:57303/i` | url | malware_download | URLhaus | 2026-10-07 05:02:35 UTC |
| 41 (media) | media | `hxxp://123[.]9[.]200[.]156:42154/i` | url | malware_download | URLhaus | 2026-10-07 05:02:35 UTC |
| 41 (media) | media | `hxxps://donutclients[.]st/TotemCounter-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:55:41 UTC |
| 41 (media) | media | `hxxp://115[.]62[.]186[.]251:52572/i` | url | malware_download | URLhaus | 2026-10-07 04:55:39 UTC |
| 41 (media) | media | `hxxp://154[.]242[.]13[.]34:43259/i` | url | malware_download | URLhaus | 2026-10-07 04:55:39 UTC |
| 41 (media) | media | `hxxp://115[.]55[.]229[.]99:46995/i` | url | malware_download | URLhaus | 2026-10-07 04:55:38 UTC |
| 41 (media) | media | `hxxps://xiazailianjie[.]com/WPS_Setup_X64[.]zip` | url | malware_download | URLhaus | 2026-10-07 04:49:18 UTC |
| 41 (media) | media | `hxxps://donutclients[.]st/alycone-client-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:31 UTC |
| 41 (media) | media | `hxxps://donutclients[.]st/radium-client-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:31 UTC |
| 41 (media) | media | `hxxps://donutclients[.]st/krypton-client-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:31 UTC |
| 41 (media) | media | `hxxps://stellaspicy[.]org/2026scrill/RuneLite[.]exe` | url | malware_download | URLhaus | 2026-10-07 04:41:31 UTC |
| 41 (media) | media | `hxxp://23[.]254[.]195[.]48:8099/beacon_x` | url | malware_download | URLhaus | 2026-10-07 04:41:31 UTC |
| 41 (media) | media | `hxxps://donutclients[.]st/gamble-rig-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:30 UTC |
| 41 (media) | media | `hxxps://donutclients[.]st/Radon-Client-26[.]2[.]jar` | url | malware_download | URLhaus | 2026-10-07 04:41:22 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
