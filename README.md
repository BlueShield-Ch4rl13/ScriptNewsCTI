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
**Última actualización:** 2026-10-04 12:16 UTC · **IOCs recolectados:** 1871 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | alta | `178[.]132[.]198[.]200:443` | ip:port | Mirai | ThreatFox | 2026-10-04 06:54:53 UTC |
| 71 (alta) | media | `94[.]154[.]43[.]214:1420` | ip:port | Unknown malware | ThreatFox | 2026-10-03 18:44:28 UTC |
| 71 (alta) | media | `103[.]77[.]246[.]150:9999` | ip:port | Unknown malware | ThreatFox | 2026-10-03 18:44:26 UTC |
| 71 (alta) | media | `176[.]65[.]134[.]121:6881` | ip:port | Bashlite | ThreatFox | 2026-10-03 18:44:26 UTC |
| 71 (alta) | media | `7b254af99efa15b124d9133e32d22244c57076c9bcfdfb01b155d369e0d47aa1` | sha256_hash | GCleaner | ThreatFox | 2026-10-03 15:46:24 UTC |
| 71 (alta) | alta | `73b7ca405b8005fd5d2533f2ac288ec0e37d47c8836c34ddab14c25b4b02927b` | sha256_hash | Mirai | ThreatFox | 2026-10-03 15:46:18 UTC |
| 70 (alta) | alta | `2babd1fc3d1a79ff0d296740c1b833a7f80bf86c483c47defa5910871b7a4d94` | sha256_hash | Mirai | ThreatFox | 2026-10-03 15:46:19 UTC |
| 70 (alta) | alta | `6d7a05a732e07fb850e0097395fa87c73287a06b0868e783c29f4f5fbeb3deaa` | sha256_hash | Mirai | ThreatFox | 2026-10-03 15:46:15 UTC |
| 69 (media) | alta | `2317a73814d8e77d392377e7779963a10e283e50bb66a4d7428e833560d62292` | sha256_hash | Mirai | ThreatFox | 2026-10-03 20:46:52 UTC |
| 69 (media) | alta | `699848a33a1808fe612ce4e2e1f1bb292546509b3939c56b6842e315ad02d731` | sha256_hash | Mirai | ThreatFox | 2026-10-03 20:46:51 UTC |
| 69 (media) | alta | `a574397f2edd591ba6a55abe63323f5022bd26996bd3fbecb36cc946215abce1` | sha256_hash | Mirai | ThreatFox | 2026-10-03 15:46:14 UTC |
| 68 (media) | alta | `f96215c68cbb8bad180587fb89c2d9bccff554694a5ce2a2209ff8c19f16b8e1` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:46 UTC |
| 68 (media) | alta | `d6dbc73627d0b1a9beec2e114c85ef4fd2788262dbe6796f4b803b6daccd3231` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:45 UTC |
| 68 (media) | alta | `34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:42 UTC |
| 68 (media) | alta | `e56b32c7b18f0a5e8a0308e45a1e11eb642d928f5efd554280b7cdf03babdb13` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:35 UTC |
| 68 (media) | alta | `9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:34 UTC |
| 68 (media) | alta | `801e4978b04e7c8377625359eaf0121fa71062ed2cb08105fdfa536fb93c1130` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:31 UTC |
| 68 (media) | media | `34b164db13fc9ec00a1fcf9a142bec0346009041a939f75da21f7239ea49e76e` | sha256_hash | SNOWLIGHT | ThreatFox | 2026-10-04 11:46:22 UTC |
| 68 (media) | media | `e9f587728e7cd8fc8eaafb87e5da4d2ebf1df16bc3cbdc9c35c76fa0b204776e` | sha256_hash | SNOWLIGHT | ThreatFox | 2026-10-04 11:46:19 UTC |
| 68 (media) | alta | `b7c026a5464800b78d27a46a6ba01b553de96e9dfb81a26e2d2940358b3802b9` | sha256_hash | Mirai | ThreatFox | 2026-10-04 04:46:50 UTC |
| 68 (media) | alta | `31919da20fdec8f6e2c8811024a1bd89e03c6d2fa5c04fcad97fdb6689501491` | sha256_hash | Mirai | ThreatFox | 2026-10-04 04:46:49 UTC |
| 68 (media) | alta | `3ce639bc2635ef7a4eb81dbe22a6d3a87c34d65477ac83a420b3480baeffc145` | sha256_hash | Mirai | ThreatFox | 2026-10-04 04:46:47 UTC |
| 68 (media) | alta | `7057e30367a3531968c465b69eb386aa86cf2396d45a04f52a32cf762e998a0c` | sha256_hash | Mirai | ThreatFox | 2026-10-04 04:46:43 UTC |
| 68 (media) | alta | `8865cec6bfc4cacc0fa38975628a6c1b32f71aa6a92446ee55414e8d2f85a2e5` | sha256_hash | Mirai | ThreatFox | 2026-10-04 04:46:38 UTC |
| 68 (media) | alta | `3ca8b87a782738aaf85290009634b35f5761d3285a84fe05041e272877219903` | sha256_hash | Mirai | ThreatFox | 2026-10-04 04:46:30 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-93952 | Arista VeloCloud Orchestrator | 2026-09-22 | Unknown |
| CVE-2026-94127 | F5 BIG-IP APM | 2026-09-22 | Unknown |
| CVE-2026-93616 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-85102 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-7273 | Zyxel GS1900 Series Switches | 2026-09-21 | Unknown |
<!-- CTI:END -->
