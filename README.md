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
**Última actualización:** 2026-09-26 11:18 UTC · **IOCs recolectados:** 2213 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | alta | `176[.]65[.]149[.]45:1312` | ip:port | Mirai | ThreatFox | 2026-09-26 06:20:09 UTC |
| 71 (alta) | media | `94[.]154[.]43[.]253:9111` | ip:port | Unknown malware | ThreatFox | 2026-09-26 08:00:03 UTC |
| 70 (alta) | alta | `eee72764a752a092bc90fce37dd5a4064d9645425f1b1345a78fc58f1825b2bf` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:25 UTC |
| 69 (media) | alta | `364a8bba8180110e83d813d40f515cff2c4e60d42cbf01aae78f088746801202` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:49 UTC |
| 69 (media) | alta | `f348ecd809cf4663af8eec9373b57efcb807ec949134de96bfa3f055f6486b44` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:48 UTC |
| 69 (media) | alta | `8aa91527ef1aade354cf6b330350b09d5a263991213d8122c5488c3d4208dab7` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:45 UTC |
| 69 (media) | alta | `4b8c3e7964709ed08ce026a532f7cfbab9977c3dd0a00e4b5d510baafb589161` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:43 UTC |
| 69 (media) | alta | `969dddce3ec20d51407ed27ed133622f8b650539d46d44b685e8b33e42335fae` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:42 UTC |
| 69 (media) | alta | `90cb327bde61aab55d3d896767c847cb3361629812d6f07d1ae43b988a6fe689` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:41 UTC |
| 69 (media) | alta | `c7cb01343d760f329205b7842a807ee8ac592f0493b6a22079491ecad35e04f0` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:39 UTC |
| 69 (media) | alta | `1b46751ac5d806724e62ade572f23b06493cd34d6a05add4b9d7a85ef50ae379` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:38 UTC |
| 69 (media) | alta | `7b0fec9dc952de2ff789094282c1d2c5071cb3ac68a52bc9537842b85bd89daf` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:37 UTC |
| 69 (media) | alta | `ab8041ced5468e8f3b180e215ab8d5118ad49a60a7a432a3a67de38d744ad360` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:27 UTC |
| 69 (media) | alta | `6c4995159c694207517468ee6991102558433bb126e6b65a85cdc4ad950b54d4` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:26 UTC |
| 69 (media) | alta | `14ad9009027b020eafe074dbed1acd94c848523f57d273641323484d24e7bcaa` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:23 UTC |
| 69 (media) | alta | `797374fbcc72ae7c24f218f344780ff240076aad99cf8ea86284fcddd7c341f4` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:22 UTC |
| 69 (media) | alta | `19aa95cf525fa5755303285f37b806faea16f70c220aab1defb07690a185fa34` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:20 UTC |
| 69 (media) | alta | `fd375233ae40384734539bd50dca5cdc44f5b2309389a1c58c17b90f7f04888d` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:20 UTC |
| 68 (media) | alta | `0e7c12b38397e093aa773de12bc8e69637b4240632cff290014af24744ddba8b` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:51 UTC |
| 68 (media) | alta | `fd49082c1a601650525c3497fa5c10bad187a3862ebe371720658fa6f658e777` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:50 UTC |
| 68 (media) | alta | `f4936e80bd509be07c091ec5dcf1433d29366badc93715467dd40b5cd3cc40d6` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:47 UTC |
| 68 (media) | alta | `1990660f815e014736fc09c6ffdae11a852c4e0f0c0d1177637417503783312b` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:46 UTC |
| 68 (media) | alta | `30369de49e7a6afafaa7707088d6e2abdcf95ec57b729ff25f525011a5d25ad1` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:44 UTC |
| 68 (media) | alta | `98d83f73703359480ec5f0f0e4e1d8b6c12b96ebd25cb09a0ca7f596712f6dd3` | sha256_hash | Mirai | ThreatFox | 2026-09-26 03:37:42 UTC |
| 68 (media) | alta | `53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a` | sha256_hash | Mirai | ThreatFox | 2026-09-26 02:38:24 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-58704 | Google Pixel | 2026-09-16 | Unknown |
| CVE-2026-76460 | Cisco Identity Services Engine | 2026-09-16 | Unknown |
| CVE-2026-87886 | Acronis Backup | 2026-09-16 | Unknown |
| CVE-2026-76461 | Cisco Secure Email Gateway | 2026-09-14 | Unknown |
<!-- CTI:END -->
