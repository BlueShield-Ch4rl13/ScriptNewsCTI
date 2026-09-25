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
**Última actualización:** 2026-09-25 21:32 UTC · **IOCs recolectados:** 2170 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | critica | `210[.]16[.]168[.]11:9999` | ip:port | Cobalt Strike | ThreatFox | 2026-09-25 07:52:08 UTC |
| 69 (media) | alta | `494aec19883cb5454d5d8e84953ceed65b83af99ff8a9cbf049544105e2b5e18` | sha256_hash | Mirai | ThreatFox | 2026-09-25 06:27:30 UTC |
| 69 (media) | alta | `3b6786813f55f4f49a2ea1bac64413b94523bc4468ab02f403c6912cbb703377` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:42 UTC |
| 69 (media) | alta | `8738d60030156b9cd03f939bad1257e7cd34de4adda9c84841564995353df593` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:37 UTC |
| 69 (media) | alta | `f1617c27d3c3b58cb6f930e21b5ffb002915ab4f7424c77552be9f82180409a8` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:36 UTC |
| 69 (media) | alta | `d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:33 UTC |
| 69 (media) | alta | `54d08acac87f7b50b4aca64be345b520d03f00818b8288fbfa4034d1bffe5800` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:32 UTC |
| 69 (media) | media | `b2e247ce007772e6b47aee8602399dfa3c305cd640d8350da80364ab42532fd4` | sha256_hash | Bashlite | ThreatFox | 2026-09-25 03:37:31 UTC |
| 69 (media) | alta | `597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-25 03:37:30 UTC |
| 68 (media) | alta | `6c944e11383fe04397727893aeb668d8b7989bdf9510e5bc283dbfb9fccd6f05` | sha256_hash | Mirai | ThreatFox | 2026-09-25 06:27:30 UTC |
| 68 (media) | alta | `640e6ad1c159f02c2e940290113a3d48cf78f33e930217802f13eaa3b62cc384` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:43 UTC |
| 68 (media) | alta | `6c420372a15415c1544790df5fe5ce9c6ff0bbef65546c83e02110307e3a32ff` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:41 UTC |
| 68 (media) | alta | `41a7d7a61716cf707ca471609069bdf649ed687c1c29c52aa196aaef75f8d077` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:40 UTC |
| 68 (media) | alta | `ac534a13006b72805cc12ea91ff2e06ab843c3806eca0e21e81f163dbd5212c6` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:39 UTC |
| 68 (media) | alta | `c754338f9ebacd78d7582f28729705d4e61c0ef05f9b8e13a71a6a0f05438dab` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:38 UTC |
| 68 (media) | alta | `939a999e03e1f80f3eb8e4e04b93c42339261e463e16582c2cccda1a28b57a8a` | sha256_hash | Mirai | ThreatFox | 2026-09-25 03:37:35 UTC |
| 66 (media) | critica | `45[.]227[.]253[.]132:56225` | ip:port | Cobalt Strike | ThreatFox | 2026-09-25 03:47:23 UTC |
| 57 (media) | alta | `158[.]94[.]210[.]177:2006` | ip:port | AsyncRAT | ThreatFox | 2026-09-25 19:44:01 UTC |
| 57 (media) | alta | `vrdx99th[.]bet313[.]org` | domain | ClearFake | ThreatFox | 2026-09-25 16:50:55 UTC |
| 57 (media) | media | `de5b4c6411938c0660f01d6933fd21e40ea7a2b6a141ff552d9dc39c931f6345` | sha256_hash | AMOS | ThreatFox | 2026-09-25 16:50:17 UTC |
| 57 (media) | media | `hxxp://211[.]101[.]233[.]147:8080/` | url | Unknown malware | ThreatFox | 2026-09-25 11:47:17 UTC |
| 57 (media) | media | `hxxp://211[.]101[.]233[.]147:8080/?a=w64&h=211[.]101[.]233[.]147&t=ws_&p=8080` | url | Unknown malware | ThreatFox | 2026-09-25 11:47:16 UTC |
| 57 (media) | media | `33cb2391cc0a21681eb67b1b85ce43117641059494c249030be388fa178bbda2` | sha256_hash | AMOS | ThreatFox | 2026-09-25 06:28:13 UTC |
| 57 (media) | media | `7243f66e3c28ef7d20a2ab34b30c577fe6f1f4273145a3379be7d3b9fea625a1` | sha256_hash | AMOS | ThreatFox | 2026-09-25 06:28:13 UTC |
| 56 (media) | media | `01d7e923a723802d5616af7d9c61dcb868b790f84b784b24db5bc9d127b0213d` | sha256_hash | AMOS | ThreatFox | 2026-09-25 20:22:29 UTC |

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
| CVE-2026-84869 | ConnectWise ScreenConnect | 2026-09-11 | Unknown |
| CVE-2026-42016 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-42018 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition | 2026-09-11 | Unknown |
<!-- CTI:END -->
