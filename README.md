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
**Última actualización:** 2026-09-28 13:39 UTC · **IOCs recolectados:** 2312 · **CVEs KEV recientes:** 19

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | media | `2beb79fc1bd0d64f6e582ebd4326cec4689e32e07e4ca63563d8e0d4a70990eb` | sha256_hash | VShell | ThreatFox | 2026-09-28 12:51:08 UTC |
| 73 (alta) | media | `99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c` | sha256_hash | VShell | ThreatFox | 2026-09-28 06:08:30 UTC |
| 71 (alta) | media | `5479dcd030b2c9fd2d990dbab36ceda46570890afa19da42a8f0c6e57b1b39be` | sha256_hash | Coinminer | ThreatFox | 2026-09-27 14:05:23 UTC |
| 70 (alta) | media | `4cbf9e936c1a19566f2f42cc7e4a96bce640ac47519696242e7ea1271364ab26` | sha256_hash | VShell | ThreatFox | 2026-09-28 06:09:13 UTC |
| 70 (alta) | media | `8aa3e180c979b0957277f1e11827ca37b1525ede929ba6b138d3a8e9db48480b` | sha256_hash | VShell | ThreatFox | 2026-09-27 17:05:05 UTC |
| 70 (alta) | media | `3e850b374c697c2a727a4783e1419508f880644dff5f70f9b6abd6e1c8624104` | sha256_hash | VShell | ThreatFox | 2026-09-27 14:05:23 UTC |
| 70 (alta) | alta | `08295c1247b7ce6dc020bfba5ba75540e3b5c98665ba99f2f73b37016811f47c` | sha256_hash | Venom RAT | ThreatFox | 2026-09-27 14:05:21 UTC |
| 70 (alta) | media | `abe4cb8229655ace61e225f9a6d4766d804b23994ac39c766ac5bb04d680bab2` | sha256_hash | VShell | ThreatFox | 2026-09-27 14:05:21 UTC |
| 70 (alta) | media | `1bc86fd3843315475b6519bb4e62ff3574ea5f2dbefc7a906717226f8712838a` | sha256_hash | VShell | ThreatFox | 2026-09-27 14:05:19 UTC |
| 69 (media) | alta | `3a2b62a3794370f1b0a4d714356e2ff44610c30ac464c43ad1fb3ca4d687a419` | sha256_hash | Mirai | ThreatFox | 2026-09-28 12:51:08 UTC |
| 69 (media) | alta | `db5ebbdf9f17e0c98a24e8f7055aa160e3dd57518b1db99b8e2056b2605a64d2` | sha256_hash | Mirai | ThreatFox | 2026-09-28 12:51:07 UTC |
| 69 (media) | media | `9cca3b4a8fe06e29d4683b448dac14be142eb3b14ed7a5b5ccf8bcf37ce80318` | sha256_hash | Bashlite | ThreatFox | 2026-09-28 12:51:07 UTC |
| 69 (media) | alta | `884d4aed509b9eba0c7b7cb4e0d98153707dcba323c95a28cbc38629e23d5de6` | sha256_hash | Mirai | ThreatFox | 2026-09-28 06:09:12 UTC |
| 69 (media) | media | `bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8` | sha256_hash | VShell | ThreatFox | 2026-09-28 06:08:30 UTC |
| 69 (media) | media | `a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b` | sha256_hash | VShell | ThreatFox | 2026-09-28 06:08:29 UTC |
| 69 (media) | media | `8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea` | sha256_hash | VShell | ThreatFox | 2026-09-28 06:08:29 UTC |
| 69 (media) | media | `af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d` | sha256_hash | VShell | ThreatFox | 2026-09-28 06:08:28 UTC |
| 69 (media) | alta | `fcab81e2c0113441109eb1ca852b80105bd18f50b0eb4fb49d79c64b5daed784` | sha256_hash | Mirai | ThreatFox | 2026-09-27 17:05:05 UTC |
| 69 (media) | alta | `c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033` | sha256_hash | Mirai | ThreatFox | 2026-09-27 17:05:04 UTC |
| 69 (media) | alta | `70b4932caeb92c33fbe1a8ad33aa73eb9ee2d7b3e32eab0cc0c7f5e8ec97678a` | sha256_hash | Vidar | ThreatFox | 2026-09-27 17:05:04 UTC |
| 69 (media) | alta | `4b1ca326143bd24d58506c4b3677b7fbaa46cf3b1d274907a38b7cba099a7955` | sha256_hash | Mirai | ThreatFox | 2026-09-27 17:05:03 UTC |
| 68 (media) | alta | `3c68a42d221a2bb52721dffb9474f314c22d29eba53e85e3d427097583fefce7` | sha256_hash | Mirai | ThreatFox | 2026-09-28 12:51:07 UTC |
| 68 (media) | media | `9e00b52b02d6e760b7cee84151b4b229e8b8f0b07f014d30f3db41d0b67feb44` | sha256_hash | Coinminer | ThreatFox | 2026-09-28 06:09:13 UTC |
| 68 (media) | media | `5e7a1b9857320e185d0dc8724dac6944bfceb01951a03b0f6c99f929020be862` | sha256_hash | Coinminer | ThreatFox | 2026-09-28 06:09:12 UTC |
| 67 (media) | media | `d0f697385ea97f20f5ab4880369e6afa16bfa1540bd2720c3e88991a8a11ec7f` | sha256_hash | Unknown malware | ThreatFox | 2026-09-28 12:51:06 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-58704 | Google Pixel | 2026-09-16 | Unknown |
| CVE-2026-76460 | Cisco Identity Services Engine | 2026-09-16 | Unknown |
| CVE-2026-87886 | Acronis Backup | 2026-09-16 | Unknown |
| CVE-2026-76461 | Cisco Secure Email Gateway | 2026-09-14 | Unknown |
<!-- CTI:END -->
