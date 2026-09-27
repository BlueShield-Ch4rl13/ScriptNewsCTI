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
**Última actualización:** 2026-09-27 21:21 UTC · **IOCs recolectados:** 4808 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | media | `c66d2b77b9e85c53391891212413ad9a99eb66f4b11c6a431e78884a5b2651e5` | sha256_hash | Coinminer | ThreatFox | 2026-09-27 06:38:28 UTC |
| 71 (alta) | media | `5479dcd030b2c9fd2d990dbab36ceda46570890afa19da42a8f0c6e57b1b39be` | sha256_hash | Coinminer | ThreatFox | 2026-09-27 14:05:23 UTC |
| 71 (alta) | alta | `14b2ac356ed75d10ef40bbaaa48e7dd9fff7de9719c2a43ad123fe843dd4e4e2` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-27 06:38:29 UTC |
| 71 (alta) | media | `6910e0a987ca752e7fcd93bc66f45790fe0e0a04140d7055f7dcb7cd901ca6fb` | sha256_hash | Coinminer | ThreatFox | 2026-09-27 06:38:27 UTC |
| 70 (alta) | media | `4cbf9e936c1a19566f2f42cc7e4a96bce640ac47519696242e7ea1271364ab26` | sha256_hash | VShell | ThreatFox | 2026-09-27 20:45:02 UTC |
| 70 (alta) | media | `8aa3e180c979b0957277f1e11827ca37b1525ede929ba6b138d3a8e9db48480b` | sha256_hash | VShell | ThreatFox | 2026-09-27 17:05:05 UTC |
| 70 (alta) | media | `3e850b374c697c2a727a4783e1419508f880644dff5f70f9b6abd6e1c8624104` | sha256_hash | VShell | ThreatFox | 2026-09-27 14:05:23 UTC |
| 70 (alta) | media | `abe4cb8229655ace61e225f9a6d4766d804b23994ac39c766ac5bb04d680bab2` | sha256_hash | VShell | ThreatFox | 2026-09-27 14:05:21 UTC |
| 70 (alta) | alta | `08295c1247b7ce6dc020bfba5ba75540e3b5c98665ba99f2f73b37016811f47c` | sha256_hash | Venom RAT | ThreatFox | 2026-09-27 14:05:21 UTC |
| 70 (alta) | media | `1bc86fd3843315475b6519bb4e62ff3574ea5f2dbefc7a906717226f8712838a` | sha256_hash | VShell | ThreatFox | 2026-09-27 14:05:19 UTC |
| 70 (alta) | alta | `8220c8b6785864f587a492d44176ed986fb30ef10c459c3068b183e7d20033a2` | sha256_hash | Mirai | ThreatFox | 2026-09-27 06:43:57 UTC |
| 70 (alta) | media | `e0d6a02ee294d46c2b57a151797eb88fce1add4571a00a746837052059e41ffa` | sha256_hash | VShell | ThreatFox | 2026-09-27 06:38:31 UTC |
| 69 (media) | alta | `884d4aed509b9eba0c7b7cb4e0d98153707dcba323c95a28cbc38629e23d5de6` | sha256_hash | Mirai | ThreatFox | 2026-09-27 20:45:11 UTC |
| 69 (media) | alta | `fcab81e2c0113441109eb1ca852b80105bd18f50b0eb4fb49d79c64b5daed784` | sha256_hash | Mirai | ThreatFox | 2026-09-27 17:05:05 UTC |
| 69 (media) | alta | `70b4932caeb92c33fbe1a8ad33aa73eb9ee2d7b3e32eab0cc0c7f5e8ec97678a` | sha256_hash | Vidar | ThreatFox | 2026-09-27 17:05:04 UTC |
| 69 (media) | alta | `c8fd41ba910705bc0a13ec8ccabbc13bd0217a6f0ba5f37f2ca45c63b89cc033` | sha256_hash | Mirai | ThreatFox | 2026-09-27 17:05:04 UTC |
| 69 (media) | alta | `4b1ca326143bd24d58506c4b3677b7fbaa46cf3b1d274907a38b7cba099a7955` | sha256_hash | Mirai | ThreatFox | 2026-09-27 17:05:03 UTC |
| 69 (media) | alta | `7f2877c0400dcaf354e7de2848461abd959ad5d56f86d0e69fa7644ffa1287da` | sha256_hash | Mirai | ThreatFox | 2026-09-27 06:44:18 UTC |
| 69 (media) | alta | `74456a082d851e2c92d2173f2a116af8cebda7911ebdcaa63c4709692fd037bc` | sha256_hash | Mirai | ThreatFox | 2026-09-27 06:43:58 UTC |
| 69 (media) | alta | `d8af3f2541124c25bd8bca1970eea9283229fb67adbed45a2bb9e368c30ea45f` | sha256_hash | Mirai | ThreatFox | 2026-09-27 06:43:56 UTC |
| 69 (media) | alta | `c4cc7a3fe27bcc65b103b7fbdbf461bf23c3ab77385dd70d1f03aad58e24aa79` | sha256_hash | Mirai | ThreatFox | 2026-09-27 06:43:55 UTC |
| 69 (media) | media | `5e8b77073c07a0212fe33de5ade94058fd9e60211535841d739a2b39821c2594` | sha256_hash | VShell | ThreatFox | 2026-09-27 06:38:30 UTC |
| 68 (media) | media | `5e7a1b9857320e185d0dc8724dac6944bfceb01951a03b0f6c99f929020be862` | sha256_hash | Coinminer | ThreatFox | 2026-09-27 20:45:07 UTC |
| 68 (media) | media | `9e00b52b02d6e760b7cee84151b4b229e8b8f0b07f014d30f3db41d0b67feb44` | sha256_hash | Coinminer | ThreatFox | 2026-09-27 20:45:05 UTC |
| 68 (media) | alta | `c458e443759ea633cde8929b4337726136675141d82251158f973f54008e20ac` | sha256_hash | Mirai | ThreatFox | 2026-09-27 06:44:18 UTC |

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
