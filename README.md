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
**Última actualización:** 2026-10-01 22:42 UTC · **IOCs recolectados:** 1714 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | alta | `176[.]65[.]139[.]196:18129` | ip:port | Mirai | ThreatFox | 2026-10-01 05:17:20 UTC |
| 71 (alta) | alta | `160[.]119[.]66[.]206:25565` | ip:port | Mirai | ThreatFox | 2026-10-01 05:17:43 UTC |
| 71 (alta) | media | `91[.]92[.]40[.]130:9999` | ip:port | Unknown malware | ThreatFox | 2026-10-01 05:17:24 UTC |
| 70 (alta) | media | `771ec7047ca7242266491a67a07b1ad4fe18dcbc6ed4b92c26905090183a196f` | sha256_hash | VShell | ThreatFox | 2026-10-01 12:45:56 UTC |
| 70 (alta) | media | `177[.]4[.]12[.]11:8080` | ip:port | Unknown malware | ThreatFox | 2026-10-01 05:27:14 UTC |
| 69 (media) | alta | `7ba88a03067c548f642bb8971f81e266e34281a6b4b42784e5d88f91892daaaa` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:08 UTC |
| 69 (media) | media | `dedad5b693e337a6d6480398e551ad9296a74da18707a5179c9fa2d88fe4bd50` | sha256_hash | VShell | ThreatFox | 2026-10-01 12:45:57 UTC |
| 69 (media) | alta | `37289b6cd05c122326f557e5ae79c6bb024e0021236dd7ef47c97ffd6af5e155` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:46 UTC |
| 69 (media) | alta | `05167be9a9fb578c118ac1e19e50f0d6aa000f5b89ee75d3ad17659743b6e720` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:15 UTC |
| 69 (media) | alta | `c45d173921af4cf37428f2b7421ddbce53edb50984cec2c8253acab50886a9c8` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:13 UTC |
| 69 (media) | alta | `9b81c8610579aaf75abc4e0fb27facd5d28d8c653529c2a78836db384dc881cb` | sha256_hash | Mirai | ThreatFox | 2026-10-01 04:42:03 UTC |
| 68 (media) | alta | `b9a5981e8cc88e30b5a2cc19fdfaddc7292c920c0d780e09dd338b95362e586a` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:09 UTC |
| 68 (media) | alta | `0f4825a816b143a681601528b75aca2092b26026c78141c842b05354e96d8a86` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:07 UTC |
| 68 (media) | alta | `5a21c34ff54ab1a92246b9cfba815ed187fe636b9350d41e26c5e4aa8f4bf891` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:04 UTC |
| 68 (media) | alta | `3ef94abf1e178ac49ddcccd474eb883e248237f2854e220de69216fb3d196a13` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:02 UTC |
| 68 (media) | alta | `cc6f394e7ab43785247b4614076cbcac9a1d47839569de8a81be2ad1bafff7ae` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:45:58 UTC |
| 68 (media) | alta | `dd0b08f858b78d57b73c079282bccd502f1165812f6c33d35e87c589201210d7` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:55 UTC |
| 68 (media) | alta | `0e31d3cfb24baf38d3faec21b52465842fbe5c16e6e16bc2efcd3a5025dde324` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:54 UTC |
| 68 (media) | alta | `a157b86bb50b92c090fc69d53330f09f4e9cba5ad3f6d071cce6c541969d08be` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:53 UTC |
| 68 (media) | alta | `a2eb9cf201f057f9860abfbd377b58d390165b6c86ff9a23f848ee0142b40f7b` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:52 UTC |
| 68 (media) | alta | `2ee382361d90e132a609142789120179e82c82291ddc7c8a477c3bb922d32093` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:50 UTC |
| 68 (media) | alta | `8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:49 UTC |
| 68 (media) | alta | `2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:48 UTC |
| 68 (media) | alta | `97eda25aafbe8e3cd94697374c2c4fc12f9f81dcad701a4473a419f863a92d9b` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:47 UTC |
| 68 (media) | alta | `086d6790e715890e2b60732204317771e64f7ea0beb3a77bf7b96420b132b007` | sha256_hash | Mirai | ThreatFox | 2026-10-01 11:45:44 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2025-39964 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-53266 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2025-39682 | Linux Kernel | 2026-09-18 | Unknown |
<!-- CTI:END -->
