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
**Última actualización:** 2026-09-12 10:36 UTC · **IOCs recolectados:** 3717 · **CVEs KEV recientes:** 24

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `ea251bf7fcc0a42cb9e954a45d925ef379ef1ffca39e482f44af701b4ace8560` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 74 (alta) | alta | `ea0c84717977b89e7c7c885c68ac7ab4d8e561044cd93b47f3ddf830f9f688cd` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 74 (alta) | alta | `ea34c3a7831cb857a91e474a5afdcbb47492b36628f94856c59db4627ab85ce4` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 73 (alta) | alta | `ea0ac7277d0fdf801972b56bdc57184fc51ac8be47438873396436736f3694a9` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 73 (alta) | alta | `ea1c9ee453e17ae228c7aeebd2582572eb495bdf25a307d16f27d113cba69ff8` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 73 (alta) | alta | `5[.]175[.]222[.]230:80` | ip:port | Mirai | ThreatFox | 2026-09-11 19:46:57 UTC |
| 72 (alta) | alta | `ea30f01cff0ddb4ce05f1b5a864040cefafc92b2eea634c0d9b971d289246fac` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 72 (alta) | alta | `ea324fad712ec25e1d05c8c37b7651d1c715b84075b6cde743b5cc25d7c68e78` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 72 (alta) | alta | `176[.]65[.]139[.]139:3778` | ip:port | Mirai | ThreatFox | 2026-09-11 12:21:14 UTC |
| 72 (alta) | alta | `176[.]65[.]139[.]139:1234` | ip:port | Mirai | ThreatFox | 2026-09-11 12:21:13 UTC |
| 71 (alta) | media | `3e7d4140d6032515c6d19b25ee836c522519935db8b54d350020f94f744c5281` | sha256_hash | VShell | ThreatFox | 2026-09-12 07:28:55 UTC |
| 71 (alta) | alta | `ea1a02105dd7f3e59089e9f0d63c958e48025da81f0d15c4fd610b12c7d61673` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 71 (alta) | media | `150[.]242[.]14[.]129:9050` | ip:port | Unknown malware | ThreatFox | 2026-09-11 17:31:46 UTC |
| 70 (alta) | alta | `9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:29:12 UTC |
| 70 (alta) | media | `3da3643f25fd8ca8bb41502bb212b9f1617187ee8c6fa4e24a7bc2009a45debe` | sha256_hash | Bashlite | ThreatFox | 2026-09-12 07:29:00 UTC |
| 70 (alta) | alta | `da7ffe7578fbd4434eb90191c71d9009656c8d0ee1e042714c450ba8ee8e8486` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:29:00 UTC |
| 70 (alta) | alta | `e2bd2df04d99a41fbf40500e1de3fbf3c69a5ad952e4d23102d22d6de1246138` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:29:00 UTC |
| 70 (alta) | alta | `d75b9a8289eda8d48ff22e483f6df819d6a3e2d3fe638f6cb986d74358fe6e8e` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:28:58 UTC |
| 70 (alta) | alta | `0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:28:57 UTC |
| 70 (alta) | alta | `9d8a4cd741ff9f08ea00c04c7c90a0a1451c0e12fa25c1b098f2b27863819cfa` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:28:56 UTC |
| 70 (alta) | media | `7d22fabcc98916294775e10101526492c105b583ccc9cf3e2edad9187dab4f14` | sha256_hash | Tsunami | ThreatFox | 2026-09-12 07:28:53 UTC |
| 70 (alta) | alta | `ea1adb71ddfe3979fd618e26e6d22cbd61545fb5a5fb33137a8610bbc2d7202d` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 70 (alta) | alta | `ea25b6e75395d2ba68c88a7fec12236274f29126fe9cfe6ac1401590b50570a9` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-12 03:29:08 UTC |
| 69 (media) | alta | `9613957243feee5856b463939fab394765d6c9d8231c6c96a8f81ff1fb8925e5` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:28:52 UTC |
| 69 (media) | alta | `36fd38fb3bde624b67d2e7be824a7da3b552326f8ad203976d49dfb87e4b3547` | sha256_hash | Mirai | ThreatFox | 2026-09-12 07:28:51 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-84869 | ConnectWise ScreenConnect | 2026-09-11 | Unknown |
| CVE-2026-42016 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-42018 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition | 2026-09-11 | Unknown |
| CVE-2026-86060 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-67277 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-19490 | Citrix NetScaler | 2026-09-09 | Unknown |
| CVE-2025-25249 | Fortinet Multiple Products | 2026-09-09 | Unknown |
| CVE-2026-87491 | Google Chromium V8 | 2026-09-09 | Unknown |
| CVE-2026-20079 | Cisco Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management | 2026-09-09 | Unknown |
| CVE-2026-75650 | Adobe Commerce and Magento | 2026-09-08 | Unknown |
| CVE-2026-81963 | Microsoft Windows | 2026-09-08 | Unknown |
| CVE-2026-86218 | N-able N-central | 2026-09-08 | Unknown |
| CVE-2026-85880 | Microsoft Windows | 2026-09-08 | Unknown |
| CVE-2026-85046 | Google Chromium V8 | 2026-09-04 | Unknown |
| CVE-2026-59822 | BerriAI LiteLLM | 2026-09-02 | Unknown |
| CVE-2026-48710 | Kludex Starlette | 2026-09-02 | Unknown |
| CVE-2026-49869 | Kestra Kestra OSS | 2026-09-02 | Unknown |
| CVE-2026-82329 | JFrog Artifactory | 2026-09-02 | Unknown |
| CVE-2026-9586 | Sangoma Switchvox | 2026-09-02 | Unknown |
| CVE-2026-83548 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-83549 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-82078 | PaperCut NG/MF | 2026-08-31 | Unknown |
| CVE-2026-81578 | PaperCut NG/MF | 2026-08-31 | Unknown |
<!-- CTI:END -->
