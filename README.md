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
**Última actualización:** 2026-09-20 15:59 UTC · **IOCs recolectados:** 1597 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | media | `b659aea8be65b89f3579b7e8f2941b1a481f4c8c72db7c17c30ad929dc87a28d` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:24 UTC |
| 73 (alta) | media | `dac96bc408b9ce098910dea7b359d0a5089081f42a84087b2ca6b724d660810d` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:24 UTC |
| 73 (alta) | alta | `3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-20 09:46:39 UTC |
| 73 (alta) | critica | `81[.]70[.]21[.]163:8080` | ip:port | Cobalt Strike | ThreatFox | 2026-09-20 04:05:07 UTC |
| 73 (alta) | critica | `81[.]70[.]21[.]163:443` | ip:port | Cobalt Strike | ThreatFox | 2026-09-20 04:05:06 UTC |
| 72 (alta) | media | `0e94b8d01393bd5d7c16095b1df29fc695b50cbb05a1b76acb4d5165de9c4378` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:20 UTC |
| 72 (alta) | media | `03b2a2fa1ba45acaf40291cef2c753c2d60ec629a851434fe20d5cfb5575f954` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:20 UTC |
| 72 (alta) | alta | `d030dbd4fb42806f83b5681716c8fd31eb280ea6c171a908a7161223e94a48ed` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-20 14:52:13 UTC |
| 72 (alta) | alta | `dff9ab23aa2ec30cb126f90448e995eb36403dee572b20ee930ad35203aef7bf` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-20 14:52:12 UTC |
| 72 (alta) | media | `7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:08 UTC |
| 72 (alta) | media | `17c23b9917d2e02b6282e3b7c80a1c0dc40e8ba8385a7f108b3d490ba56b23e1` | sha256_hash | VShell | ThreatFox | 2026-09-20 05:32:29 UTC |
| 71 (alta) | alta | `7e6815495d078bff962365cd929cdcf8f0c25f24b9de5ee89bebec4af778d76f` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-20 14:52:31 UTC |
| 71 (alta) | alta | `690494e1727859959830d17d45a432120d5950dbcaa7ff6fd6a1f6d482e5b2eb` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-20 14:52:29 UTC |
| 71 (alta) | alta | `6b3062c7b0408711b942f47e3d30d776a91d3963c3a243408d2421f164f2b987` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-20 14:52:29 UTC |
| 71 (alta) | media | `639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:10 UTC |
| 70 (alta) | alta | `872af2d22eebf08a55cf54293892b70f7d69f2d6a9665d7ac2cc7ab41ba59976` | sha256_hash | Mirai | ThreatFox | 2026-09-20 14:52:21 UTC |
| 70 (alta) | media | `5c93b5acf69d903e4a3b82d93d0b4dfd0f0421d01899e2dbd19b42dc90b662ca` | sha256_hash | VShell | ThreatFox | 2026-09-20 05:32:32 UTC |
| 70 (alta) | media | `c63795af3f664de95aacf2a1829805c5d04be7e79524f511b15f6a85453aa6f0` | sha256_hash | VShell | ThreatFox | 2026-09-20 05:32:29 UTC |
| 70 (alta) | media | `e46795ecf21f16b7ff23f8a5b06cbdb560255df8d7a5d083f6434dcdd3fc6628` | sha256_hash | VShell | ThreatFox | 2026-09-20 05:32:29 UTC |
| 70 (alta) | media | `d4a1d31071219e052098223e88b0bc28bb78cc47fb0b6aa8cddf4ceff36ef556` | sha256_hash | VShell | ThreatFox | 2026-09-20 05:32:28 UTC |
| 69 (media) | media | `fffe3d53b69069600316d95da7141188c232111549832e053cdc26756f92315a` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:28 UTC |
| 69 (media) | media | `9ced5fc61e2b93800be8938382d7c9db7d53ae80ac81fbe9aad82fe0ec7efced` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:27 UTC |
| 69 (media) | media | `35e1673c95baa0a8f0ebb5714253420ee450f1280a61d2c17bd2e71a55beb0fc` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:27 UTC |
| 69 (media) | media | `5b9d71bb2865c9af13147a50584c6b44deb1a87a17e9e64c85af69fdd59670de` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:27 UTC |
| 69 (media) | media | `1954b7ea05ea3e449d750c7e7b6d2f2e1c531f04ad1b47ee4f51a389508c1138` | sha256_hash | VShell | ThreatFox | 2026-09-20 14:52:26 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
<!-- CTI:END -->
