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
**Última actualización:** 2026-09-30 22:15 UTC · **IOCs recolectados:** 1487 · **CVEs KEV recientes:** 20

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `94[.]154[.]43[.]84:8900` | ip:port | Unknown malware | ThreatFox | 2026-09-30 14:49:48 UTC |
| 75 (alta) | media | `94[.]154[.]43[.]84:7000` | ip:port | Unknown malware | ThreatFox | 2026-09-30 14:49:47 UTC |
| 75 (alta) | media | `94[.]154[.]43[.]84:9000` | ip:port | Unknown malware | ThreatFox | 2026-09-30 14:49:47 UTC |
| 75 (alta) | critica | `158[.]94[.]209[.]12:8444` | ip:port | AdaptixC2 | ThreatFox | 2026-09-30 06:02:27 UTC |
| 72 (alta) | alta | `209[.]126[.]103[.]97:1791` | ip:port | Mirai | ThreatFox | 2026-09-30 14:49:39 UTC |
| 72 (alta) | media | `0f4f26d4e4b73735e19f147751fb0cc3678aa74b2113f8f1405f3ab0145238fd` | sha256_hash | VShell | ThreatFox | 2026-09-30 12:21:51 UTC |
| 70 (alta) | alta | `3797d5082f3612a2493ce6430ed09a61922573f6871401f95b0d2e735a12ada1` | sha256_hash | Remcos | ThreatFox | 2026-09-30 11:08:14 UTC |
| 69 (media) | media | `d135fd8610833b6961936ba31f8feb2fd97efd1a0f5b6d4e333301e94531a3ba` | sha256_hash | VShell | ThreatFox | 2026-09-30 11:08:12 UTC |
| 69 (media) | alta | `3fd8de4fd28f7bdc4b5d428693f45d2a867bb6177e9b0f5c6f59cc8a71c75363` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:48:40 UTC |
| 69 (media) | alta | `6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:48:39 UTC |
| 68 (media) | alta | `e216b69e4e2e4faebaee321cb343e17dbf2b62449b072d66ac557ba2a88199a6` | sha256_hash | Mirai | ThreatFox | 2026-09-30 21:46:01 UTC |
| 68 (media) | alta | `962a11883caa14e1a181908e7da277d155a77747632b0dbd823277c362a722ec` | sha256_hash | Mirai | ThreatFox | 2026-09-30 21:46:00 UTC |
| 68 (media) | alta | `b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa` | sha256_hash | Mirai | ThreatFox | 2026-09-30 21:45:59 UTC |
| 68 (media) | alta | `04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70` | sha256_hash | Mirai | ThreatFox | 2026-09-30 21:45:52 UTC |
| 68 (media) | alta | `b882d7626ff89aa52514fdb06a9333db386e98b31937d0184d65c8ba70474eed` | sha256_hash | Mirai | ThreatFox | 2026-09-30 12:21:51 UTC |
| 68 (media) | alta | `4d79178fa6d7f0627caef122e3c29a0a95a0802ba5a050041660f4d6e11adbfd` | sha256_hash | Mirai | ThreatFox | 2026-09-30 12:21:50 UTC |
| 68 (media) | alta | `a6a9d179d50a8102d277da718045535cf59dc5e7f48420403ac34c2f08fb5e35` | sha256_hash | Mirai | ThreatFox | 2026-09-30 12:21:50 UTC |
| 68 (media) | alta | `02c05faa97ebc77db971a14b06fd99ec004e669b662a55d520031b1bed808199` | sha256_hash | Mirai | ThreatFox | 2026-09-30 12:21:50 UTC |
| 68 (media) | alta | `a49bba3715642957c6abde3d3ce3784bd3e5c3cc9d77936746e75d68fd62e9d0` | sha256_hash | Mirai | ThreatFox | 2026-09-30 11:08:13 UTC |
| 68 (media) | alta | `a28f193f95de3465f9dca27f2cb47329dc397cc6eae9670a9391d8dbcaa473b1` | sha256_hash | Mirai | ThreatFox | 2026-09-30 11:08:11 UTC |
| 68 (media) | alta | `208fd8397429bf71c97ece08b94d94d9787bb31f9830e41f18132f34de87986f` | sha256_hash | Mirai | ThreatFox | 2026-09-30 11:08:10 UTC |
| 68 (media) | alta | `829aeb0ca33254480fd405f89c4b8efd64a2662371a7aa001c724ac342e93a6a` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:49:42 UTC |
| 68 (media) | alta | `4e3e766423891ef7c8b09f7c2d02636ea15aac18ef5c028acc3ef08e2643b1ab` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:49:41 UTC |
| 68 (media) | alta | `2c64c6270c6cb3caa16e6f5051102f25dfec903eb1017de5976fae422024553a` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:49:40 UTC |
| 68 (media) | alta | `8b2cbc92f4a2a878304edd1560ba40a644e8fd55b46ef5d36f0cd0764d3c6e53` | sha256_hash | Mirai | ThreatFox | 2026-09-30 05:49:40 UTC |

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
| CVE-2026-58704 | Google Pixel | 2026-09-16 | Unknown |
| CVE-2026-76460 | Cisco Identity Services Engine | 2026-09-16 | Unknown |
| CVE-2026-87886 | Acronis Backup | 2026-09-16 | Unknown |
<!-- CTI:END -->
