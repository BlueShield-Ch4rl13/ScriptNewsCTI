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
**Última actualización:** 2026-09-30 05:13 UTC · **IOCs recolectados:** 1362 · **CVEs KEV recientes:** 19

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | critica | `158[.]94[.]209[.]12:8444` | ip:port | AdaptixC2 | ThreatFox | 2026-09-30 03:01:53 UTC |
| 72 (alta) | media | `7d99a996c6a1e5d1295b6fc9cc4958d5501ea32700f39b5f3787fe38dd89757a` | sha256_hash | VShell | ThreatFox | 2026-09-29 12:10:46 UTC |
| 70 (alta) | alta | `941efe52eb858311653bf2c1e855555cf735896d500f11ea90aaf7e93d1faa3f` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:38 UTC |
| 70 (alta) | media | `5b9c569ed427882d17d347ed511ce60e1a20f5876609e14eba6e44423ccc33d9` | sha256_hash | Bashlite | ThreatFox | 2026-09-29 12:10:38 UTC |
| 70 (alta) | alta | `0bbece3dc42199a2cc3db4e7685e5e6078084203e51e9ef6df657038cf79b306` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:30 UTC |
| 70 (alta) | media | `ab1ae861b41f856ad304e965385d44eb4286e385943b83dda6f47e419c63071c` | sha256_hash | VShell | ThreatFox | 2026-09-29 06:28:04 UTC |
| 69 (media) | alta | `6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce` | sha256_hash | Mirai | ThreatFox | 2026-09-30 04:45:28 UTC |
| 69 (media) | alta | `3fd8de4fd28f7bdc4b5d428693f45d2a867bb6177e9b0f5c6f59cc8a71c75363` | sha256_hash | Mirai | ThreatFox | 2026-09-30 04:45:25 UTC |
| 69 (media) | critica | `c1e184615241fe69db3bf4093a22c7c0bf5d6072d2f51e558142b844e871084f` | sha256_hash | Sliver | ThreatFox | 2026-09-29 20:57:07 UTC |
| 69 (media) | critica | `d146f59f4dcfe845fe28ed91b3eed530e78947a8` | sha1_hash | Sliver | ThreatFox | 2026-09-29 20:57:07 UTC |
| 69 (media) | critica | `76d2b36de3696996b07353c29a06698a` | md5_hash | Sliver | ThreatFox | 2026-09-29 20:57:07 UTC |
| 69 (media) | alta | `d1d398c1a8e4822fca6fa00e0cb60e8360884d59a8a64fcde24d4027d6d39d08` | sha256_hash | Mirai | ThreatFox | 2026-09-29 12:10:51 UTC |
| 69 (media) | alta | `e759a73f9d73a6c2d72b537a31294fcbc78fcc36139ad7c97597aac8568f07ae` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:32 UTC |
| 69 (media) | alta | `93d8b8ecae2f71494ff55c642236a8cf29b1bef976631ec64345b7dde0fede69` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:32 UTC |
| 69 (media) | alta | `0116035ec7b3089b35231c75dc558547337e99bb99319c52241905a2c968f341` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:31 UTC |
| 69 (media) | alta | `0aa485506ebf9f1fb8c3931f0834875f1284776e86ef6d7d34e381df68f1d9dd` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:31 UTC |
| 69 (media) | alta | `9ea665fe5d5d4c705d31d81918bccdec8038257fa316aaa10a97995c0e4d2c99` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:30 UTC |
| 69 (media) | alta | `73bcca5b454619b329fd696ba5049fb404b38857702dd65e2f093851076fda38` | sha256_hash | Mirai | ThreatFox | 2026-09-29 06:28:30 UTC |
| 68 (media) | alta | `b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd` | sha256_hash | Mirai | ThreatFox | 2026-09-30 04:45:30 UTC |
| 68 (media) | alta | `0cf26764fb6640c09a25bc5a0e877ef690ef8237b9bbc35feadfd27254ed288c` | sha256_hash | Mirai | ThreatFox | 2026-09-30 04:45:27 UTC |
| 68 (media) | alta | `68de31e7ab680594337c3f74c8bef5cf993d2c7a49bc7ef4a029b483d8f337fc` | sha256_hash | Mirai | ThreatFox | 2026-09-30 04:45:24 UTC |
| 68 (media) | alta | `8b2cbc92f4a2a878304edd1560ba40a644e8fd55b46ef5d36f0cd0764d3c6e53` | sha256_hash | Mirai | ThreatFox | 2026-09-29 21:45:31 UTC |
| 68 (media) | alta | `2c64c6270c6cb3caa16e6f5051102f25dfec903eb1017de5976fae422024553a` | sha256_hash | Mirai | ThreatFox | 2026-09-29 21:45:29 UTC |
| 68 (media) | alta | `4e3e766423891ef7c8b09f7c2d02636ea15aac18ef5c028acc3ef08e2643b1ab` | sha256_hash | Mirai | ThreatFox | 2026-09-29 21:45:27 UTC |
| 68 (media) | alta | `829aeb0ca33254480fd405f89c4b8efd64a2662371a7aa001c724ac342e93a6a` | sha256_hash | Mirai | ThreatFox | 2026-09-29 21:45:25 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
