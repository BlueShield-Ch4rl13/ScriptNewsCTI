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
**Última actualización:** 2026-09-19 04:16 UTC · **IOCs recolectados:** 787 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `63b0475bd58c48b4fe32f23515816550b6bb20455725b703e12d3428b3e7bedf` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:47 UTC |
| 75 (alta) | media | `141[.]98[.]10[.]26:6969` | ip:port | CECbot | ThreatFox | 2026-09-18 11:06:17 UTC |
| 74 (alta) | media | `77a90a2dd2aeef925b0198b39a788c9ff5183044bdfa398c75889c74750fe407` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:46 UTC |
| 73 (alta) | media | `6fa80698d7268f6e88aa88c06fb27ee99e1bcee747c2e76911e6206a5b1aeeb3` | sha256_hash | xmrig | ThreatFox | 2026-09-19 00:45:14 UTC |
| 72 (alta) | alta | `176[.]65[.]132[.]207:80` | ip:port | Mirai | ThreatFox | 2026-09-18 19:44:14 UTC |
| 72 (alta) | alta | `af23e31dddd570b2747feff467157e265c1a6627be0649d51ed9b71383053eea` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-18 17:23:52 UTC |
| 72 (alta) | media | `e401bb0221be358e9639b552e367cf7cc2d6ce9b9c8cf2721a0ac877fbd2ecaa` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:45 UTC |
| 71 (alta) | alta | `176[.]65[.]139[.]219:9111` | ip:port | Mirai | ThreatFox | 2026-09-18 06:18:42 UTC |
| 70 (alta) | media | `6f102146c656ffdc9a31fbbbeb8e319b00898e485f93b76c5ad04a964bfd4fdc` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:47 UTC |
| 70 (alta) | media | `bf22312e3e995c77f4f8234f230bf5bb4ba5c609d9e8f68c303d5a5cd0503cce` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:46 UTC |
| 70 (alta) | media | `a6b9e11dd7457c49ef440964ef625cb34762d94b894e05925f92fc14d1e2b714` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:46 UTC |
| 70 (alta) | media | `7eb1acc29ed9cdd6dbc9ff1ffcea397ec5119e752b8ee7cf662925d5aa132cc3` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:44 UTC |
| 69 (media) | alta | `d04c03df654d5cb80cd95be199b2e43337ea2f9de68addf4708fe8b73a03640f` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 01:28:57 UTC |
| 69 (media) | alta | `9eb7a6a0199d37909f2d682d9dff839cc6e335d173680e8f056c0bf606d3351d` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-18 17:23:52 UTC |
| 69 (media) | alta | `1f423c42e631e5b57350566821bc0561f9105ec4e9eb055f29f44d0cb5d9aff3` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-18 17:23:52 UTC |
| 69 (media) | alta | `a33181af9e44bf83c799f1fcf422f2b9145c41d49b20cca569e33243476056c4` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-18 17:23:51 UTC |
| 69 (media) | alta | `89d0f591a743900b2b3922b63d223de7347f909c3ebfa4deb47b9ac5b073070c` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-18 17:23:50 UTC |
| 69 (media) | alta | `6ade2c266048157c395e9a054ead60b6b8ba1f45069bcd2ac49fc347a9ec7192` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-18 17:23:50 UTC |
| 69 (media) | media | `0242e4675a8c55d179341a617c074e6d8c5752ac4158f73cdbec8a400a9e306a` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:44 UTC |
| 69 (media) | media | `beccb2cbc29a0c839af07e7f6e29473f6aa9b162960447a5c19733e19757e0b8` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:43 UTC |
| 69 (media) | media | `d5634b7f71b704851628e6a8e93e31a6044f0cffea2316f454cf0efd8f640de8` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:43 UTC |
| 69 (media) | media | `91c8498add9ef05e7b20983dff07eff8d23a70bad7093990b23761f89a4800eb` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:42 UTC |
| 69 (media) | media | `18f59334aaa3e6fee325946df9c1571d06f0e41ce38dd19221f8b6d1f121bb03` | sha256_hash | VShell | ThreatFox | 2026-09-18 17:23:42 UTC |
| 68 (media) | alta | `06d41e963ea49632f199c7bd18d7d939dc9d8dc6c02cf7ce714b7c24fef4868e` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 01:28:58 UTC |
| 68 (media) | alta | `b98fc9f0dbc61810287e77ea978665a0b762dceea927bbffceb63fb7005149b3` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 01:28:58 UTC |

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
