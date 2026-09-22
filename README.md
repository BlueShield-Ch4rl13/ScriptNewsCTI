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
**Última actualización:** 2026-09-22 21:17 UTC · **IOCs recolectados:** 1360 · **CVEs KEV recientes:** 26

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `221[.]236[.]125[.]241:23` | ip:port | Unknown malware | ThreatFox | 2026-09-22 01:05:05 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:2222` | ip:port | Unknown malware | ThreatFox | 2026-09-22 01:05:05 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:22` | ip:port | Unknown malware | ThreatFox | 2026-09-22 00:05:09 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:21` | ip:port | Unknown malware | ThreatFox | 2026-09-22 00:05:08 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:60000` | ip:port | Unknown malware | ThreatFox | 2026-09-21 22:05:06 UTC |
| 75 (alta) | media | `221[.]236[.]125[.]241:9192` | ip:port | Unknown malware | ThreatFox | 2026-09-21 22:05:05 UTC |
| 72 (alta) | critica | `81[.]70[.]21[.]163:389` | ip:port | Cobalt Strike | ThreatFox | 2026-09-22 20:05:08 UTC |
| 72 (alta) | critica | `81[.]70[.]21[.]163:8888` | ip:port | Cobalt Strike | ThreatFox | 2026-09-22 19:05:06 UTC |
| 71 (alta) | media | `80[.]87[.]206[.]86:18082` | ip:port | Unknown malware | ThreatFox | 2026-09-22 17:57:26 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]12:33` | ip:port | Mirai | ThreatFox | 2026-09-22 05:29:45 UTC |
| 70 (alta) | alta | `4deefc89b2046999f1a6ea578950dab891579dfa5032b6d1d534f88aa000b7e5` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:58:02 UTC |
| 69 (media) | alta | `526e532170acbc980bf41c48d1886b592a871c852d5ea86f98db4296bbbe85b6` | sha256_hash | KrBanker | ThreatFox | 2026-09-22 04:58:01 UTC |
| 69 (media) | media | `586960df8bf559ffbba600f11917a99baed4a875cb7faa5eabc060bcde67277b` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:58 UTC |
| 69 (media) | alta | `bcfbd1d0c98844ddd4795a6df4e6431a494a0320c72413f188b50140cd30f506` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:58 UTC |
| 69 (media) | media | `97eaa49999cbcc866fc30ca2ba20f2a1d4e9b01d1c824d3924a185683d2b87c5` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:57 UTC |
| 69 (media) | media | `7aac36e30a811f7463cfb882ee6ff76834a60428c436b0b3fa15ff8f94b8db51` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:57 UTC |
| 69 (media) | media | `f407f10ce043dce0f4a8aeed21912f20f21f613ec0fe495394451097dc8ced0b` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:55 UTC |
| 69 (media) | media | `3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b` | sha256_hash | Bashlite | ThreatFox | 2026-09-22 04:57:54 UTC |
| 69 (media) | alta | `32dcfd588d0602147330508b7f35e5f4424abf20a4459150c56a08e5ebb1693c` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:53 UTC |
| 69 (media) | alta | `01c895e125b6c2214f509b0d0c94b81b29b34d3da3ec52d2014eeb4c19bd1086` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:52 UTC |
| 69 (media) | alta | `6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:52 UTC |
| 69 (media) | alta | `a2a6d8a0b14a5c8108e8a0678ce60b43fff05f5d5ac8088482895746e645b18e` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:51 UTC |
| 68 (media) | media | `134[.]33[.]66[.]210:443` | ip:port | Unknown malware | ThreatFox | 2026-09-22 11:40:48 UTC |
| 68 (media) | alta | `0f525163359e877881bd5a2ed6c231f829c2ff23d3c00f6105f9d860a6ed95cb` | sha256_hash | Mirai | ThreatFox | 2026-09-22 04:57:51 UTC |
| 67 (media) | alta | `b9533ce8e428f16f3d0e1946f19a6f756ff11a532d0b7e61ae402837f46c678e` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-22 04:58:00 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-86060 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-67277 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-19490 | Citrix NetScaler | 2026-09-09 | Unknown |
| CVE-2025-25249 | Fortinet Multiple Products | 2026-09-09 | Unknown |
| CVE-2026-87491 | Google Chromium V8 | 2026-09-09 | Unknown |
| CVE-2026-20079 | Cisco Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management | 2026-09-09 | Unknown |
| CVE-2026-75650 | Adobe Commerce and Magento | 2026-09-08 | Unknown |
| CVE-2026-81963 | Microsoft Windows | 2026-09-08 | Unknown |
| CVE-2026-86218 | N-able N-central | 2026-09-08 | Unknown |
<!-- CTI:END -->
