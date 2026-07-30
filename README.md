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
| Frescura | ×1,0 ≤7 días · ×0,85 ≤30 · ×0,6 ≤90 · ×0,3 resto |

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

## Troubleshooting

- **El workflow no commitea**: revisa *Settings → Actions → General → Workflow permissions* y marca *Read and write permissions*.
- **ThreatFox/URLhaus devuelven 401/403**: falta o es inválida la `ABUSECH_API_KEY`.
- **Score o gravedad en «—» en la web**: los datos publicados los generó una versión antigua del pipeline; comprueba que `main.py` importa `enrich` y relanza *CTI Update*.
- **Reputación en «—»**: faltan `VT_API_KEY` / `ABUSEIPDB_API_KEY`; el log del run lo confirma (`VirusTotal omitido: falta VT_API_KEY`).
- **El run tarda ~10 minutos**: normal con VirusTotal activo (rate limit del plan gratuito) — no lo canceles.
- **Push rechazado (`fetch first`)**: usa la versión actual del workflow, que serializa ejecuciones y rebasa antes de publicar.
- **El cron deja de ejecutarse**: GitHub pausa los schedules tras 60 días sin actividad; los commits del bot cuentan como actividad, así que con que funcione no se pausará.

---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-07-30 19:52 UTC · **IOCs recolectados:** 1696 · **CVEs KEV recientes:** 12

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `83[.]168[.]69[.]141:9481` | ip:port | Mirai | ThreatFox | 2026-07-30 19:23:18 UTC |
| 75 (alta) | alta | `45[.]90[.]163[.]37:35342` | ip:port | Mirai | ThreatFox | 2026-07-29 19:44:37 UTC |
| 71 (alta) | critica | `103[.]75[.]183[.]232:31337` | ip:port | Sliver | ThreatFox | 2026-07-30 09:03:57 UTC |
| 71 (alta) | alta | `91[.]199[.]133[.]133:8080` | ip:port | Mirai | ThreatFox | 2026-07-29 19:46:24 UTC |
| 69 (media) | critica | `144[.]172[.]93[.]33:80` | ip:port | Havoc | ThreatFox | 2026-07-30 09:43:35 UTC |
| 69 (media) | alta | `90b30f19d6dc61e4c84539324b839f4fec0b4814` | sha1_hash | SalatStealer | ThreatFox | 2026-07-29 23:26:38 UTC |
| 69 (media) | alta | `fe2d63e6c7d907019e44bb4a2138b236` | md5_hash | SalatStealer | ThreatFox | 2026-07-29 23:26:38 UTC |
| 69 (media) | alta | `ebd767d125e3d336657c2c6d1d06ed3089e19d02` | sha1_hash | SalatStealer | ThreatFox | 2026-07-29 23:26:37 UTC |
| 69 (media) | alta | `24aee3a61aecc5ec58375d838322010b` | md5_hash | SalatStealer | ThreatFox | 2026-07-29 23:26:37 UTC |
| 69 (media) | alta | `fce8ba975afa37727c61a9940c81c8e20da1de724f8a10b44b89d7ed44d7f526` | sha256_hash | SalatStealer | ThreatFox | 2026-07-29 23:26:37 UTC |
| 69 (media) | alta | `2cc5df961162f8f9cea6273cb82756ea591f1d5ee62ee5cd0f19bc12cda7b7d3` | sha256_hash | SalatStealer | ThreatFox | 2026-07-29 23:26:36 UTC |
| 66 (media) | alta | `194[.]59[.]31[.]51:8808` | ip:port | AsyncRAT | ThreatFox | 2026-07-29 19:44:28 UTC |
| 66 (media) | alta | `194[.]59[.]31[.]51:7707` | ip:port | AsyncRAT | ThreatFox | 2026-07-29 19:44:27 UTC |
| 65 (media) | media | `4a2bb63c5007379ea2dffb8669743af4cc773844` | sha1_hash | Kuiper | ThreatFox | 2026-07-29 23:26:35 UTC |
| 63 (media) | media | `0664d2922ea22920f609f17e3f5b512623d940b5` | sha1_hash | Kuiper | ThreatFox | 2026-07-30 11:25:15 UTC |
| 63 (media) | media | `af38775c7c7dc7046f77a7748b89933d` | md5_hash | Kuiper | ThreatFox | 2026-07-30 11:25:15 UTC |
| 62 (media) | media | `159[.]223[.]4[.]28:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-30 10:47:13 UTC |
| 62 (media) | media | `134[.]122[.]48[.]153:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-30 10:47:12 UTC |
| 61 (media) | media | `27550b8c15c5a7cf5568dd1d2e1243b510eb983a7eb8ff5ddc9974415e5a0093` | sha256_hash | Kuiper | ThreatFox | 2026-07-30 11:25:14 UTC |
| 61 (media) | media | `174[.]138[.]11[.]120:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-30 10:47:13 UTC |
| 60 (media) | media | `hxxp://45[.]95[.]147[.]178/hima_data/index[.]php` | url | Unknown malware | ThreatFox | 2026-07-30 19:33:51 UTC |
| 60 (media) | media | `hxxps://laurelcloister[.]top/role/logout-header[.]js` | url | SmartApeSG | ThreatFox | 2026-07-30 12:28:04 UTC |
| 59 (media) | alta | `voucher-01-static[.]com` | domain | PureLogs Stealer | ThreatFox | 2026-07-30 19:16:19 UTC |
| 59 (media) | alta | `adobeartsia[.]com` | domain | PureLogs Stealer | ThreatFox | 2026-07-30 19:16:16 UTC |
| 59 (media) | media | `download[.]stopbanningmydomains[.]ru` | domain | XMRIG | ThreatFox | 2026-07-30 17:13:39 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-20316 | Cisco Secure Firewall Management Center (FMC) | 2026-07-29 | Unknown |
| CVE-2025-68686 | Fortinet FortiOS | 2026-07-27 | Unknown |
| CVE-2026-16812 | Arista VeloCloud Orchestrator | 2026-07-27 | Unknown |
| CVE-2026-16232 | Check Point SmartConsole | 2026-07-22 | Unknown |
| CVE-2026-50522 | Microsoft SharePoint | 2026-07-22 | Unknown |
| CVE-2026-60137 | WordPress Core | 2026-07-21 | Unknown |
| CVE-2026-63030 | WordPress Core | 2026-07-21 | Unknown |
| CVE-2026-0770 | Langflow Langflow | 2026-07-21 | Unknown |
| CVE-2021-27137 | DD-WRT DD-WRT | 2026-07-21 | Unknown |
| CVE-2026-58644 | Microsoft SharePoint | 2026-07-16 | Unknown |
| CVE-2026-25089 | Fortinet FortiSandbox | 2026-07-16 | Unknown |
| CVE-2026-39808 | Fortinet FortiSandbox | 2026-07-16 | Unknown |
<!-- CTI:END -->
