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
**Última actualización:** 2026-07-20 09:36 UTC · **IOCs recolectados:** 771 · **CVEs KEV recientes:** 16

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `8c21b2fbded2faeb6db2e7a20c513cdb` | md5_hash | RedLine Stealer | ThreatFox | 2026-07-20 01:16:13 UTC |
| 77 (alta) | alta | `b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0` | sha256_hash | RedLine Stealer | ThreatFox | 2026-07-20 01:16:12 UTC |
| 77 (alta) | alta | `38b837cc5fe814ca9580f9029386aa405f8e94df` | sha1_hash | RedLine Stealer | ThreatFox | 2026-07-20 01:16:12 UTC |
| 71 (alta) | media | `5a8031f3c9ff3c65ebaa0aa60f9e59feba83c71c` | sha1_hash | Phorpiex | ThreatFox | 2026-07-20 01:16:10 UTC |
| 71 (alta) | media | `b0c4fe17a83df1621ce3db824684bb55` | md5_hash | Phorpiex | ThreatFox | 2026-07-20 01:16:10 UTC |
| 71 (alta) | media | `2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e` | sha256_hash | Phorpiex | ThreatFox | 2026-07-20 01:16:09 UTC |
| 62 (media) | alta | `9c986d7e311ce1e8db7bd65b8271a87d` | md5_hash | ValleyRAT | ThreatFox | 2026-07-20 01:16:11 UTC |
| 62 (media) | alta | `40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145` | sha256_hash | ValleyRAT | ThreatFox | 2026-07-20 01:16:10 UTC |
| 62 (media) | alta | `5c542d609013e48e6095af6ce5ef28208a35bb3f` | sha1_hash | ValleyRAT | ThreatFox | 2026-07-20 01:16:10 UTC |
| 60 (media) | critica | `124[.]220[.]6[.]158:8097` | ip:port | Cobalt Strike | ThreatFox | 2026-07-20 03:05:03 UTC |
| 60 (media) | critica | `116[.]198[.]233[.]179:3443` | ip:port | Cobalt Strike | ThreatFox | 2026-07-19 13:05:07 UTC |
| 60 (media) | critica | `117[.]72[.]178[.]246:9200` | ip:port | Cobalt Strike | ThreatFox | 2026-07-19 13:05:05 UTC |
| 60 (media) | critica | `179[.]43[.]186[.]214:22` | ip:port | Cobalt Strike | ThreatFox | 2026-07-19 12:05:07 UTC |
| 60 (media) | critica | `104[.]248[.]201[.]191:22` | ip:port | Cobalt Strike | ThreatFox | 2026-07-19 11:05:06 UTC |
| 59 (media) | alta | `137[.]184[.]135[.]42:9034` | ip:port | Aisuru | ThreatFox | 2026-07-20 06:28:31 UTC |
| 59 (media) | media | `103[.]142[.]147[.]19:5230` | ip:port | Unknown malware | ThreatFox | 2026-07-20 02:05:07 UTC |
| 59 (media) | critica | `120[.]76[.]143[.]184:3306` | ip:port | Cobalt Strike | ThreatFox | 2026-07-20 02:05:07 UTC |
| 59 (media) | alta | `52f56cc1abe3ed2f437aaae0c74f5db9` | md5_hash | Venus Stealer | ThreatFox | 2026-07-20 01:16:12 UTC |
| 59 (media) | alta | `5f85e22acb86ebc9031256efb11af9f1eed58621312a0c0bf448fe699e809c92` | sha256_hash | Venus Stealer | ThreatFox | 2026-07-20 01:16:11 UTC |
| 59 (media) | alta | `196515f98d4a043751629ffdc6e4fc371391b5b3` | sha1_hash | Venus Stealer | ThreatFox | 2026-07-20 01:16:11 UTC |
| 59 (media) | alta | `0bf07f316fe80ace56c947a2021e56a07dab0d6b` | sha1_hash | Venus Stealer | ThreatFox | 2026-07-20 01:16:09 UTC |
| 59 (media) | alta | `d0b2dbfbc3a1d6474628f5268cf884fc` | md5_hash | Venus Stealer | ThreatFox | 2026-07-20 01:16:09 UTC |
| 59 (media) | alta | `602862693c2edba1df17afd61b4fcdc3a5ca139f` | sha1_hash | ValleyRAT | ThreatFox | 2026-07-20 01:16:08 UTC |
| 59 (media) | alta | `137[.]184[.]135[.]42:8443` | ip:port | Aisuru | ThreatFox | 2026-07-19 20:10:38 UTC |
| 59 (media) | alta | `137[.]184[.]135[.]42:34567` | ip:port | Aisuru | ThreatFox | 2026-07-19 20:09:47 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-58644 | Microsoft SharePoint | 2026-07-16 | Unknown |
| CVE-2026-25089 | Fortinet FortiSandbox | 2026-07-16 | Unknown |
| CVE-2026-39808 | Fortinet FortiSandbox | 2026-07-16 | Unknown |
| CVE-2026-46817 | Oracle E-Business Suite | 2026-07-15 | Unknown |
| CVE-2023-4346 | KNX Association KNX Protocol Connection Authorization Option 1 | 2026-07-15 | Unknown |
| CVE-2026-56155 | Microsoft Active Directory Federation Services | 2026-07-14 | Unknown |
| CVE-2026-56164 | Microsoft SharePoint Server | 2026-07-14 | Unknown |
| CVE-2026-15409 | SonicWall SMA1000 Appliances | 2026-07-14 | Unknown |
| CVE-2026-15410 | SonicWall SMA1000 Appliances | 2026-07-14 | Unknown |
| CVE-2008-4128 | Cisco IOS | 2026-07-13 | Unknown |
| CVE-2026-56291 | Balbooa Forms | 2026-07-10 | Unknown |
| CVE-2026-48939 | iCagenda iCagenda | 2026-07-10 | Unknown |
| CVE-2026-48908 | JoomShaper SP Page Builder | 2026-07-07 | Unknown |
| CVE-2026-55255 | Langflow Langflow | 2026-07-07 | Unknown |
| CVE-2026-56290 | Joomlack Page Builder | 2026-07-07 | Unknown |
| CVE-2026-48282 | Adobe ColdFusion | 2026-07-07 | Unknown |
<!-- CTI:END -->
