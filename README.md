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
**Última actualización:** 2026-07-23 14:26 UTC · **IOCs recolectados:** 1151 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `45[.]74[.]3[.]37:9` | ip:port | Mirai | ThreatFox | 2026-07-23 05:11:38 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]102:345` | ip:port | Mirai | ThreatFox | 2026-07-23 05:26:19 UTC |
| 71 (alta) | alta | `91[.]92[.]42[.]213:1312` | ip:port | Mirai | ThreatFox | 2026-07-22 14:17:30 UTC |
| 69 (media) | alta | `bd6c7efbdd13e521de1f00c22b2bc8104e2c10c3` | sha1_hash | Venus Stealer | ThreatFox | 2026-07-23 01:48:26 UTC |
| 69 (media) | alta | `512bb4a122568ab91f86b9bb716739a5` | md5_hash | Venus Stealer | ThreatFox | 2026-07-23 01:48:26 UTC |
| 69 (media) | alta | `72935b04a5ab38bfd9240514cd205935f7ffe921ae5a61d0b389495235feaeb3` | sha256_hash | Venus Stealer | ThreatFox | 2026-07-23 01:48:25 UTC |
| 68 (media) | alta | `ae58622241092d9ba1d2426a875119a7` | md5_hash | Formbook | ThreatFox | 2026-07-23 01:48:30 UTC |
| 68 (media) | alta | `ef8f821a54f3f07ae8036c005c7656aa755f8078de6c70a1a8f72ebafe35fe69` | sha256_hash | Formbook | ThreatFox | 2026-07-23 01:48:29 UTC |
| 68 (media) | alta | `514853c657defc7e450cce08e5884fce6c0c1066` | sha1_hash | Formbook | ThreatFox | 2026-07-23 01:48:29 UTC |
| 68 (media) | media | `709ea37c2d8c2bc532b065d95af124d9a7dab1c1` | sha1_hash | Kuiper | ThreatFox | 2026-07-23 01:48:25 UTC |
| 68 (media) | media | `0a635961383389c90b59d8104d1a70cc` | md5_hash | Kuiper | ThreatFox | 2026-07-23 01:48:25 UTC |
| 68 (media) | media | `ee313cc02f4f644e2a80a407a4971faa06df65ac484d1bd0f57e62eb2c55d8bd` | sha256_hash | Kuiper | ThreatFox | 2026-07-23 01:48:24 UTC |
| 67 (media) | alta | `9460a4fc5ef4a5f6a8a3b851398c0b44` | md5_hash | Vidar | ThreatFox | 2026-07-23 01:48:28 UTC |
| 67 (media) | alta | `75a0d2b32af70bcbffb8ed27215b60c924efd460a85cd21013fc1b83e1d2fdc8` | sha256_hash | Vidar | ThreatFox | 2026-07-23 01:48:27 UTC |
| 67 (media) | alta | `4b21892cf36b9e75f7ce2ee7e42227187a79f5e9` | sha1_hash | Vidar | ThreatFox | 2026-07-23 01:48:27 UTC |
| 67 (media) | media | `3eb6186b67791934b8e94d9ba5324abd` | md5_hash | Kuiper | ThreatFox | 2026-07-23 01:48:22 UTC |
| 66 (media) | media | `77[.]247[.]88[.]88:46996` | ip:port | Unknown malware | ThreatFox | 2026-07-23 05:12:52 UTC |
| 65 (media) | alta | `face4acb042c323fca0ead3463d0e896` | md5_hash | RN Stealer | ThreatFox | 2026-07-23 01:48:29 UTC |
| 65 (media) | alta | `4c897108e8e793d6904110928c996815c302d6975c9bc61162149e855a963d50` | sha256_hash | RN Stealer | ThreatFox | 2026-07-23 01:48:28 UTC |
| 65 (media) | alta | `b3f6efdbac7547ee988417c636a9eea999e8eebb` | sha1_hash | RN Stealer | ThreatFox | 2026-07-23 01:48:28 UTC |
| 64 (media) | alta | `91[.]92[.]42[.]213:80` | ip:port | Mirai | ThreatFox | 2026-07-23 05:13:13 UTC |
| 60 (media) | alta | `137[.]184[.]135[.]42:12345` | ip:port | Aisuru | ThreatFox | 2026-07-23 05:11:40 UTC |
| 60 (media) | media | `4b1ff336071a687cd35ef14ad285c854` | md5_hash | Coinminer | ThreatFox | 2026-07-23 01:48:24 UTC |
| 60 (media) | alta | `f9f49c54ef5a103b4efdfba8fe7bc54e` | md5_hash | Vidar | ThreatFox | 2026-07-23 01:48:23 UTC |
| 60 (media) | media | `ab161caf790e0722f10c95343132e648a3d64185ed575834e5a9853c9dca7618` | sha256_hash | Coinminer | ThreatFox | 2026-07-23 01:48:23 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-16232 | Check Point SmartConsole | 2026-07-22 | Unknown |
| CVE-2026-50522 | Microsoft SharePoint | 2026-07-22 | Unknown |
| CVE-2026-60137 | WordPress Core | 2026-07-21 | Unknown |
| CVE-2026-63030 | WordPress Core | 2026-07-21 | Unknown |
| CVE-2026-0770 | Langflow Langflow | 2026-07-21 | Unknown |
| CVE-2021-27137 | DD-WRT DD-WRT | 2026-07-21 | Unknown |
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
<!-- CTI:END -->
