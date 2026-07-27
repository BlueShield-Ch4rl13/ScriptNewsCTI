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
**Última actualización:** 2026-07-27 10:12 UTC · **IOCs recolectados:** 2398 · **CVEs KEV recientes:** 16

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | media | `143[.]20[.]185[.]88:8081` | ip:port | Unknown malware | ThreatFox | 2026-07-26 13:10:34 UTC |
| 71 (alta) | alta | `93[.]152[.]221[.]140:1010` | ip:port | AsyncRAT | ThreatFox | 2026-07-26 19:45:49 UTC |
| 71 (alta) | media | `51[.]89[.]11[.]180:6000` | ip:port | Unknown malware | ThreatFox | 2026-07-26 16:44:27 UTC |
| 71 (alta) | media | `45[.]205[.]1[.]36:8081` | ip:port | Unknown malware | ThreatFox | 2026-07-26 13:10:34 UTC |
| 68 (media) | media | `73021a747bab23a60469f89a42ac4ff2a3d3531cd9d2f3d8816f1d97b46f6551` | sha256_hash | Unknown malware | ThreatFox | 2026-07-26 13:04:59 UTC |
| 68 (media) | media | `6491a2ccac96e64a37a5d18e62575b44ba7704159fbe21d06f83b712ba747c9d` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:47 UTC |
| 68 (media) | media | `a53dd987ba4c34030e10da19431fa7f81208c7ce010ec474bc62ee82dde6fa61` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:41 UTC |
| 67 (media) | media | `9d41737cb7aa161590fb9e32589f670da77e992a02778a6447cd0daf14100b8e` | sha256_hash | Unknown malware | ThreatFox | 2026-07-26 13:04:59 UTC |
| 67 (media) | media | `e0c6b4998e0c8c5e1a18f5af13c236809df2c7b281e8dba1038592c3e6e752f3` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:50 UTC |
| 67 (media) | media | `ee56b8f51fd5722918ff2082c0027cc6183429554bcf177ea20b17af7d46a2a4` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:48 UTC |
| 66 (media) | media | `07b8ca62d5b394842a09e05d06fa833d51504b69b1085eec49732e65594e5392` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:51 UTC |
| 66 (media) | media | `4b05cd307e64425075f3f651d3d07c381e87a8846976ca241733a6e1d7f892db` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:40 UTC |
| 66 (media) | media | `f105326c65e40d64430bc80c367485295b73d5255164f4b022868dc97b71955a` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:40 UTC |
| 65 (media) | alta | `hxxp://47[.]239[.]127[.]71/lib/xxx` | url | Mirai | ThreatFox, URLhaus | 2026-07-27 05:59:25 UTC |
| 65 (media) | media | `8abae386ec6aaa1d1bf03e39f339922053e4b66d7ebbbeba15701d3ecc183fb8` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:59 UTC |
| 65 (media) | media | `9697a161278f262022eb0cd80ac97e2b83349f79990fd6547d452d40cd422969` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:50 UTC |
| 65 (media) | media | `333774e3405c4e6ef3a663bb7fe5e9074f03a6c8bb080e0ff3bcc33eec848b30` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:49 UTC |
| 64 (media) | critica | `141[.]255[.]162[.]234:37422` | ip:port | Cobalt Strike | ThreatFox | 2026-07-26 23:45:57 UTC |
| 64 (media) | media | `85[.]11[.]167[.]31:8081` | ip:port | Unknown malware | ThreatFox | 2026-07-26 13:10:35 UTC |
| 64 (media) | media | `3268fb5f29930a2daaedb31db15c5c614d17963f5b241a60c36f5d5d32b08d50` | sha256_hash | Unknown malware | ThreatFox | 2026-07-26 13:04:59 UTC |
| 64 (media) | media | `d7c75c5258ea8467690ec1f710415e7f8234491d4873566515f15fb7e5e729a2` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:57 UTC |
| 64 (media) | media | `01d5fba3c3906d1fb26a6697644610f0f9f02140720de49edf907091669dbb8b` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:39 UTC |
| 63 (media) | media | `9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:38 UTC |
| 63 (media) | media | `672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:37 UTC |
| 62 (media) | media | `7247db5cefb311a3315946beb72f6f4469fef639d80541322d7b5f96b940d2ad` | sha256_hash | Jackskid | ThreatFox | 2026-07-26 10:59:52 UTC |

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
<!-- CTI:END -->
