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
**Última actualización:** 2026-07-19 08:37 UTC · **IOCs recolectados:** 708 · **CVEs KEV recientes:** 16

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 68 (media) | media | `hxxp://95[.]164[.]53[.]214:5554/d[.]bat` | url | Unknown malware | ThreatFox, URLhaus | 2026-07-19 07:37:55 UTC |
| 68 (media) | media | `hxxp://93[.]152[.]224[.]29/VMvDWLT7AqpC45hhHf` | url | Unknown malware | ThreatFox, URLhaus | 2026-07-19 07:37:54 UTC |
| 68 (media) | alta | `b1a6dba6636b519d76d7219f6264ac9f1456681c0855baef954fb435d3e25ce5` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:30 UTC |
| 68 (media) | alta | `e987bb8b32facef51c3cc5a94bd51e01d8c3be8a19c106de70147ab5ce84dc66` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:29 UTC |
| 68 (media) | alta | `6e709fb9b09d9f8318724a8620812f55411a3ea49de6319c4832885547773ddd` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:29 UTC |
| 68 (media) | alta | `b4acd1ab65624b694946b1181bba0732bb63c88c51b8334914c26c1805b2e1aa` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:28 UTC |
| 68 (media) | alta | `21c5f4a04173a5176d60b06095bf5d25e0022ffbe304601e368eccf718587dc8` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:27 UTC |
| 68 (media) | alta | `ec442a132f27486d1dfa3faa92c03e10012afe2b8de39fa9b42b367f7971c989` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:27 UTC |
| 68 (media) | alta | `9538c8a2edeaa8667134a469d03a7057ddc1e753ce1e5250f92f01c1097fcb1d` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:26 UTC |
| 67 (media) | alta | `bf38b3e5d645c78377599a6c218a347312c5a3daef693c7931f2710806d85317` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:30 UTC |
| 67 (media) | media | `23[.]94[.]27[.]110:3478` | ip:port | Unknown malware | ThreatFox | 2026-07-19 01:05:05 UTC |
| 67 (media) | media | `23[.]94[.]27[.]110:111` | ip:port | Unknown malware | ThreatFox | 2026-07-19 00:05:04 UTC |
| 67 (media) | media | `23[.]94[.]27[.]110:631` | ip:port | Unknown malware | ThreatFox | 2026-07-19 00:05:04 UTC |
| 66 (media) | alta | `103[.]83[.]87[.]122:80` | ip:port | Mirai | ThreatFox | 2026-07-19 07:08:39 UTC |
| 66 (media) | alta | `103[.]83[.]87[.]122:2222` | ip:port | Mirai | ThreatFox | 2026-07-19 07:08:39 UTC |
| 66 (media) | alta | `103[.]83[.]87[.]122:4444` | ip:port | Mirai | ThreatFox | 2026-07-19 07:08:39 UTC |
| 66 (media) | alta | `103[.]83[.]87[.]122:8060` | ip:port | Mirai | ThreatFox | 2026-07-19 07:08:38 UTC |
| 66 (media) | alta | `f5cb6dadaee4399a1f014ef5946d0a4c1af578d15ff078e725e0757f28dc8493` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:30 UTC |
| 65 (media) | media | `hxxps://natural-health-news[.]com/Verify[.]msi?I` | url | Unknown malware | ThreatFox, URLhaus | 2026-07-19 07:37:55 UTC |
| 65 (media) | media | `hxxp://178[.]17[.]59[.]195:5506/ll[.]vbs` | url | Unknown malware | ThreatFox, URLhaus | 2026-07-19 07:37:54 UTC |
| 65 (media) | alta | `0d64cd75599dea5b8cf393b6e2b709f51b3971e64b96920e0707020e22ee7953` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:29 UTC |
| 64 (media) | media | `hxxps://gerenland[.]click/flask/whales[.]msi` | url | Unknown malware | ThreatFox, URLhaus | 2026-07-19 07:37:54 UTC |
| 64 (media) | media | `hxxps://gerenland[.]click/api/stale[.]msi` | url | Unknown malware | ThreatFox, URLhaus | 2026-07-19 07:28:19 UTC |
| 64 (media) | alta | `f38d748d9ea29424c28744c52bcd1d14328d49fcb604ca08fab3547ec500d6f0` | sha256_hash | Mirai | ThreatFox | 2026-07-19 07:08:28 UTC |
| 62 (media) | critica | `101[.]42[.]255[.]92:8082` | ip:port | Cobalt Strike | ThreatFox | 2026-07-19 06:05:05 UTC |

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
