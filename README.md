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
**Última actualización:** 2026-08-10 02:21 UTC · **IOCs recolectados:** 546 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 81 (alta) | alta | `94[.]154[.]43[.]87:8082` | ip:port | Mirai | ThreatFox | 2026-08-09 06:30:55 UTC |
| 80 (alta) | media | `130[.]12[.]180[.]51:43782` | ip:port | RedTail | ThreatFox | 2026-08-10 01:41:54 UTC |
| 76 (alta) | alta | `161[.]35[.]48[.]40:9034` | ip:port | Aisuru | ThreatFox | 2026-08-09 12:27:57 UTC |
| 75 (alta) | alta | `79[.]143[.]191[.]7:8082` | ip:port | Mirai | ThreatFox | 2026-08-09 06:30:59 UTC |
| 71 (alta) | media | `hxxp://178[.]16[.]54[.]109/bolodo` | url | Phorpiex | ThreatFox, URLhaus | 2026-08-09 23:19:10 UTC |
| 71 (alta) | alta | `130[.]12[.]182[.]39:2700` | ip:port | AsyncRAT | ThreatFox | 2026-08-09 09:43:26 UTC |
| 66 (media) | alta | `180[.]93[.]116[.]41:56999` | ip:port | Mirai | ThreatFox | 2026-08-09 21:09:02 UTC |
| 65 (media) | alta | `5[.]83[.]150[.]71:4567` | ip:port | Quasar RAT | ThreatFox | 2026-08-09 08:05:09 UTC |
| 60 (media) | media | `183[.]60[.]226[.]2:110` | ip:port | Unknown malware | ThreatFox | 2026-08-09 05:05:05 UTC |
| 59 (media) | critica | `36[.]140[.]162[.]173:12443` | ip:port | Cobalt Strike | ThreatFox | 2026-08-09 13:05:07 UTC |
| 58 (media) | alta | `37[.]221[.]66[.]27:443` | ip:port | Nanocore RAT | ThreatFox | 2026-08-09 15:55:03 UTC |
| 57 (media) | media | `hxxps://fashion-chicken[.]com/x9i32md/w1/la02` | url | Unknown malware | ThreatFox | 2026-08-09 23:45:34 UTC |
| 57 (media) | alta | `46[.]151[.]182[.]200:60195` | ip:port | Mirai | ThreatFox | 2026-08-09 16:09:02 UTC |
| 57 (media) | media | `8[.]218[.]211[.]108:3232` | ip:port | Unknown malware | ThreatFox | 2026-08-09 14:05:06 UTC |
| 57 (media) | media | `31[.]7[.]62[.]178:12583` | ip:port | VShell | ThreatFox | 2026-08-09 14:05:05 UTC |
| 57 (media) | alta | `zfnv2q4q[.]dayvillelaundry[.]com` | domain | ClearFake | ThreatFox | 2026-08-09 09:49:31 UTC |
| 57 (media) | alta | `jhjokx[.]sweethannahs[.]com` | domain | ClearFake | ThreatFox | 2026-08-09 03:54:48 UTC |
| 57 (media) | alta | `sholap[.]sweethannahs[.]com` | domain | ClearFake | ThreatFox | 2026-08-09 03:24:14 UTC |
| 56 (media) | alta | `zgeetmr[.]enus-bpzone[.]com` | domain | ClearFake | ThreatFox | 2026-08-10 01:56:37 UTC |
| 56 (media) | alta | `hqwgki[.]habbofutbol[.]com` | domain | ClearFake | ThreatFox | 2026-08-10 01:13:27 UTC |
| 56 (media) | alta | `4lmn5pp8[.]eachway-multiplier[.]com` | domain | ClearFake | ThreatFox | 2026-08-10 01:07:44 UTC |
| 56 (media) | alta | `hxxps://vokhmiwmncjba[.]vivaldinotabot[.]com/s/psc4?cl` | url | Unknown Loader | ThreatFox | 2026-08-10 00:55:17 UTC |
| 56 (media) | alta | `5gghr1ol[.]eng-echoxen[.]us` | domain | ClearFake | ThreatFox | 2026-08-10 00:34:16 UTC |
| 56 (media) | alta | `zwqbnl[.]gtacauto[.]com` | domain | ClearFake | ThreatFox | 2026-08-10 00:26:58 UTC |
| 56 (media) | alta | `aqfcvod[.]en-usa-sugarmute[.]us` | domain | ClearFake | ThreatFox | 2026-08-10 00:15:47 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-8037 | Progress LoadMaster | 2026-08-07 | Unknown |
| CVE-2026-63077 | JetBrains TeamCity | 2026-08-05 | Unknown |
| CVE-2026-18556 | N-able N-central | 2026-08-04 | Unknown |
| CVE-2026-34486 | Apache Tomcat | 2026-08-04 | Unknown |
| CVE-2026-9198 | IBM Langflow | 2026-08-04 | Unknown |
| CVE-2026-18577 | N-able N-central | 2026-08-03 | Unknown |
| CVE-2026-20316 | Cisco Secure Firewall Management Center (FMC) | 2026-07-29 | Unknown |
| CVE-2025-68686 | Fortinet FortiOS | 2026-07-27 | Unknown |
| CVE-2026-16812 | Arista VeloCloud Orchestrator | 2026-07-27 | Unknown |
<!-- CTI:END -->
