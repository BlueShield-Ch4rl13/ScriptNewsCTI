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
**Última actualización:** 2026-08-08 18:56 UTC · **IOCs recolectados:** 1173 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 79 (alta) | media | `176[.]65[.]148[.]250:6556` | ip:port | XMRIG | ThreatFox | 2026-08-08 11:09:24 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]46:1337` | ip:port | Mirai | ThreatFox | 2026-08-08 16:47:48 UTC |
| 72 (alta) | alta | `94[.]154[.]43[.]97:9931` | ip:port | Mirai | ThreatFox | 2026-08-08 16:47:47 UTC |
| 72 (alta) | alta | `217[.]60[.]195[.]187:8529` | ip:port | Mirai | ThreatFox | 2026-08-08 16:47:46 UTC |
| 71 (alta) | alta | `217[.]60[.]195[.]187:80` | ip:port | Mirai | ThreatFox | 2026-08-08 09:45:29 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]12:32` | ip:port | Mirai | ThreatFox | 2026-08-08 07:33:27 UTC |
| 66 (media) | alta | `188[.]166[.]222[.]192:34567` | ip:port | Aisuru | ThreatFox | 2026-08-08 16:47:46 UTC |
| 64 (media) | media | `188[.]253[.]125[.]245:8080` | ip:port | VShell | ThreatFox | 2026-08-08 11:05:08 UTC |
| 64 (media) | media | `188[.]253[.]125[.]245:80` | ip:port | VShell | ThreatFox | 2026-08-08 11:05:08 UTC |
| 62 (media) | media | `hxxp://178[.]16[.]54[.]109/molakc` | url | Phorpiex | ThreatFox | 2026-08-08 06:35:29 UTC |
| 61 (media) | media | `hxxp://178[.]16[.]54[.]109/locopoco` | url | Phorpiex | ThreatFox | 2026-08-08 16:47:49 UTC |
| 59 (media) | media | `hxxp://176[.]65[.]148[.]250:6556/ok` | url | XMRIG | ThreatFox | 2026-08-08 11:09:24 UTC |
| 57 (media) | media | `139[.]212[.]143[.]218:22` | ip:port | Unknown malware | ThreatFox | 2026-08-08 18:05:06 UTC |
| 57 (media) | alta | `4pm3ff8r[.]tacticalk9familycoin[.]com` | domain | ClearFake | ThreatFox | 2026-08-08 17:56:11 UTC |
| 57 (media) | critica | `192[.]255[.]236[.]156:80` | ip:port | Cobalt Strike | ThreatFox | 2026-08-08 12:05:06 UTC |
| 57 (media) | media | `34[.]70[.]205[.]211:80` | ip:port | XMRIG | ThreatFox | 2026-08-08 11:09:21 UTC |
| 57 (media) | alta | `155[.]2[.]192[.]235:8041` | ip:port | Unknown RAT | ThreatFox | 2026-08-08 06:48:28 UTC |
| 57 (media) | alta | `167[.]99[.]64[.]180:9035` | ip:port | Aisuru | ThreatFox | 2026-08-08 06:35:38 UTC |
| 57 (media) | media | `tracklifefit[.]com[.]br` | domain | Unknown malware | ThreatFox | 2026-08-08 00:03:58 UTC |
| 57 (media) | alta | `217[.]60[.]97[.]106:6606` | ip:port | AsyncRAT | ThreatFox | 2026-08-07 19:45:24 UTC |
| 56 (media) | alta | `mwf64ejt[.]greaternewzionbc[.]org` | domain | ClearFake | ThreatFox | 2026-08-08 17:59:35 UTC |
| 56 (media) | alta | `myi88a45[.]eng-gutdrops[.]us` | domain | ClearFake | ThreatFox | 2026-08-08 12:00:04 UTC |
| 56 (media) | alta | `rkuepjvspjokrqjehy[.]nygyrowillmar[.]com` | domain | ClearFake | ThreatFox | 2026-08-08 11:53:24 UTC |
| 56 (media) | media | `43[.]143[.]94[.]53:22` | ip:port | Unknown malware | ThreatFox | 2026-08-08 11:05:05 UTC |
| 56 (media) | alta | `139[.]59[.]144[.]8:8080` | ip:port | Aisuru | ThreatFox | 2026-08-08 06:35:28 UTC |

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
