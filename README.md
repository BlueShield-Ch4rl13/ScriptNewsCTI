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
**Última actualización:** 2026-07-29 19:35 UTC · **IOCs recolectados:** 2072 · **CVEs KEV recientes:** 14

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 80 (alta) | alta | `217[.]60[.]195[.]187:1302` | ip:port | Mirai | ThreatFox | 2026-07-29 07:41:38 UTC |
| 75 (alta) | alta | `45[.]90[.]163[.]37:35342` | ip:port | Mirai | ThreatFox | 2026-07-29 17:55:19 UTC |
| 75 (alta) | alta | `91[.]199[.]133[.]133:443` | ip:port | Mirai | ThreatFox | 2026-07-29 07:41:16 UTC |
| 75 (alta) | alta | `45[.]74[.]3[.]37:9111` | ip:port | Mirai | ThreatFox | 2026-07-29 07:41:05 UTC |
| 63 (media) | media | `134[.]122[.]154[.]180:80` | ip:port | VShell | ThreatFox | 2026-07-29 15:05:06 UTC |
| 63 (media) | media | `134[.]122[.]154[.]180:8080` | ip:port | VShell | ThreatFox | 2026-07-29 15:05:05 UTC |
| 61 (media) | alta | `217[.]165[.]57[.]225:8808` | ip:port | AsyncRAT | ThreatFox | 2026-07-29 03:05:09 UTC |
| 60 (media) | critica | `41[.]216[.]189[.]163:22` | ip:port | AdaptixC2 | ThreatFox | 2026-07-29 12:05:06 UTC |
| 60 (media) | media | `goodpix21341[.]digital` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:32 UTC |
| 60 (media) | media | `pixellanalit213[.]buzz` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:30 UTC |
| 60 (media) | media | `googlanalitlcs[.]icu` | domain | IClickFix | ThreatFox | 2026-07-29 07:41:55 UTC |
| 59 (media) | media | `172[.]86[.]90[.]64:443` | ip:port | Unknown malware | ThreatFox | 2026-07-29 19:05:05 UTC |
| 59 (media) | critica | `118[.]31[.]18[.]77:8080` | ip:port | Cobalt Strike | ThreatFox | 2026-07-29 14:05:06 UTC |
| 59 (media) | media | `usual-pixx12[.]digital` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:36 UTC |
| 59 (media) | media | `sodapixerr[.]world` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:34 UTC |
| 59 (media) | media | `pixelart341[.]buzz` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:31 UTC |
| 59 (media) | media | `visitorflow[.]icu` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:31 UTC |
| 58 (media) | media | `bs-deliver-e817[.]61d8f0e6ac62c139abd08ba5[.]workers[.]dev` | domain | Unknown malware | ThreatFox | 2026-07-29 13:27:06 UTC |
| 58 (media) | media | `119[.]45[.]190[.]210:27017` | ip:port | Unknown malware | ThreatFox | 2026-07-29 13:05:05 UTC |
| 58 (media) | media | `199[.]30[.]90[.]240:54321` | ip:port | Unknown malware | ThreatFox | 2026-07-29 08:05:04 UTC |
| 58 (media) | media | `analyze-me6[.]world` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:37 UTC |
| 58 (media) | media | `drampix2421[.]xyz` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:32 UTC |
| 58 (media) | media | `fire-grass12[.]life` | domain | IClickFix | ThreatFox | 2026-07-29 07:42:30 UTC |
| 58 (media) | alta | `157[.]20[.]182[.]21:9992` | ip:port | AsyncRAT | ThreatFox | 2026-07-29 07:42:04 UTC |
| 57 (media) | alta | `20[.]215[.]40[.]6:7000` | ip:port | Quasar RAT | ThreatFox | 2026-07-29 19:05:05 UTC |

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
| CVE-2026-46817 | Oracle E-Business Suite | 2026-07-15 | Unknown |
| CVE-2023-4346 | KNX Association KNX Protocol Connection Authorization Option 1 | 2026-07-15 | Unknown |
<!-- CTI:END -->
