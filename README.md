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
**Última actualización:** 2026-08-03 03:42 UTC · **IOCs recolectados:** 765 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | media | `94[.]154[.]43[.]249:7777` | ip:port | XMRIG | ThreatFox | 2026-08-02 06:55:05 UTC |
| 75 (alta) | alta | `95[.]155[.]151[.]113:9506` | ip:port | Mirai | ThreatFox | 2026-08-02 06:55:18 UTC |
| 62 (media) | alta | `207[.]154[.]240[.]223:9034` | ip:port | Aisuru | ThreatFox | 2026-08-03 01:27:31 UTC |
| 62 (media) | alta | `bd216916031c63a5f3174bc27d64babf31294363f1b8274e4ab7d8802c46d91c` | sha256_hash | Mirai | ThreatFox | 2026-08-02 06:54:52 UTC |
| 61 (media) | alta | `207[.]154[.]240[.]223:8443` | ip:port | Aisuru | ThreatFox | 2026-08-02 06:54:54 UTC |
| 60 (media) | critica | `23[.]141[.]12[.]111:21` | ip:port | Cobalt Strike | ThreatFox | 2026-08-03 02:05:05 UTC |
| 60 (media) | alta | `wqok85qtq[.]net` | domain | Mirai | ThreatFox | 2026-08-02 06:54:47 UTC |
| 59 (media) | critica | `60[.]247[.]206[.]23:808` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 19:05:07 UTC |
| 59 (media) | critica | `43[.]166[.]246[.]26:993` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 11:05:06 UTC |
| 59 (media) | media | `101[.]37[.]210[.]236:8081` | ip:port | Unknown malware | ThreatFox | 2026-08-02 06:05:05 UTC |
| 59 (media) | media | `1[.]117[.]77[.]166:111` | ip:port | Unknown malware | ThreatFox | 2026-08-02 05:05:06 UTC |
| 59 (media) | media | `1[.]117[.]77[.]166:8082` | ip:port | Unknown malware | ThreatFox | 2026-08-02 05:05:06 UTC |
| 58 (media) | media | `85[.]137[.]240[.]26:17000` | ip:port | Unknown malware | ThreatFox | 2026-08-02 19:05:09 UTC |
| 58 (media) | critica | `156[.]224[.]18[.]21:25` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 19:05:06 UTC |
| 58 (media) | critica | `156[.]224[.]18[.]21:22` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 18:05:08 UTC |
| 58 (media) | critica | `156[.]224[.]18[.]21:110` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 08:05:08 UTC |
| 58 (media) | critica | `124[.]222[.]145[.]172:3306` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 08:05:07 UTC |
| 58 (media) | alta | `185[.]157[.]46[.]242:8808` | ip:port | AsyncRAT | ThreatFox | 2026-08-02 07:05:05 UTC |
| 58 (media) | critica | `43[.]166[.]246[.]26:110` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 07:05:04 UTC |
| 57 (media) | media | `hxxp://31[.]56[.]209[.]153/nz[.]sh` | url | Unknown malware | ThreatFox | 2026-08-03 02:40:49 UTC |
| 57 (media) | critica | `45[.]195[.]8[.]67:8080` | ip:port | AdaptixC2 | ThreatFox | 2026-08-02 23:05:06 UTC |
| 57 (media) | critica | `45[.]195[.]8[.]67:80` | ip:port | AdaptixC2 | ThreatFox | 2026-08-02 23:05:05 UTC |
| 57 (media) | alta | `165[.]245[.]219[.]184:8443` | ip:port | Aisuru | ThreatFox | 2026-08-02 22:47:29 UTC |
| 57 (media) | media | `106[.]52[.]255[.]211:19876` | ip:port | Unknown malware | ThreatFox | 2026-08-02 17:05:05 UTC |
| 57 (media) | critica | `101[.]42[.]176[.]50:80` | ip:port | Cobalt Strike | ThreatFox | 2026-08-02 11:05:09 UTC |

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
<!-- CTI:END -->
