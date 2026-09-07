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
**Última actualización:** 2026-09-07 12:17 UTC · **IOCs recolectados:** 1797 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `134[.]209[.]251[.]50:8001` | ip:port | Aisuru | ThreatFox | 2026-09-07 05:44:27 UTC |
| 77 (alta) | alta | `134[.]209[.]251[.]50:8080` | ip:port | Aisuru | ThreatFox | 2026-09-07 05:44:26 UTC |
| 73 (alta) | alta | `180[.]93[.]115[.]26:80` | ip:port | Mirai | ThreatFox | 2026-09-06 19:44:18 UTC |
| 71 (alta) | alta | `91[.]92[.]40[.]108:9111` | ip:port | Unknown RAT | ThreatFox | 2026-09-07 06:36:59 UTC |
| 71 (alta) | alta | `90bbefd7f59df783c656d143564b4f7b8a7fc7d76517325127d1b3f5a51b757b` | sha256_hash | PureLogs Stealer | ThreatFox | 2026-09-07 05:44:28 UTC |
| 68 (media) | media | `94[.]154[.]43[.]200:606` | ip:port | Unknown malware | ThreatFox | 2026-09-07 05:44:24 UTC |
| 68 (media) | media | `94[.]154[.]43[.]200:80` | ip:port | Unknown malware | ThreatFox | 2026-09-07 05:44:24 UTC |
| 66 (media) | alta | `184[.]75[.]208[.]10:49006` | ip:port | Remcos | ThreatFox | 2026-09-07 08:18:08 UTC |
| 61 (media) | alta | `64[.]225[.]107[.]48:8080` | ip:port | Aisuru | ThreatFox | 2026-09-07 09:41:48 UTC |
| 61 (media) | alta | `64[.]225[.]107[.]48:8001` | ip:port | Aisuru | ThreatFox | 2026-09-07 05:44:28 UTC |
| 60 (media) | alta | `130[.]12[.]182[.]211:2404` | ip:port | Remcos | ThreatFox | 2026-09-06 23:20:38 UTC |
| 59 (media) | media | `144[.]225[.]137[.]26:80` | ip:port | VShell | ThreatFox | 2026-09-07 05:05:06 UTC |
| 58 (media) | alta | `hxxps://haziranaltyapi[.]com/welcome/` | url | Unknown Stealer | ThreatFox | 2026-09-07 11:54:11 UTC |
| 58 (media) | alta | `hxxps://hybridmediaworks[.]net/gplznr/` | url | Unknown Stealer | ThreatFox | 2026-09-07 11:54:09 UTC |
| 58 (media) | alta | `hxxps://simecsoft[.]myscriptcase[.]com/zr/` | url | Unknown Stealer | ThreatFox | 2026-09-07 11:54:08 UTC |
| 58 (media) | alta | `hxxps://sportspromotion[.]mx/trackplanzer/` | url | Unknown Stealer | ThreatFox | 2026-09-07 11:54:05 UTC |
| 58 (media) | alta | `hxxps://capmentor[.]vn/planzer/` | url | Unknown Stealer | ThreatFox | 2026-09-07 11:54:05 UTC |
| 58 (media) | alta | `hxxps://capmentor[.]vn/plo/` | url | Unknown Stealer | ThreatFox | 2026-09-07 11:54:04 UTC |
| 58 (media) | alta | `009a1e2d7a582a24e50cf2ffc2a005482c8e38f22bf5ed416053855f8d054e1e` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:38 UTC |
| 58 (media) | alta | `09739441ed4599bac2f8159028f772f71e4b25c8badfff95574e56d7384f3dbe` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:38 UTC |
| 58 (media) | alta | `12810854c8b2c391b23e2e18b013e873d0369b0637aa3cf993136c07188ba3b8` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:38 UTC |
| 58 (media) | alta | `2f02b09d61d432134e994ad671258f523bbf289ae6091fd4eae192c60bd51b6f` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:37 UTC |
| 58 (media) | alta | `5db1b6d52faf60b4f32d6fd0c7c938e4d05d29a14c32ded4a9668357c08b6a91` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:37 UTC |
| 58 (media) | alta | `6cf1b5e92a9c0756f597a5ddefb38eba32961c52efac7ab2a0aa52c639a8fc53` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:37 UTC |
| 58 (media) | alta | `7007a78d50a993cb174c685eba96eb442c9507e38fd9d8e5dffc712f613ec110` | sha256_hash | CurlBack RAT | ThreatFox, OTX | 2026-09-07 09:00:36 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-85046 | Google Chromium V8 | 2026-09-04 | Unknown |
| CVE-2026-59822 | BerriAI LiteLLM | 2026-09-02 | Unknown |
| CVE-2026-48710 | Kludex Starlette | 2026-09-02 | Unknown |
| CVE-2026-49869 | Kestra Kestra OSS | 2026-09-02 | Unknown |
| CVE-2026-82329 | JFrog Artifactory | 2026-09-02 | Unknown |
| CVE-2026-9586 | Sangoma Switchvox | 2026-09-02 | Unknown |
| CVE-2026-83548 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-83549 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-82078 | PaperCut NG/MF | 2026-08-31 | Unknown |
| CVE-2026-81578 | PaperCut NG/MF | 2026-08-31 | Unknown |
| CVE-2023-49105 | ownCloud ownCloud | 2026-08-27 | Unknown |
| CVE-2026-53362 | Linux Kernel | 2026-08-27 | Unknown |
| CVE-2026-66384 | JFrog Artifactory | 2026-08-27 | Unknown |
| CVE-2021-23758 | Ajax.NET Professional Ajax.NET Professional | 2026-08-26 | Unknown |
| CVE-2015-3246 | Red Hat Libuser | 2026-08-26 | Unknown |
| CVE-2015-5287 | Red Hat Automatic Bug Reporting Tool | 2026-08-26 | Unknown |
| CVE-2022-0995 | Linux Kernel | 2026-08-26 | Unknown |
| CVE-2026-8452 | Citrix NetScaler ADC and NetScaler Gateway | 2026-08-26 | Unknown |
| CVE-2019-1068 | Microsoft SQL Server | 2026-08-26 | Unknown |
| CVE-2026-60004 | Gitea Gitea | 2026-08-25 | Unknown |
| CVE-2026-21962 | Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in | 2026-08-24 | Unknown |
<!-- CTI:END -->
