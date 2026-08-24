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
**Última actualización:** 2026-08-24 13:10 UTC · **IOCs recolectados:** 1037 · **CVEs KEV recientes:** 12

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `94[.]154[.]43[.]249:2327` | ip:port | Mirai | ThreatFox | 2026-08-24 07:46:06 UTC |
| 60 (media) | alta | `167[.]99[.]194[.]254:8080` | ip:port | Aisuru | ThreatFox | 2026-08-24 12:38:13 UTC |
| 60 (media) | alta | `hxxp://192[.]253[.]248[.]181/api/v1/bot/actions/d51c30267c864160a1da8ba3d183cdd3` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:28 UTC |
| 60 (media) | alta | `hxxp://86[.]54[.]25[.]213/d/unix23269396` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:28 UTC |
| 60 (media) | alta | `hxxp://192[.]253[.]248[.]181/api/v1/getscpt/jaicharan` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:27 UTC |
| 60 (media) | alta | `192[.]253[.]248[.]181:80` | ip:port | Unknown Stealer | ThreatFox | 2026-08-23 16:11:24 UTC |
| 60 (media) | alta | `hxxps://aprettopizza[.]world/live/` | url | Latrodectus | ThreatFox | 2026-08-23 16:11:12 UTC |
| 59 (media) | alta | `95871105a8ca339c39ede4b2da1e2d30989b5a91395b808ba81f3cf9f7ed0b14` | sha256_hash | Mirai | ThreatFox | 2026-08-24 07:45:48 UTC |
| 59 (media) | alta | `185[.]157[.]163[.]138:50810` | ip:port | Remcos | ThreatFox | 2026-08-24 01:25:03 UTC |
| 59 (media) | alta | `hxxps://peermangoz[.]me/live/` | url | Latrodectus | ThreatFox | 2026-08-23 16:11:13 UTC |
| 59 (media) | alta | `185[.]53[.]179[.]136:443` | ip:port | Nanocore RAT | ThreatFox | 2026-08-23 14:30:05 UTC |
| 58 (media) | alta | `hxxp://86[.]54[.]25[.]213/log` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:29 UTC |
| 57 (media) | critica | `164[.]160[.]187[.]69:443` | ip:port | AdaptixC2 | ThreatFox | 2026-08-24 12:05:06 UTC |
| 57 (media) | critica | `8[.]163[.]59[.]20:8000` | ip:port | Cobalt Strike | ThreatFox | 2026-08-24 07:05:05 UTC |
| 57 (media) | media | `hxxps://hayvavillage[.]com/` | url | Unknown malware | ThreatFox | 2026-08-24 01:00:22 UTC |
| 57 (media) | alta | `156[.]225[.]94[.]168:80` | ip:port | ValleyRAT | ThreatFox | 2026-08-23 18:30:08 UTC |
| 57 (media) | media | `45[.]8[.]46[.]122:8545` | ip:port | Unknown malware | ThreatFox | 2026-08-23 18:05:04 UTC |
| 57 (media) | alta | `86[.]54[.]25[.]213:80` | ip:port | Unknown Stealer | ThreatFox | 2026-08-23 16:11:26 UTC |
| 57 (media) | alta | `123[.]13[.]48[.]131:55210` | ip:port | Mirai | ThreatFox | 2026-08-23 16:10:45 UTC |
| 56 (media) | media | `hxxp://zakuiru[.]shop:9048/projects` | url | Remus | ThreatFox | 2026-08-24 12:50:37 UTC |
| 56 (media) | media | `hxxp://zakuiru[.]shop:9048/attachments` | url | Remus | ThreatFox | 2026-08-24 12:35:26 UTC |
| 56 (media) | critica | `209[.]200[.]246[.]194:24563` | ip:port | Cobalt Strike | ThreatFox | 2026-08-24 11:47:51 UTC |
| 56 (media) | media | `hxxps://muhammadshakirp[.]com/` | url | Unknown malware | ThreatFox | 2026-08-24 11:30:22 UTC |
| 56 (media) | media | `hxxp://vexdico[.]shop:8539/orders` | url | Remus | ThreatFox | 2026-08-24 11:25:23 UTC |
| 56 (media) | alta | `z5rfxyfc[.]en-eng-geniusbrainsignal[.]com` | domain | ClearFake | ThreatFox | 2026-08-24 11:20:18 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-73570 | Synacor Zimbra Collaboration Suite (ZCS) | 2026-08-21 | Unknown |
| CVE-2026-72530 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-72529 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-64849 | MLflow MLflow | 2026-08-19 | Unknown |
| CVE-2026-33824 | Microsoft Internet Key Exchange (IKE) Service Extensions | 2026-08-18 | Unknown |
| CVE-2026-59310 | Broadcom VMware vCenter | 2026-08-18 | Unknown |
| CVE-2026-55040 | Microsoft SharePoint | 2026-08-18 | Unknown |
| CVE-2026-65400 | Apple macOS | 2026-08-18 | Unknown |
| CVE-2025-62593 | Ray-Project Ray | 2026-08-17 | Unknown |
| CVE-2026-20349 | Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD)  | 2026-08-11 | Unknown |
| CVE-2026-68820 | Microsoft Windows Ancillary Function Driver for WinSock  | 2026-08-11 | Unknown |
| CVE-2026-72898 | Metabase Metabase | 2026-08-11 | Unknown |
<!-- CTI:END -->
