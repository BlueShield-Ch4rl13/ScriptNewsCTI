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
**Última actualización:** 2026-10-16 11:16 UTC · **IOCs recolectados:** 2320 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `72[.]167[.]43[.]61:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:11 UTC |
| 77 (alta) | alta | `103[.]18[.]14[.]157:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:09 UTC |
| 76 (alta) | alta | `220[.]74[.]36[.]3:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:12 UTC |
| 76 (alta) | alta | `142[.]93[.]140[.]36:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:11 UTC |
| 76 (alta) | alta | `143[.]110[.]153[.]215:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:09 UTC |
| 75 (alta) | alta | `92[.]232[.]113[.]29:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:11 UTC |
| 71 (alta) | alta | `45[.]153[.]34[.]235:8765` | ip:port | Mirai | ThreatFox | 2026-10-16 09:45:09 UTC |
| 71 (alta) | alta | `91[.]92[.]43[.]221:80` | ip:port | Mirai | ThreatFox | 2026-10-16 06:10:48 UTC |
| 71 (alta) | media | `216[.]9[.]225[.]228:8765` | ip:port | Unknown malware | ThreatFox | 2026-10-16 06:10:41 UTC |
| 65 (media) | media | `hxxps://haven-post[.]com/curl/3evg00amsb/jx4r0tn568o5n8sm58[.]json` | url | AMOS | ThreatFox, URLhaus | 2026-10-16 08:48:37 UTC |
| 65 (media) | media | `hxxps://haven-post[.]com/f/zh2s2xptaamrnzpdyiq0ng/vj1ury4s` | url | AMOS | ThreatFox, URLhaus | 2026-10-16 08:48:37 UTC |
| 64 (media) | critica | `107[.]172[.]22[.]3:31337` | ip:port | Sliver | ThreatFox | 2026-10-16 06:10:35 UTC |
| 63 (media) | critica | `64[.]227[.]97[.]214:31337` | ip:port | Sliver | ThreatFox | 2026-10-16 06:10:33 UTC |
| 62 (media) | media | `104[.]248[.]206[.]134:7061` | ip:port | Drifter | ThreatFox | 2026-10-16 06:48:51 UTC |
| 62 (media) | media | `104[.]248[.]206[.]134:25632` | ip:port | Drifter | ThreatFox | 2026-10-16 06:35:25 UTC |
| 61 (media) | alta | `153[.]218[.]25[.]149:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:10 UTC |
| 61 (media) | media | `46[.]101[.]249[.]247:7061` | ip:port | Drifter | ThreatFox | 2026-10-16 06:48:52 UTC |
| 61 (media) | media | `46[.]101[.]249[.]247:32505` | ip:port | Drifter | ThreatFox | 2026-10-16 06:35:26 UTC |
| 61 (media) | media | `102[.]220[.]161[.]63:10213` | ip:port | CECbot | ThreatFox | 2026-10-15 13:04:58 UTC |
| 60 (media) | media | `b4a2106375c183c4c88d831e5e836096958458c0a2c8831ed5f6d61ffb9b3790` | sha256_hash | Coinminer | ThreatFox | 2026-10-16 10:49:15 UTC |
| 60 (media) | media | `138[.]68[.]134[.]9:7061` | ip:port | Drifter | ThreatFox | 2026-10-16 06:48:52 UTC |
| 60 (media) | media | `138[.]68[.]134[.]9:32505` | ip:port | Drifter | ThreatFox | 2026-10-16 06:35:25 UTC |
| 59 (media) | media | `185[.]165[.]171[.]21:8888` | ip:port | Unknown malware | ThreatFox | 2026-10-16 06:10:46 UTC |
| 59 (media) | media | `185[.]165[.]171[.]21:8898` | ip:port | Unknown malware | ThreatFox | 2026-10-16 06:10:46 UTC |
| 58 (media) | alta | `tribot[.]co[.]uk` | domain | Unknown Stealer | ThreatFox | 2026-10-16 10:49:14 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-21589 | Atlassian Multiple Products | 2026-10-15 | Unknown |
| CVE-2026-105134 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-76519 | Cisco Secure Email Gateway | 2026-10-14 | Unknown |
| CVE-2026-105133 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-0322 | Palo Alto Networks PAN-OS | 2026-10-14 | Unknown |
| CVE-2026-104935 | Ivanti Connect Secure | 2026-10-13 | Unknown |
| CVE-2026-96951 | Microsoft Windows | 2026-10-13 | Unknown |
| CVE-2015-5477 | ISC BIND | 2026-10-08 | Unknown |
| CVE-2016-3081 | Apache Struts | 2026-10-08 | Unknown |
| CVE-2023-22894 | Strapi Strapi | 2026-10-08 | Unknown |
| CVE-2021-3199 | ONLYOFFICE Docs | 2026-10-08 | Unknown |
| CVE-2015-3306 | ProFTPD ProFTPD | 2026-10-08 | Unknown |
| CVE-2026-88779 | Citrix NetScaler | 2026-10-04 | Unknown |
| CVE-2026-102490 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-102489 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
<!-- CTI:END -->
