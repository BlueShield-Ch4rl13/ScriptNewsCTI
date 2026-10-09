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
**Última actualización:** 2026-10-09 22:39 UTC · **IOCs recolectados:** 1814 · **CVEs KEV recientes:** 16

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `130[.]12[.]180[.]212:8001` | ip:port | Aisuru | ThreatFox | 2026-10-09 08:53:51 UTC |
| 73 (alta) | alta | `78eda3158bc47d7d0982c476486b12faaf6e46195e0bfc457c8ed43690f0de82` | sha256_hash | SVCStealer | ThreatFox | 2026-10-09 22:12:29 UTC |
| 73 (alta) | alta | `77[.]90[.]57[.]20:8080` | ip:port | Mirai | ThreatFox | 2026-10-09 21:54:35 UTC |
| 69 (media) | alta | `2b263e84b679f604988922f3ad5928c68be97e3ffe305d1fad4e2b7623815b9d` | sha256_hash | SmartLoader | ThreatFox | 2026-10-09 22:12:26 UTC |
| 66 (media) | media | `171785acdb1595e6a4d2fc0a2a153895b1ebfd75b9dcfb30c8ffa43885abbf58` | sha256_hash | XOR DDoS | ThreatFox | 2026-10-09 22:12:27 UTC |
| 66 (media) | alta | `6394596ffddbf240d0ec2584c2d66984f1cb415f7d440d9b29b04d58b8e0fbcc` | sha256_hash | Mirai | ThreatFox | 2026-10-09 21:12:53 UTC |
| 65 (media) | alta | `384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c` | sha256_hash | Mirai | ThreatFox | 2026-10-09 22:12:33 UTC |
| 65 (media) | alta | `a38d9d55a54179e26ec9031764a623b25282f55080329702affacd795621d4df` | sha256_hash | Mirai | ThreatFox | 2026-10-09 22:12:30 UTC |
| 65 (media) | alta | `b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c` | sha256_hash | Mirai | ThreatFox | 2026-10-09 21:12:52 UTC |
| 65 (media) | alta | `75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1` | sha256_hash | Mirai | ThreatFox | 2026-10-09 21:12:50 UTC |
| 64 (media) | alta | `1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b` | sha256_hash | Mirai | ThreatFox | 2026-10-09 21:12:49 UTC |
| 63 (media) | alta | `b926c66f511842d0b2fb8d09d7bba064d5385f28f2a4d71e3bf230eb5a2fcde1` | sha256_hash | Mirai | ThreatFox | 2026-10-09 12:06:15 UTC |
| 62 (media) | alta | `60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e` | sha256_hash | Mirai | ThreatFox | 2026-10-09 22:12:32 UTC |
| 62 (media) | alta | `9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203` | sha256_hash | Mirai | ThreatFox | 2026-10-09 22:12:31 UTC |
| 62 (media) | media | `213[.]232[.]114[.]14:80` | ip:port | Bashlite | ThreatFox | 2026-10-09 21:54:34 UTC |
| 62 (media) | media | `213[.]232[.]114[.]14:21` | ip:port | Bashlite | ThreatFox | 2026-10-09 21:54:08 UTC |
| 62 (media) | alta | `708c3628746961658e1b16c2af396aaa362c868f28681fc7025b69733057b4af` | sha256_hash | Mirai | ThreatFox | 2026-10-09 12:06:13 UTC |
| 62 (media) | media | `4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d` | sha256_hash | xmrig | ThreatFox, OTX | 2026-10-09 10:48:34 UTC |
| 61 (media) | media | `93[.]152[.]221[.]45:37610` | ip:port | Drifter | ThreatFox | 2026-10-08 22:52:20 UTC |
| 60 (media) | alta | `51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224` | sha256_hash | Mirai | ThreatFox | 2026-10-09 22:12:36 UTC |
| 60 (media) | alta | `141[.]98[.]10[.]127:14641` | ip:port | Remcos | ThreatFox | 2026-10-09 06:04:52 UTC |
| 59 (media) | alta | `13[.]140[.]176[.]180:24331` | ip:port | Mirai | ThreatFox | 2026-10-09 21:54:08 UTC |
| 59 (media) | media | `b65d1f2fb47de8bd278b685b7b787fee69b65232b678ac8721ca41896c7bf544` | sha256_hash | AMOS | ThreatFox | 2026-10-09 21:32:29 UTC |
| 59 (media) | alta | `7309360ac07a489a256e64fc4221b4f08aab4263b487bc6831acc11c8e75c012` | sha256_hash | Mirai | ThreatFox | 2026-10-09 21:12:51 UTC |
| 59 (media) | media | `b55e16170cbba64cb8fe432d2004c0b011db6318ed41dd359637a2afe9d6545b` | sha256_hash | AMOS | ThreatFox | 2026-10-09 13:05:06 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2015-5477 | ISC BIND | 2026-10-08 | Unknown |
| CVE-2016-3081 | Apache Struts | 2026-10-08 | Unknown |
| CVE-2023-22894 | Strapi Strapi | 2026-10-08 | Unknown |
| CVE-2021-3199 | ONLYOFFICE Docs | 2026-10-08 | Unknown |
| CVE-2015-3306 | ProFTPD ProFTPD | 2026-10-08 | Unknown |
| CVE-2026-88779 | Citrix NetScaler | 2026-10-04 | Unknown |
| CVE-2026-102490 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-102489 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-104286 | Fortinet FortiMail | 2026-10-01 | Unknown |
| CVE-2026-76504 | Cisco Catalyst SD-WAN Manager | 2026-09-30 | Unknown |
| CVE-2026-86950 | Apple Multiple Products | 2026-09-29 | Unknown |
| CVE-2026-88772 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-88771 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-67279 | MikroTik RouterOS | 2026-09-25 | Unknown |
| CVE-2026-65660 | Microsoft SharePoint | 2026-09-25 | Unknown |
| CVE-2026-87902 | WordPress Core | 2026-09-25 | Unknown |
<!-- CTI:END -->
