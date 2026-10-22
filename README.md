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
**Última actualización:** 2026-10-22 04:20 UTC · **IOCs recolectados:** 2737 · **CVEs KEV recientes:** 20

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `5[.]175[.]222[.]236:777` | ip:port | Mirai | ThreatFox | 2026-10-21 16:15:17 UTC |
| 75 (alta) | alta | `178[.]16[.]53[.]56:9035` | ip:port | Aisuru | ThreatFox | 2026-10-21 10:19:44 UTC |
| 75 (alta) | media | `77[.]239[.]124[.]135:9111` | ip:port | Unknown malware | ThreatFox | 2026-10-21 05:31:44 UTC |
| 73 (alta) | alta | `164[.]152[.]105[.]37:443` | ip:port | Mirai | ThreatFox | 2026-10-21 18:10:30 UTC |
| 73 (alta) | alta | `163[.]192[.]114[.]50:443` | ip:port | Mirai | ThreatFox | 2026-10-21 18:10:30 UTC |
| 72 (alta) | alta | `3d22f41bee487415272e17f7b9d029500b076e75ae5aaea80c0799e0190e5529` | sha256_hash | Vidar | ThreatFox | 2026-10-21 11:07:33 UTC |
| 71 (alta) | alta | `85[.]215[.]73[.]250:80` | ip:port | Mirai | ThreatFox | 2026-10-22 01:18:15 UTC |
| 70 (alta) | alta | `159[.]203[.]28[.]151:8080` | ip:port | Aisuru | ThreatFox | 2026-10-21 21:07:33 UTC |
| 68 (media) | alta | `176[.]65[.]139[.]232:1995` | ip:port | Mirai | ThreatFox | 2026-10-21 15:20:06 UTC |
| 68 (media) | alta | `14[.]242[.]243[.]212:1995` | ip:port | Mirai | ThreatFox | 2026-10-21 15:19:30 UTC |
| 65 (media) | media | `hxxps://forge-copper[.]com/f/9bpeg1jkca3l-cqrd7zulg/6br4vm6w` | url | AMOS | ThreatFox, URLhaus | 2026-10-22 02:58:49 UTC |
| 65 (media) | media | `hxxps://forge-copper[.]com/curl/erevrlcfb/bootstrap[.]sh` | url | AMOS | ThreatFox, URLhaus | 2026-10-22 02:56:37 UTC |
| 65 (media) | alta | `213[.]152[.]176[.]152:35339` | ip:port | Remcos | ThreatFox | 2026-10-21 16:02:44 UTC |
| 64 (media) | alta | `400d22f6ea66e0f002936ce5cfaaf46e9d279d7b3bf04e37810ef34a18a8b298` | sha256_hash | Mirai | ThreatFox | 2026-10-22 03:54:45 UTC |
| 64 (media) | alta | `4537002cbc3e7711a5878d880ffa6ac5cf0a2cfd8735d6be41da38d1a623ab78` | sha256_hash | Mirai | ThreatFox | 2026-10-22 03:54:44 UTC |
| 61 (media) | media | `7311a535954158323045282fef16e143a4f323a8b2916518854874957eba1d45` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:27:01 UTC |
| 60 (media) | alta | `67ad72d026647fe417abb534b1cd6dadf618968e30d53c59dbf0b76464e68723` | sha256_hash | Mirai | ThreatFox | 2026-10-22 03:54:46 UTC |
| 60 (media) | media | `46[.]101[.]249[.]247:23004` | ip:port | Drifter | ThreatFox | 2026-10-21 08:30:26 UTC |
| 59 (media) | alta | `5f35f015791950b625f9727f8e8a39e699c695477c35dc80095d405035584d0c` | sha256_hash | Mirai | ThreatFox | 2026-10-21 16:54:33 UTC |
| 58 (media) | media | `28b961f955fe52c16a240e8526bb29f00f46c75931518fd3116883755897da41` | sha256_hash | AMOS | ThreatFox | 2026-10-22 03:43:23 UTC |
| 58 (media) | media | `81cebf383b544f9b5a968b16a091a049f4862d6b4e9a20840b3a87356594dc21` | sha256_hash | AMOS | ThreatFox | 2026-10-22 03:30:17 UTC |
| 58 (media) | alta | `cc42f35f4a207c377f7775dd91dbe71b25b4e536071e6201a7c0144ce3287ae7` | sha256_hash | Mirai | ThreatFox | 2026-10-21 16:54:39 UTC |
| 58 (media) | media | `3445ce80c99c9d2af195376a3ea61d369dcfbbc7045c8f945dbf6553927f3598` | sha256_hash | AMOS | ThreatFox | 2026-10-21 16:46:39 UTC |
| 58 (media) | media | `fd3988f2fc8bd69ebe48397fdfb082344eceab69f2801c23880865e7fea8ebb1` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:21:53 UTC |
| 58 (media) | media | `157[.]230[.]122[.]72:23004` | ip:port | Drifter | ThreatFox | 2026-10-21 09:29:38 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | 2026-10-20 | Unknown |
| CVE-2026-96656 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96655 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96654 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96652 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-110936 | Siemens Software Center | 2026-10-20 | Unknown |
| CVE-2026-102764 | BeyondTrust Remote Support | 2026-10-16 | Unknown |
| CVE-2025-61624 | Fortinet Multiple Products | 2026-10-16 | Unknown |
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
<!-- CTI:END -->
