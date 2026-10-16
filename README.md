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
**Última actualización:** 2026-10-16 16:35 UTC · **IOCs recolectados:** 2599 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `72[.]167[.]43[.]61:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:11 UTC |
| 77 (alta) | alta | `103[.]18[.]14[.]157:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:09 UTC |
| 76 (alta) | alta | `220[.]74[.]36[.]3:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:12 UTC |
| 76 (alta) | alta | `142[.]93[.]140[.]36:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:11 UTC |
| 76 (alta) | alta | `143[.]110[.]153[.]215:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:09 UTC |
| 75 (alta) | media | `54[.]215[.]31[.]113:7713` | ip:port | Remus | ThreatFox | 2026-10-16 15:15:02 UTC |
| 75 (alta) | alta | `92[.]232[.]113[.]29:23` | ip:port | Mirai | ThreatFox | 2026-10-16 10:49:11 UTC |
| 71 (alta) | alta | `45[.]153[.]34[.]235:8765` | ip:port | Mirai | ThreatFox | 2026-10-16 09:45:09 UTC |
| 71 (alta) | alta | `91[.]92[.]43[.]221:80` | ip:port | Mirai | ThreatFox | 2026-10-16 06:10:48 UTC |
| 71 (alta) | media | `216[.]9[.]225[.]228:8765` | ip:port | Unknown malware | ThreatFox | 2026-10-16 06:10:41 UTC |
| 69 (media) | media | `cd1dcfe992c4a4df8e5cb406d298c118e1f81ed9d3eebdc116e4bce9dc544367` | sha256_hash | Bobik | ThreatFox | 2026-10-16 15:54:08 UTC |
| 69 (media) | alta | `fe7cb6fa9d73b474e2256659d70a3bc71d20b9f38f2160bf0956166bb4131606` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:53:55 UTC |
| 68 (media) | alta | `b2070ddbecc03dbb26cdc2a72df88e9fc5f6bb7215ea3e12d0d1035704553bde` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:07 UTC |
| 68 (media) | alta | `d1d78a81d451f8ae2ac73fcf26696f8c364e3521106e56bbf41020f51fb54e70` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:04 UTC |
| 68 (media) | alta | `60ec6d3aaa6f36ddfcec5c33f0d6c9d22cef9b15765868f5913ef6cfeeac29cd` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:53:57 UTC |
| 68 (media) | alta | `62550c7ec27b049999506513f37f06eb5e2e1bf3c8fd1d2487e15ef70cdb2949` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:53:56 UTC |
| 67 (media) | alta | `d2ae3982f07f89253b21d45321e97f57b4b81c78164c2504b2578958ca186362` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:20 UTC |
| 67 (media) | alta | `3d11f1b4703e85910c6f8e0087d97c106eb4e2db7496056125cbf675838180e7` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:19 UTC |
| 67 (media) | alta | `4bec4b7cf78bfca1cfb3857492e944640e8aba60e593dfc7725eb936618f5c72` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:18 UTC |
| 67 (media) | alta | `785f500873a225e6c460e57521106c5cc2596839596354c7e3dda9aa3b24b791` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:12 UTC |
| 67 (media) | alta | `09768b33697871b52d87d6422395568155e6bd39950785adf4d7dcd603c88470` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:05 UTC |
| 67 (media) | alta | `336656fc6a31de7dda597b739354db26beea2315edc0628232d3972a8d65f98e` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:03 UTC |
| 67 (media) | alta | `60d59f27b6a1498829fe232f5c484d0317b300ab5c0d8bd0c530e3614c8b0f5e` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:01 UTC |
| 67 (media) | alta | `82b95344d95da717c3e487f7fe0d68e8308ba94439a0ef6bb1e0191367351991` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:54:00 UTC |
| 67 (media) | alta | `5fa395bbe688fbbd6364f3d58fb14a8c1dca63933491e475b8740f77e1401b3d` | sha256_hash | Mirai | ThreatFox | 2026-10-16 15:53:59 UTC |

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
