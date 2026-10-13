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
**Última actualización:** 2026-10-13 00:32 UTC · **IOCs recolectados:** 1451 · **CVEs KEV recientes:** 11

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 78 (alta) | alta | `71[.]15[.]96[.]217:23` | ip:port | Mirai | ThreatFox | 2026-10-12 06:11:07 UTC |
| 77 (alta) | alta | `178[.]16[.]53[.]56:9034` | ip:port | Aisuru | ThreatFox | 2026-10-12 05:02:09 UTC |
| 76 (alta) | alta | `211[.]43[.]97[.]233:23` | ip:port | Mirai | ThreatFox | 2026-10-12 06:11:06 UTC |
| 75 (alta) | alta | `103[.]170[.]217[.]170:3912` | ip:port | Mirai | ThreatFox | 2026-10-12 23:44:42 UTC |
| 75 (alta) | media | `165[.]245[.]160[.]178:5900` | ip:port | DarkVNC | ThreatFox | 2026-10-12 06:11:09 UTC |
| 75 (alta) | media | `165[.]245[.]171[.]220:5900` | ip:port | DarkVNC | ThreatFox | 2026-10-12 06:11:09 UTC |
| 75 (alta) | media | `31[.]59[.]220[.]26:5900` | ip:port | DarkVNC | ThreatFox | 2026-10-12 06:11:09 UTC |
| 75 (alta) | alta | `34[.]22[.]226[.]31:23` | ip:port | Mirai | ThreatFox | 2026-10-12 06:11:06 UTC |
| 72 (alta) | alta | `176[.]65[.]139[.]76:1999` | ip:port | Mirai | ThreatFox | 2026-10-12 18:10:03 UTC |
| 71 (alta) | alta | `45[.]198[.]224[.]34:80` | ip:port | Mirai | ThreatFox | 2026-10-12 10:46:34 UTC |
| 69 (media) | alta | `113[.]254[.]122[.]139:23` | ip:port | Mirai | ThreatFox | 2026-10-12 06:11:07 UTC |
| 63 (media) | media | `45[.]207[.]157[.]28:9999` | ip:port | Unknown malware | ThreatFox | 2026-10-12 06:11:20 UTC |
| 62 (media) | media | `176[.]65[.]139[.]166:54321` | ip:port | Unknown malware | ThreatFox | 2026-10-12 18:29:40 UTC |
| 62 (media) | alta | `176[.]65[.]139[.]40:80` | ip:port | Mirai | ThreatFox | 2026-10-12 18:10:00 UTC |
| 61 (media) | alta | `6507fe13084e475016874e40bb8a5b404ee9d5aaab5a99bd9d369e411be6e212` | sha256_hash | Mirai | ThreatFox | 2026-10-12 14:53:05 UTC |
| 61 (media) | alta | `eae1f8de417d97e96c8bdf8c171b4275e042e7e0482b38619516e93e2f3f201d` | sha256_hash | Mirai | ThreatFox | 2026-10-12 04:53:04 UTC |
| 61 (media) | alta | `b930b4978b1a7408240781988f7c634f8c36d9e5dfb4f58967abe065d6553c55` | sha256_hash | Mirai | ThreatFox | 2026-10-12 04:53:00 UTC |
| 60 (media) | alta | `e7ae78e8f568c7af08a5fa663ed3063ad09918bbdc9fe033324cfa80363290e3` | sha256_hash | Mirai | ThreatFox | 2026-10-12 14:53:08 UTC |
| 60 (media) | alta | `1ad0d5bb014ddffbd73e450ba2a63285598aad9865c216e2eff6660b3e53056d` | sha256_hash | Mirai | ThreatFox | 2026-10-12 14:53:02 UTC |
| 60 (media) | alta | `182[.]190[.]217[.]14:23` | ip:port | Mirai | ThreatFox | 2026-10-12 06:11:10 UTC |
| 60 (media) | alta | `217[.]60[.]195[.]219:2404` | ip:port | Remcos | ThreatFox | 2026-10-12 05:10:03 UTC |
| 60 (media) | alta | `281cdbb7d1f655808e2748311bc002ec86238d91013a7c2dd088faea6e6fd548` | sha256_hash | Mirai | ThreatFox | 2026-10-12 04:53:12 UTC |
| 60 (media) | alta | `e88f382fa651eb327f2c541c87ae555683b5aa9a037645259eab2a68162ea894` | sha256_hash | Mirai | ThreatFox | 2026-10-12 04:53:11 UTC |
| 60 (media) | alta | `565422e182c8dd4d799257eb053248b8ff9ed052a7729b56ec04722f95057328` | sha256_hash | Mirai | ThreatFox | 2026-10-12 04:53:10 UTC |
| 60 (media) | alta | `edb22b57fddffcbae1d8a6348efe724e3361bc97575f7231599bd51ad3430807` | sha256_hash | Mirai | ThreatFox | 2026-10-12 04:53:09 UTC |

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
<!-- CTI:END -->
