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
**Última actualización:** 2026-08-26 13:14 UTC · **IOCs recolectados:** 1327 · **CVEs KEV recientes:** 11

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 71 (alta) | media | `213[.]152[.]162[.]110:43148` | ip:port | Unknown malware | ThreatFox | 2026-08-26 07:20:19 UTC |
| 71 (alta) | alta | `64[.]89[.]160[.]253:49158` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:09:17 UTC |
| 71 (alta) | alta | `77[.]239[.]124[.]108:5173` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:09:17 UTC |
| 71 (alta) | alta | `178[.]16[.]54[.]149:5050` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:09:16 UTC |
| 70 (alta) | alta | `179[.]43[.]175[.]47:443` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:16:38 UTC |
| 70 (alta) | alta | `179[.]43[.]175[.]47:80` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:16:38 UTC |
| 67 (media) | media | `hxxp://cta[.]edu[.]pe/wp-content/plugins/linux[.]bin` | url | XMRIG | ThreatFox, URLhaus | 2026-08-26 12:52:31 UTC |
| 67 (media) | alta | `91[.]92[.]42[.]99:8080` | ip:port | RatonRAT | ThreatFox | 2026-08-26 12:06:54 UTC |
| 66 (media) | media | `hxxps://paste[.]mangsud[.]org/raw/ea2e61cc` | url | XMRIG | ThreatFox, URLhaus | 2026-08-26 12:52:04 UTC |
| 65 (media) | media | `hxxps://repositoryserver[.]dpdns[.]org/linuxsh` | url | XMRIG | ThreatFox, URLhaus | 2026-08-26 12:52:05 UTC |
| 65 (media) | media | `hxxps://repositoryserver[.]dpdns[.]org/cronsys` | url | XMRIG | ThreatFox, URLhaus | 2026-08-26 12:52:05 UTC |
| 65 (media) | media | `hxxps://repositoryserver[.]dpdns[.]org/killersys` | url | XMRIG | ThreatFox, URLhaus | 2026-08-26 12:52:04 UTC |
| 61 (media) | alta | `88[.]87[.]85[.]199:443` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:16:44 UTC |
| 61 (media) | alta | `31[.]7[.]63[.]12:443` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:16:41 UTC |
| 61 (media) | alta | `31[.]7[.]63[.]12:80` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:16:41 UTC |
| 60 (media) | critica | `204[.]44[.]122[.]232:24444` | ip:port | Sliver | ThreatFox | 2026-08-26 12:09:25 UTC |
| 60 (media) | alta | `167[.]99[.]194[.]254:8443` | ip:port | Aisuru | ThreatFox | 2026-08-26 05:46:17 UTC |
| 60 (media) | alta | `94[.]26[.]83[.]25:80` | ip:port | Overlord RAT | ThreatFox | 2026-08-25 14:16:44 UTC |
| 59 (media) | media | `remus[.]su` | domain | Remus | ThreatFox | 2026-08-26 12:43:52 UTC |
| 59 (media) | media | `158[.]94[.]210[.]86:443` | ip:port | Unknown malware | ThreatFox | 2026-08-26 07:28:58 UTC |
| 59 (media) | alta | `165[.]22[.]122[.]89:8443` | ip:port | Aisuru | ThreatFox | 2026-08-26 05:46:18 UTC |
| 59 (media) | media | `185[.]242[.]3[.]178:8080` | ip:port | VShell | ThreatFox | 2026-08-26 01:05:05 UTC |
| 59 (media) | alta | `hxxp://cloudscrsolutions[.]com/v8sjh3hs8/index[.]php` | url | Amadey | ThreatFox | 2026-08-25 18:15:34 UTC |
| 59 (media) | alta | `hxxp://atraflaxtt[.]com/g9sjh3djv/index[.]php` | url | Amadey | ThreatFox | 2026-08-25 18:15:33 UTC |
| 59 (media) | alta | `hxxp://jazoopsloo[.]info/k92lsA3dpb/index[.]php` | url | Amadey | ThreatFox | 2026-08-25 18:15:30 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-60004 | Gitea Gitea | 2026-08-25 | Unknown |
| CVE-2026-21962 | Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in | 2026-08-24 | Unknown |
| CVE-2026-73570 | Synacor Zimbra Collaboration Suite (ZCS) | 2026-08-21 | Unknown |
| CVE-2026-72530 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-72529 | TrueConf Server | 2026-08-20 | Unknown |
| CVE-2026-64849 | MLflow MLflow | 2026-08-19 | Unknown |
| CVE-2026-33824 | Microsoft Internet Key Exchange (IKE) Service Extensions | 2026-08-18 | Unknown |
| CVE-2026-59310 | Broadcom VMware vCenter | 2026-08-18 | Unknown |
| CVE-2026-55040 | Microsoft SharePoint | 2026-08-18 | Unknown |
| CVE-2026-65400 | Apple macOS | 2026-08-18 | Unknown |
| CVE-2025-62593 | Ray-Project Ray | 2026-08-17 | Unknown |
<!-- CTI:END -->
