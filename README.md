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
**Última actualización:** 2026-08-24 01:51 UTC · **IOCs recolectados:** 1110 · **CVEs KEV recientes:** 12

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 66 (media) | media | `092efbe07f739c831b8811c95bd4a506` | md5_hash | Crystal Rans0m | ThreatFox | 2026-08-23 11:19:31 UTC |
| 66 (media) | media | `cec1219e3640202c54a484ed3b88dd56fd26edfdb533c5eba8b2416e17ea6334` | sha256_hash | Crystal Rans0m | ThreatFox | 2026-08-23 11:19:30 UTC |
| 66 (media) | media | `e5a5ba8d8c6b47ad5614d0d879c946ff7b842191` | sha1_hash | Crystal Rans0m | ThreatFox | 2026-08-23 11:19:30 UTC |
| 64 (media) | alta | `c4ed4c72d4e1cdfabeade9a6021d3ac9` | md5_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:26 UTC |
| 64 (media) | alta | `496f3cba557efd0d708b008b906c45b985b996905b2f8eb922a23b892b57cfdf` | sha256_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:25 UTC |
| 64 (media) | alta | `fe8a9be873800aab5c0e4b5999a2104ae92202dd` | sha1_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:25 UTC |
| 64 (media) | media | `cdcd5f2b289d8c9354c05b55e970218bceaf61d1decd05a628fc34799b7df0a1` | sha256_hash | NetWire RC | ThreatFox | 2026-08-23 11:19:21 UTC |
| 64 (media) | alta | `130[.]12[.]182[.]39:2600` | ip:port | AsyncRAT | ThreatFox | 2026-08-23 09:43:34 UTC |
| 63 (media) | alta | `a947f68792122ab241f671e9e7ee20d5a0e7766f` | sha1_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:25 UTC |
| 63 (media) | alta | `905c791b2ed300193fbc4248c5bca33d` | md5_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:25 UTC |
| 63 (media) | alta | `d5729bc0561611794d6d1b49b24c0d9dc3fde404` | sha1_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:24 UTC |
| 63 (media) | alta | `ce4ba16956b7c2802e7dba75244e0352` | md5_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:24 UTC |
| 63 (media) | alta | `b3aa80f62cf946fa6d290d17d895c2885c8c628e698a786549a31f28bfd9aaa1` | sha256_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:24 UTC |
| 63 (media) | alta | `44c79975608861ee3a4bc452a4d643316d1d09641d40d8c9a63ed7536f3821a7` | sha256_hash | ValleyRAT | ThreatFox | 2026-08-23 11:19:23 UTC |
| 63 (media) | media | `ffaf64672a89086ad11d0a290fa2468a2a16d7a0f54e57a1abf52b427f54ba0a` | sha256_hash | NetWire RC | ThreatFox | 2026-08-23 11:19:22 UTC |
| 63 (media) | media | `2b1673d6d6e892f6f8be201e01294ac4b89a845f` | sha1_hash | NetWire RC | ThreatFox | 2026-08-23 11:19:22 UTC |
| 63 (media) | media | `0b55a6f1ae9d946ece71647dd09500b5` | md5_hash | NetWire RC | ThreatFox | 2026-08-23 11:19:22 UTC |
| 60 (media) | alta | `hxxp://192[.]253[.]248[.]181/api/v1/bot/actions/d51c30267c864160a1da8ba3d183cdd3` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:28 UTC |
| 60 (media) | alta | `hxxp://86[.]54[.]25[.]213/d/unix23269396` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:28 UTC |
| 60 (media) | alta | `hxxp://192[.]253[.]248[.]181/api/v1/getscpt/jaicharan` | url | Unknown Stealer | ThreatFox | 2026-08-23 16:11:27 UTC |
| 60 (media) | alta | `192[.]253[.]248[.]181:80` | ip:port | Unknown Stealer | ThreatFox | 2026-08-23 16:11:24 UTC |
| 60 (media) | alta | `hxxps://aprettopizza[.]world/live/` | url | Latrodectus | ThreatFox | 2026-08-23 16:11:12 UTC |
| 59 (media) | alta | `185[.]157[.]163[.]138:50810` | ip:port | Remcos | ThreatFox | 2026-08-24 01:25:03 UTC |
| 59 (media) | alta | `hxxps://peermangoz[.]me/live/` | url | Latrodectus | ThreatFox | 2026-08-23 16:11:13 UTC |
| 59 (media) | alta | `185[.]53[.]179[.]136:443` | ip:port | Nanocore RAT | ThreatFox | 2026-08-23 14:30:05 UTC |

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
