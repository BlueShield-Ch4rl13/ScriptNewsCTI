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
**Última actualización:** 2026-08-22 01:46 UTC · **IOCs recolectados:** 668 · **CVEs KEV recientes:** 12

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 68 (media) | alta | `dc7fcc0d7d189555827260b3e4acc96a` | md5_hash | Vidar | ThreatFox | 2026-08-21 11:10:46 UTC |
| 68 (media) | alta | `acce16056f1fe8efd131034d6d27814ba5fb3e0878cf8147d1983bd73f59eec2` | sha256_hash | Vidar | ThreatFox | 2026-08-21 11:10:45 UTC |
| 68 (media) | alta | `78059e3070682f0ed14015624d8323d4a42fe908` | sha1_hash | Vidar | ThreatFox | 2026-08-21 11:10:45 UTC |
| 65 (media) | alta | `346cf14b787747160f789525e9843663b05a7e588f8fa92b8a2b858a8d54272b` | sha256_hash | Vidar | ThreatFox | 2026-08-21 11:10:51 UTC |
| 65 (media) | alta | `647653bcb618be9cf1883c969cfa3b4b3e3cea13` | sha1_hash | Vidar | ThreatFox | 2026-08-21 11:10:51 UTC |
| 65 (media) | alta | `edc8338feddcdc93e69c966d26a8e94e` | md5_hash | Vidar | ThreatFox | 2026-08-21 11:10:51 UTC |
| 64 (media) | critica | `36[.]140[.]162[.]173:8082` | ip:port | Cobalt Strike | ThreatFox | 2026-08-21 12:05:07 UTC |
| 63 (media) | media | `hxxp://113[.]228[.]208[.]46:56903/Mozi[.]a` | url | Mozi | ThreatFox, URLhaus | 2026-08-21 12:33:02 UTC |
| 63 (media) | alta | `729f56d9643c97fa9d9fb4a7696df881cbe0321b` | sha1_hash | Formbook | ThreatFox | 2026-08-21 11:10:50 UTC |
| 63 (media) | alta | `88602976f7c64499ef40e4972ac17db6` | md5_hash | Formbook | ThreatFox | 2026-08-21 11:10:50 UTC |
| 63 (media) | media | `219d35e9f33b48b3fc1ee51cb4fed27616c09d5f` | sha1_hash | Coinminer | ThreatFox | 2026-08-21 11:10:47 UTC |
| 63 (media) | media | `9853d168bdc4e85fb0c9d2446b5d13ff` | md5_hash | Coinminer | ThreatFox | 2026-08-21 11:10:47 UTC |
| 63 (media) | alta | `e89e2ea4c743c87ef7faff9303b9133c54737dd683536cf5e6518374fb130a4a` | sha256_hash | Formbook | ThreatFox | 2026-08-21 11:10:47 UTC |
| 63 (media) | media | `02522eaec42abfb57e780e43fda7ef0cc4f0e6d061c2e35aaa3575d5b62f7c13` | sha256_hash | Coinminer | ThreatFox | 2026-08-21 11:10:46 UTC |
| 60 (media) | alta | `60786e24a45df08c6b53a35b485d6243371d43e6749390e7304e7c7a0d97d521` | sha256_hash | Mirai | ThreatFox | 2026-08-22 00:18:41 UTC |
| 60 (media) | media | `103[.]242[.]12[.]143:1234` | ip:port | VShell | ThreatFox | 2026-08-21 06:05:07 UTC |
| 59 (media) | media | `178[.]16[.]52[.]120:8787` | ip:port | VShell | ThreatFox | 2026-08-21 23:41:44 UTC |
| 59 (media) | alta | `8abd6a3d21097d75fc4970cb1c202c7b30bc709cf2446a94a298e3020578942a` | sha256_hash | Venus Stealer | ThreatFox | 2026-08-21 11:10:44 UTC |
| 59 (media) | alta | `31c21965b3661caf899480e5a6bc1e5e411e4518` | sha1_hash | Venus Stealer | ThreatFox | 2026-08-21 11:10:44 UTC |
| 59 (media) | alta | `cb470ad87c2982fd1d60b2fa6cbe637d` | md5_hash | Venus Stealer | ThreatFox | 2026-08-21 11:10:44 UTC |
| 59 (media) | media | `113[.]44[.]89[.]87:3306` | ip:port | Unknown malware | ThreatFox | 2026-08-21 06:05:05 UTC |
| 59 (media) | media | `113[.]44[.]89[.]87:8080` | ip:port | Unknown malware | ThreatFox | 2026-08-21 05:05:10 UTC |
| 59 (media) | media | `113[.]44[.]89[.]87:80` | ip:port | Unknown malware | ThreatFox | 2026-08-21 05:05:09 UTC |
| 59 (media) | media | `113[.]44[.]89[.]87:443` | ip:port | Unknown malware | ThreatFox | 2026-08-21 05:05:09 UTC |
| 58 (media) | alta | `checkout[.]lat` | domain | ClearFake | ThreatFox | 2026-08-21 11:43:30 UTC |

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
