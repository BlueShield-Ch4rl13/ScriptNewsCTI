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
**Última actualización:** 2026-08-23 07:00 UTC · **IOCs recolectados:** 1420 · **CVEs KEV recientes:** 12

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `77[.]239[.]124[.]108:1995` | ip:port | Mirai | ThreatFox | 2026-08-22 09:03:32 UTC |
| 74 (alta) | alta | `dc954b97b95d03465f0f981c3bfdb3bc26a3a9812ce74dbae7fdea6368cd8125` | sha256_hash | 404 Keylogger | ThreatFox | 2026-08-22 06:59:54 UTC |
| 65 (media) | media | `b9826e3da49b12448a57cd37175e01fc776fc38e` | sha1_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:35 UTC |
| 65 (media) | media | `9f6cf57a2791b8c53733f410804dcd1a` | md5_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:35 UTC |
| 65 (media) | media | `c2e63d8266f7c297f0303eecb4cb18dd9151ada99c13ca1683794eb8d6db8217` | sha256_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:34 UTC |
| 65 (media) | alta | `4fef263fa94dc0c45d65a24739d906d2144bb9b8022b5a93713a7fed4f715fba` | sha256_hash | 404 Keylogger | ThreatFox | 2026-08-22 06:59:54 UTC |
| 64 (media) | media | `6c255ef0b62a23e7828f04054e8f3896` | md5_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:42 UTC |
| 64 (media) | media | `df94520df3d218bd7982a7fc40e92530` | md5_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:41 UTC |
| 64 (media) | media | `edc73cf039196893ce93018f5fef4057f90a80447c9b7bf55b91a91b423abde1` | sha256_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:41 UTC |
| 64 (media) | media | `22c9f62d38f274eddf7b38a7f63d9d6c926f8c35` | sha1_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:41 UTC |
| 64 (media) | media | `d684d14082b121f32ce1f6b9df8d173d4daee35c` | sha1_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:40 UTC |
| 64 (media) | media | `c6bfb0d885265012930ecd07a5bc2eb2e1c2db218ced4416839af5761f24f927` | sha256_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:38 UTC |
| 64 (media) | media | `99d5dbbcec96cc84ac22c077680420e70315e19703667e5c8d9f2ec76af1acad` | sha256_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:37 UTC |
| 64 (media) | media | `1fba1be772a9cc5ec1359949e28fb1a97fad53de` | sha1_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:37 UTC |
| 64 (media) | media | `a67819c12c69894357adbec5d970085d` | md5_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:37 UTC |
| 64 (media) | alta | `3faadf0db8cb12791efc12956752a57d69e0ee52eecbe66cbbc70f2008e37626` | sha256_hash | 404 Keylogger | ThreatFox | 2026-08-22 06:59:59 UTC |
| 63 (media) | media | `0f9aeb923449eec7d1f5f1382c69bebf68cbb908` | sha1_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:36 UTC |
| 63 (media) | media | `ee1ed321e64aee5b57ad715a43c23835` | md5_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:36 UTC |
| 63 (media) | media | `355c5ee15bdc6e13d52a6c2551ebffd4932bcb7b93b3f3c7584e6e3a2c420830` | sha256_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:35 UTC |
| 63 (media) | alta | `f067ff68e80f3f037c43069655689d284b587d52368e4f3b20a2d9466fec9f40` | sha256_hash | 404 Keylogger | ThreatFox | 2026-08-22 06:59:55 UTC |
| 62 (media) | media | `e2a6345a9ab066c8d230f10505e564914ed5fab8` | sha1_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:34 UTC |
| 62 (media) | media | `bce4944eabdb55b2b42df2c5a7bd7683` | md5_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:34 UTC |
| 62 (media) | media | `137d06e4b5009f494fd546fc87eb9fa1dcadf35664cecaeb36416c359f803a86` | sha256_hash | NetWire RC | ThreatFox | 2026-08-22 11:19:32 UTC |
| 62 (media) | media | `94d65bfd648a8c6ba9d05f48d89f11b0614128def305d881766397eed481a8cf` | sha256_hash | Unknown malware | ThreatFox | 2026-08-22 09:03:47 UTC |
| 62 (media) | media | `a73195599731fc4d61697c6866dc934df5d7e227810bd9246de9775ad027d494` | sha256_hash | Unknown malware | ThreatFox | 2026-08-22 09:03:46 UTC |

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
