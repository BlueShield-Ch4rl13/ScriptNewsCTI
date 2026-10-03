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
**Última actualización:** 2026-10-03 04:56 UTC · **IOCs recolectados:** 2710 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `94[.]26[.]68[.]68:2404` | ip:port | Remcos | ThreatFox | 2026-10-03 01:11:37 UTC |
| 72 (alta) | media | `088f624bf51e8c9db46a345c3a85df89f5729a226da1846f70aae91b9b44ffe7` | sha256_hash | Bashlite | ThreatFox | 2026-10-02 21:46:54 UTC |
| 70 (alta) | alta | `77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:43 UTC |
| 70 (alta) | alta | `dc17c133c5d7087e6fa11a41cbaabf7cd870b2cf982f02b2df398eb78e408229` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:57 UTC |
| 69 (media) | alta | `fad87a2968c7eb2470e1587d11a16d260fac7f381e131c1d53e39def1be20845` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:55 UTC |
| 69 (media) | media | `61958a485732d3fb76ef286246047687239f374e873281dfdeddb1538a889958` | sha256_hash | Bashlite | ThreatFox | 2026-10-02 21:46:50 UTC |
| 69 (media) | alta | `15612d87e4b1d45699cdfdba08d1ce405e87c95757c6bdac4d819f9d5d99c777` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:47 UTC |
| 69 (media) | alta | `baf99548f2c0e47d6234bcc964d387184a59e5d4acdbf8af79a736d817730a2e` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:36 UTC |
| 69 (media) | alta | `3ee840bc79a034e38e1f4d42a19fbdc7cf50bea0581bbcdbd92149b6009fbf90` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:27 UTC |
| 69 (media) | alta | `64ecb45d56f1126d982609f4c9679e3a7db4fea47b90726e28aed6c1555e9331` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:55 UTC |
| 69 (media) | alta | `14adbc5ababc074a0a890804138c8ac4c9be11a70a38456bc11ab625c2194622` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:53 UTC |
| 68 (media) | alta | `5edf7cb9422a1b24892a23b207c9d5c18040963c5577b80ecef7e84c46abac63` | sha256_hash | AsyncRAT | ThreatFox | 2026-10-03 04:01:00 UTC |
| 68 (media) | alta | `5ee56307c6fc01f08cf1c73c8770f137d9e91d993e8fab9a66463c411d1b3523` | sha256_hash | AsyncRAT | ThreatFox | 2026-10-03 04:01:00 UTC |
| 68 (media) | alta | `5ef95b38828c6d99c6cc41f377373c7b1c6d5b48c6f63ceeb2b103daec226716` | sha256_hash | AsyncRAT | ThreatFox | 2026-10-03 04:01:00 UTC |
| 68 (media) | alta | `661d546af82629fe989abcf66a570e568e69b91feee7509f8aede9f6362b3173` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:56 UTC |
| 68 (media) | alta | `e759653346bfd8e7f818b5ea8e30e372bf2143f475af9ed50950c97c87392f37` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:52 UTC |
| 68 (media) | media | `68feece51b734c46cd81c082c80515282a66da2872d3fe9c83c62199d9aba7a9` | sha256_hash | Bashlite | ThreatFox | 2026-10-02 21:46:51 UTC |
| 68 (media) | alta | `85a00051bd64a07945c16f0147aee1db76afd198febeebfbc5689409d5c0836c` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:46 UTC |
| 68 (media) | alta | `32bd603ba84e760872a70162ce899c250826c450a878760dfe22fa11ee61ef92` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:45 UTC |
| 68 (media) | alta | `2d1ec8a263610b7a565b961364a62b85526958c25ff23f7f3aacbd8be78bbc01` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:44 UTC |
| 68 (media) | alta | `38534279305c05fc31115da438390708295fc646f41926c3f3a5fab428757551` | sha256_hash | Mirai | ThreatFox | 2026-10-02 21:46:33 UTC |
| 68 (media) | alta | `dc45540bdad7a5ffc99dbe071dd8803aebb8b85c59b14871e33e58f9096d235d` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:58 UTC |
| 68 (media) | alta | `448bb7bd702777e61ee298cc5b366813dccb872748afdf7f8d462ccd80030f85` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:56 UTC |
| 67 (media) | alta | `5effc80d5f389747bd27654eba317d8287f5f35ee6aaffc434ae24fdca702cee` | sha256_hash | AsyncRAT | ThreatFox | 2026-10-03 04:01:00 UTC |
| 67 (media) | alta | `5e9e17de1d5865d1811704f0b6de7ac45fcb3b3070fdc186536e347f99a6ced8` | sha256_hash | AsyncRAT | ThreatFox | 2026-10-03 04:00:59 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-5430 | WSO2 Multiple Products | 2026-09-24 | Unknown |
| CVE-2026-71362 | Adobe Commerce and Magento  | 2026-09-24 | Unknown |
| CVE-2026-93952 | Arista VeloCloud Orchestrator | 2026-09-22 | Unknown |
| CVE-2026-94127 | F5 BIG-IP APM | 2026-09-22 | Unknown |
| CVE-2026-93616 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-85102 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-7273 | Zyxel GS1900 Series Switches | 2026-09-21 | Unknown |
<!-- CTI:END -->
