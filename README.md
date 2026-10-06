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
**Última actualización:** 2026-10-06 22:43 UTC · **IOCs recolectados:** 2704 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | media | `89[.]32[.]41[.]19:7193` | ip:port | Potassium | ThreatFox | 2026-10-06 21:19:56 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:15987` | ip:port | Potassium | ThreatFox | 2026-10-06 16:57:12 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]49:7193` | ip:port | Potassium | ThreatFox | 2026-10-06 16:03:36 UTC |
| 74 (alta) | alta | `176[.]65[.]134[.]119:4444` | ip:port | Mirai | ThreatFox | 2026-10-06 05:27:48 UTC |
| 72 (alta) | alta | `139[.]162[.]5[.]254:3778` | ip:port | Mirai | ThreatFox | 2026-10-06 14:30:45 UTC |
| 70 (alta) | alta | `700982a7340b326fd1fb402dfab1d7991eb9ff85ba06437457f182ae9f041a88` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:05 UTC |
| 69 (media) | alta | `b3ee99af1e9dc43036a5832b6aa4fbf6ac995bcea2d6fce9e933b2ee74550411` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:02 UTC |
| 69 (media) | alta | `7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:56 UTC |
| 68 (media) | alta | `5130fc199132ce3538b6c50790ddd09683ab986b21841bcfd9d9b32ad7f4d80e` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-06 05:46:53 UTC |
| 68 (media) | media | `176[.]65[.]134[.]119:80` | ip:port | Unknown malware | ThreatFox | 2026-10-06 05:27:51 UTC |
| 68 (media) | alta | `bacd686528120d6216a3354cb4e3aebc16c6eb4e3795bd514d63d748a6098df5` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:04 UTC |
| 68 (media) | alta | `3acb3901111c81c4204026c3fea5dfd7d3e78c019fd35422f98e42db058ba98d` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:01 UTC |
| 67 (media) | alta | `40e18dfbbb8082477c8e5a9a883a0a792c27d858b2918eb2f38df1695070020b` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:06 UTC |
| 67 (media) | alta | `704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:53 UTC |
| 67 (media) | alta | `8996a15739bad7bf32ea6755851c5ab0febe3dbeb4b79ae28cfb9e8e5987ca7d` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:47 UTC |
| 66 (media) | alta | `3d9d34fd1f5ec84f1e98c8613e27d2acf33db7fb623e2796c2489a7ce4fbfb03` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:03 UTC |
| 66 (media) | alta | `95ca6596a568a7d0c8a2fab1768926662ddb33e0bd100e6aa6ef8bee69ec44ec` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:59 UTC |
| 66 (media) | alta | `f3f4cdd0e555489d531a3bc837e0cb26e20db5cdbeabc4e8dcdcfffb32f4fefc` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:57 UTC |
| 66 (media) | alta | `7244d8f48ecb496020d4de0192fc9377bd013572d1eecde227472b27e0629703` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:54 UTC |
| 66 (media) | alta | `28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:49 UTC |
| 66 (media) | alta | `0b98075245e1454db217330e5f8f9eefe8ed995ce3f9009c6687e95596286f81` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:46 UTC |
| 65 (media) | alta | `aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:00 UTC |
| 65 (media) | alta | `0237044d214277a844e26964c532ecf35809c6e915cd8761518112c8f9f889ca` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:52 UTC |
| 65 (media) | alta | `0736007a31e212eddfcdb48b0785c9d241da739fe9df9c68ed2b05255815af6a` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:50 UTC |
| 64 (media) | critica | `45[.]227[.]253[.]132:8080` | ip:port | Cobalt Strike | ThreatFox | 2026-10-06 15:05:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-5430 | WSO2 Multiple Products | 2026-09-24 | Unknown |
| CVE-2026-71362 | Adobe Commerce and Magento  | 2026-09-24 | Unknown |
| CVE-2026-93952 | Arista VeloCloud Orchestrator | 2026-09-22 | Unknown |
| CVE-2026-94127 | F5 BIG-IP APM | 2026-09-22 | Unknown |
| CVE-2026-93616 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-85102 | Check Point Multiple Products | 2026-09-22 | Unknown |
<!-- CTI:END -->
