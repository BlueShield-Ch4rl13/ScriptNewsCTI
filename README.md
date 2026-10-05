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
**Última actualización:** 2026-10-05 05:12 UTC · **IOCs recolectados:** 2993 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | alta | `178[.]132[.]198[.]200:443` | ip:port | Mirai | ThreatFox | 2026-10-04 06:54:53 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]30:695` | ip:port | Mirai | ThreatFox | 2026-10-05 03:20:28 UTC |
| 69 (media) | alta | `5aefe115dc06827f878068f6f30470ddcc2aa53b5ad441224ba00b75169a9892` | sha256_hash | Mirai | ThreatFox | 2026-10-04 20:58:21 UTC |
| 68 (media) | alta | `932b07f7f22083aee44fa5160a272af1fe4a6e35629326c58d4d0816c74a6bea` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:53 UTC |
| 68 (media) | alta | `5d161c376217f39228581ba6aa070131ed29b15440d2a3cfb08f62a73dd22f07` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:51 UTC |
| 68 (media) | alta | `aa1d28fa405d3e156ae2d26c531a7674f6697f80a905d0f40eb5f9a587c52fee` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:50 UTC |
| 68 (media) | alta | `b78c607e100e2851675e0b6b130d97109b2dfe7c0bf7c7bba861dd39ebb59040` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:42 UTC |
| 68 (media) | alta | `b41d7edd26b0da6c49a42cdb903ff0a37402bd9927c8754a213dde55e3c847dc` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:40 UTC |
| 68 (media) | alta | `d2daf8a90587a500006b912584feb398977e0087cd8ada2a31a0ab2c5e52114c` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:39 UTC |
| 68 (media) | alta | `84d5b689b4e9ca6ca4c5f78444a67b9048e1ff055dcc860fb5ef916602658015` | sha256_hash | Mirai | ThreatFox | 2026-10-04 20:58:21 UTC |
| 68 (media) | alta | `fe0c0bf5ed8f6036eb1138b499073807fea4d5b98525af72c2d1d24285d9076e` | sha256_hash | Mirai | ThreatFox | 2026-10-04 20:58:20 UTC |
| 68 (media) | alta | `dc22c37cc0ae4a88717cdcd54df18a42e09f85c682189f58e77ddd722b5ee3ee` | sha256_hash | Mirai | ThreatFox | 2026-10-04 20:58:20 UTC |
| 68 (media) | alta | `f96215c68cbb8bad180587fb89c2d9bccff554694a5ce2a2209ff8c19f16b8e1` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:46 UTC |
| 68 (media) | alta | `d6dbc73627d0b1a9beec2e114c85ef4fd2788262dbe6796f4b803b6daccd3231` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:45 UTC |
| 68 (media) | alta | `34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:42 UTC |
| 68 (media) | alta | `e56b32c7b18f0a5e8a0308e45a1e11eb642d928f5efd554280b7cdf03babdb13` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:35 UTC |
| 68 (media) | alta | `9ccc4db28c8da295f73b0180fe7812f2668910726cf8e7d410b27e2d059369ae` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:34 UTC |
| 68 (media) | alta | `801e4978b04e7c8377625359eaf0121fa71062ed2cb08105fdfa536fb93c1130` | sha256_hash | Mirai | ThreatFox | 2026-10-04 11:46:31 UTC |
| 68 (media) | media | `34b164db13fc9ec00a1fcf9a142bec0346009041a939f75da21f7239ea49e76e` | sha256_hash | SNOWLIGHT | ThreatFox | 2026-10-04 11:46:22 UTC |
| 68 (media) | media | `e9f587728e7cd8fc8eaafb87e5da4d2ebf1df16bc3cbdc9c35c76fa0b204776e` | sha256_hash | SNOWLIGHT | ThreatFox | 2026-10-04 11:46:19 UTC |
| 67 (media) | alta | `70d911746eed11854ee20db2103a7fd453a7ec5e3124163b2e32eb03d3165b76` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:47:09 UTC |
| 67 (media) | alta | `9c37802dffcb07416e5a206f28dc51fd5fe58c32602f1c840f8a969b3d37e4b5` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:45 UTC |
| 67 (media) | alta | `0577e2fd8f5da73991195505977723893ae8178d436ca747440eeb1ff9738bf9` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:44 UTC |
| 67 (media) | alta | `489cbebb3535f702f95549ea2ec70dea622944fbf188a951cd89ad80e5bb3fc0` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:43 UTC |
| 67 (media) | alta | `3c579af3ac3f294aebdcbb98d326c5046a135bd1a159ba6c1a2ad6b2fbfe1dd5` | sha256_hash | Mirai | ThreatFox | 2026-10-05 04:46:41 UTC |

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
| CVE-2026-7273 | Zyxel GS1900 Series Switches | 2026-09-21 | Unknown |
<!-- CTI:END -->
