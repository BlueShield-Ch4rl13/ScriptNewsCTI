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
**Última actualización:** 2026-09-11 11:09 UTC · **IOCs recolectados:** 5432 · **CVEs KEV recientes:** 20

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `c56c57e77a34895e23a4074201021f516694eef5b917035c375e05390a5a4976` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 74 (alta) | media | `63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5` | sha256_hash | VShell | ThreatFox | 2026-09-11 05:26:04 UTC |
| 74 (alta) | alta | `c59eb755bf1ae526a437b9be70026c8ba11fa71464ca58ad9c7a940ddb8a061c` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:49 UTC |
| 74 (alta) | alta | `c569e00e1a929f2fcf18dda04f46a69ef03c4582fb055e83eeb4c922fe0908a0` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 74 (alta) | alta | `c56bab6942f5ed5b5eacb042382473f0759f45fe93c4d6c32c6582d5fb510567` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 73 (alta) | media | `7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c` | sha256_hash | VShell | ThreatFox | 2026-09-11 05:26:05 UTC |
| 73 (alta) | media | `b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5` | sha256_hash | VShell | ThreatFox | 2026-09-11 05:26:05 UTC |
| 73 (alta) | media | `c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d` | sha256_hash | VShell | ThreatFox | 2026-09-11 05:25:56 UTC |
| 73 (alta) | alta | `c563da502542ee60f589b10e7527829dba285de17d8feee007752a5ad201c849` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 72 (alta) | alta | `176[.]65[.]139[.]139:1234` | ip:port | Mirai | ThreatFox | 2026-09-11 09:09:03 UTC |
| 72 (alta) | alta | `176[.]65[.]139[.]139:3778` | ip:port | Mirai | ThreatFox | 2026-09-11 09:09:02 UTC |
| 72 (alta) | media | `1a937fa01d4ff5ce37ce61bd6b6abdca0c9bd6f66752e640b77bef673f20bd27` | sha256_hash | Coinminer | ThreatFox | 2026-09-11 05:26:06 UTC |
| 72 (alta) | alta | `440cb05dbc1425d4e40e70c260ac1aed00152c2d348ecb7c87aa7a8198cd9eae` | sha256_hash | Unknown Stealer | ThreatFox | 2026-09-11 05:26:01 UTC |
| 72 (alta) | media | `1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257` | sha256_hash | VShell | ThreatFox | 2026-09-11 05:25:57 UTC |
| 72 (alta) | media | `d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c` | sha256_hash | VShell | ThreatFox | 2026-09-11 05:25:56 UTC |
| 72 (alta) | alta | `c5913f8db147f164efa92fb1449d69fd63384b26775c1b3ecd08ec571d88bd4f` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:49 UTC |
| 72 (alta) | alta | `c585cf3efd2e543fcd45dae0623efa1520f65bf5d456d9fc99f6adec217c6e39` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 71 (alta) | alta | `f270a80b90acb4302bb29b2f4c7436f6d7eedc4738ca63351f59f22bd59ce28d` | sha256_hash | Vidar | ThreatFox | 2026-09-11 05:26:12 UTC |
| 71 (alta) | alta | `ffb3eacf4164d66a8d5e591c043f3f86d599e8d39384417d6fdf78796ae18a84` | sha256_hash | Unknown Stealer | ThreatFox | 2026-09-11 05:26:10 UTC |
| 71 (alta) | media | `a04ac6d98ad989312783d4fe3456c53730b212c79a426fb215708b6c6daa3de3` | sha256_hash | Hajime | ThreatFox | 2026-09-11 05:26:07 UTC |
| 71 (alta) | alta | `13bf1cfedc09e959f6fe09da8c9a687de9ed0d7ba10ca5839a6f0928429a1272` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-11 05:26:06 UTC |
| 71 (alta) | alta | `7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd` | sha256_hash | Mirai | ThreatFox | 2026-09-11 05:26:04 UTC |
| 71 (alta) | alta | `d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d` | sha256_hash | Mirai | ThreatFox | 2026-09-11 05:26:03 UTC |
| 71 (alta) | alta | `78e6be4b42f91994927633295f95f835596ba9224be5715202b1f88dd4e2b99a` | sha256_hash | Mirai | ThreatFox | 2026-09-11 05:26:02 UTC |
| 71 (alta) | alta | `0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a` | sha256_hash | Mirai | ThreatFox | 2026-09-11 05:26:00 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-86060 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-67277 | MikroTik RouterOS | 2026-09-10 | Unknown |
| CVE-2026-19490 | Citrix NetScaler | 2026-09-09 | Unknown |
| CVE-2025-25249 | Fortinet Multiple Products | 2026-09-09 | Unknown |
| CVE-2026-87491 | Google Chromium V8 | 2026-09-09 | Unknown |
| CVE-2026-20079 | Cisco Secure Firewall Management Center (FMC) and Security Cloud Control (SCC) Firewall Management | 2026-09-09 | Unknown |
| CVE-2026-75650 | Adobe Commerce and Magento | 2026-09-08 | Unknown |
| CVE-2026-81963 | Microsoft Windows | 2026-09-08 | Unknown |
| CVE-2026-86218 | N-able N-central | 2026-09-08 | Unknown |
| CVE-2026-85880 | Microsoft Windows | 2026-09-08 | Unknown |
| CVE-2026-85046 | Google Chromium V8 | 2026-09-04 | Unknown |
| CVE-2026-59822 | BerriAI LiteLLM | 2026-09-02 | Unknown |
| CVE-2026-48710 | Kludex Starlette | 2026-09-02 | Unknown |
| CVE-2026-49869 | Kestra Kestra OSS | 2026-09-02 | Unknown |
| CVE-2026-82329 | JFrog Artifactory | 2026-09-02 | Unknown |
| CVE-2026-9586 | Sangoma Switchvox | 2026-09-02 | Unknown |
| CVE-2026-83548 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-83549 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-82078 | PaperCut NG/MF | 2026-08-31 | Unknown |
| CVE-2026-81578 | PaperCut NG/MF | 2026-08-31 | Unknown |
<!-- CTI:END -->
