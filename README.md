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
**Última actualización:** 2026-09-13 11:40 UTC · **IOCs recolectados:** 911 · **CVEs KEV recientes:** 24

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `141[.]98[.]10[.]26:10213` | ip:port | CECbot | ThreatFox | 2026-09-13 11:09:05 UTC |
| 75 (alta) | alta | `213[.]209[.]159[.]91:443` | ip:port | PureRAT | ThreatFox | 2026-09-12 19:45:18 UTC |
| 73 (alta) | media | `6a341b3e9c265e672ac0bb8c72a7fb2b72f8872a1a12b5d1fa48b868ca43f8b4` | sha256_hash | MASS Logger | ThreatFox | 2026-09-13 06:34:15 UTC |
| 73 (alta) | media | `e11f3af65a8ff295858d81d135d49aadb0a157b48b7daffdc34c0c921a29d5ca` | sha256_hash | MASS Logger | ThreatFox | 2026-09-13 06:34:14 UTC |
| 73 (alta) | media | `114[.]111[.]53[.]214:22` | ip:port | XMRIG | ThreatFox | 2026-09-12 13:44:26 UTC |
| 73 (alta) | media | `103[.]182[.]132[.]154:22` | ip:port | XMRIG | ThreatFox | 2026-09-12 13:44:26 UTC |
| 73 (alta) | media | `45[.]78[.]201[.]248:22` | ip:port | XMRIG | ThreatFox | 2026-09-12 13:44:25 UTC |
| 73 (alta) | media | `120[.]26[.]164[.]252:9918` | ip:port | Payload  | ThreatFox | 2026-09-12 13:44:23 UTC |
| 72 (alta) | media | `223[.]19[.]66[.]178:22` | ip:port | Payload  | ThreatFox | 2026-09-12 13:44:24 UTC |
| 70 (alta) | alta | `9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:14 UTC |
| 70 (alta) | media | `86947b00a3d61b82b6f752876404953ff3c39952f2b261988baf63fbbbd6d6ae` | sha256_hash | Tsunami | ThreatFox | 2026-09-13 06:34:12 UTC |
| 69 (media) | alta | `b1e7123c09c5cc0d00ba274aa17f7f0c6b1871251063d071398d3199449115b9` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:22 UTC |
| 69 (media) | alta | `c630cb386ed061f395b2527513b40f45d5c857637856cdacef856a6b061ff277` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:22 UTC |
| 69 (media) | alta | `34307d43ad3de41e8913fead533bc27f33e458b83f0107053b822fbb5a6f1c57` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:22 UTC |
| 69 (media) | alta | `691a464914194f0afc7524c2b1e4b555c28acbbc8ac8ce7c33d461f3806084ec` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:16 UTC |
| 69 (media) | alta | `f6436608095cd0d25dde490e6ce7b23c9bad762f278efae6aa0201a9a68b3cba` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:16 UTC |
| 69 (media) | alta | `c9f1898be5497409f06688f413d277d3391ee1f4406b16a611bdcce761c04930` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:16 UTC |
| 69 (media) | media | `bc77970b42b8b065a4c268c9b25249c112f7b29c23a908743a0c29b1f9f80364` | sha256_hash | Bashlite | ThreatFox | 2026-09-13 06:34:15 UTC |
| 69 (media) | alta | `1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:13 UTC |
| 69 (media) | alta | `fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:13 UTC |
| 69 (media) | alta | `c61311407e9a31f60807d3cab8d38f254f3d961c4df04906de869415d3fd458e` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:12 UTC |
| 69 (media) | media | `0d762c8cbba56cd827c0dc710688d7410840940b9994020b8e365b63d3ff316c` | sha256_hash | Tsunami | ThreatFox | 2026-09-13 06:34:11 UTC |
| 69 (media) | alta | `5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:10 UTC |
| 69 (media) | alta | `8fb4cfabec6fa0b8f0e0d25135e87e88c13c3dce61c1335a89ee2e474a3d1570` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:10 UTC |
| 69 (media) | alta | `3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422` | sha256_hash | Mirai | ThreatFox | 2026-09-13 06:34:09 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-84869 | ConnectWise ScreenConnect | 2026-09-11 | Unknown |
| CVE-2026-42016 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-42018 | JFrog Artifactory | 2026-09-11 | Unknown |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition | 2026-09-11 | Unknown |
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
