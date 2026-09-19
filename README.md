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
**Última actualización:** 2026-09-19 20:33 UTC · **IOCs recolectados:** 759 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | media | `6fa80698d7268f6e88aa88c06fb27ee99e1bcee747c2e76911e6206a5b1aeeb3` | sha256_hash | xmrig | ThreatFox | 2026-09-19 05:52:28 UTC |
| 69 (media) | alta | `d04c03df654d5cb80cd95be199b2e43337ea2f9de68addf4708fe8b73a03640f` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 05:52:23 UTC |
| 68 (media) | alta | `188[.]166[.]158[.]18:8001` | ip:port | Aisuru | ThreatFox | 2026-09-19 15:47:23 UTC |
| 68 (media) | alta | `188[.]166[.]158[.]18:8443` | ip:port | Aisuru | ThreatFox | 2026-09-19 15:46:46 UTC |
| 68 (media) | alta | `06d41e963ea49632f199c7bd18d7d939dc9d8dc6c02cf7ce714b7c24fef4868e` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 05:52:23 UTC |
| 68 (media) | alta | `b98fc9f0dbc61810287e77ea978665a0b762dceea927bbffceb63fb7005149b3` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 05:52:23 UTC |
| 67 (media) | alta | `f656b47e2337fea418a36933f173da98901d9ba4c0e05e3457ee3c59f94ad458` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-19 05:52:22 UTC |
| 66 (media) | media | `1b831a9366cd53a4127f885dab247bc2f0b3f661a7d9d9510bbd0a9f150bfb27` | sha256_hash | Ngioweb | ThreatFox | 2026-09-19 20:04:26 UTC |
| 66 (media) | media | `52bff4bf58eb6031c16763b12b696e849a38f36e69c55402a444819cb9c1bc0e` | sha256_hash | Ngioweb | ThreatFox | 2026-09-19 20:04:26 UTC |
| 66 (media) | media | `1631e63ee373601c1f42f2674f996fc6c14dc6aebe45ca5d2395bf347a0e3661` | sha256_hash | Ngioweb | ThreatFox | 2026-09-19 20:04:25 UTC |
| 63 (media) | alta | `167[.]71[.]45[.]235:9034` | ip:port | Aisuru | ThreatFox | 2026-09-19 19:49:57 UTC |
| 63 (media) | alta | `167[.]71[.]45[.]235:8080` | ip:port | Aisuru | ThreatFox | 2026-09-19 18:03:01 UTC |
| 63 (media) | alta | `167[.]71[.]45[.]235:8001` | ip:port | Aisuru | ThreatFox | 2026-09-19 15:47:24 UTC |
| 62 (media) | media | `66[.]23[.]197[.]18:8888` | ip:port | VShell | ThreatFox | 2026-09-19 01:05:04 UTC |
| 62 (media) | media | `45[.]192[.]213[.]11:80` | ip:port | VShell | ThreatFox | 2026-09-18 22:05:06 UTC |
| 61 (media) | alta | `178[.]128[.]167[.]82:9034` | ip:port | Aisuru | ThreatFox | 2026-09-19 18:02:59 UTC |
| 61 (media) | alta | `178[.]128[.]167[.]82:8001` | ip:port | Aisuru | ThreatFox | 2026-09-19 15:47:24 UTC |
| 61 (media) | media | `165[.]232[.]73[.]74:80` | ip:port | AMOS | ThreatFox | 2026-09-19 05:52:48 UTC |
| 60 (media) | media | `13e3e1310dd9e9210ed937a651361be16b554be2d20ce5ae06b1dcf610dda603` | sha256_hash | Unknown malware | ThreatFox | 2026-09-19 09:19:14 UTC |
| 59 (media) | media | `hxxp://118[.]145[.]196[.]225:800/` | url | Ngioweb | ThreatFox | 2026-09-19 20:04:28 UTC |
| 58 (media) | alta | `hxxp://193[.]160[.]32[.]138:8085/?h=193[.]160[.]32[.]138&p=8085&t=ws&a=l64&stage=true` | url | Mirai | ThreatFox | 2026-09-19 19:28:20 UTC |
| 58 (media) | alta | `144[.]126[.]224[.]25:8001` | ip:port | Aisuru | ThreatFox | 2026-09-19 15:47:25 UTC |
| 58 (media) | alta | `144[.]126[.]224[.]25:8443` | ip:port | Aisuru | ThreatFox | 2026-09-19 15:46:46 UTC |
| 58 (media) | media | `hxxp://222[.]112[.]70[.]149:8084/?h=222[.]112[.]70[.]149&p=8084&t=tcp&a=w32&stage=true` | url | VShell | ThreatFox | 2026-09-19 15:46:40 UTC |
| 58 (media) | alta | `193[.]124[.]131[.]235:2409` | ip:port | Remcos | ThreatFox | 2026-09-19 05:52:51 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2025-39964 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-53266 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2025-39682 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-58704 | Google Pixel | 2026-09-16 | Unknown |
| CVE-2026-76460 | Cisco Identity Services Engine | 2026-09-16 | Unknown |
| CVE-2026-87886 | Acronis Backup | 2026-09-16 | Unknown |
| CVE-2026-76461 | Cisco Secure Email Gateway | 2026-09-14 | Unknown |
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
<!-- CTI:END -->
