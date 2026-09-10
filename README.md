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
**Última actualización:** 2026-09-10 16:21 UTC · **IOCs recolectados:** 4544 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `c56c57e77a34895e23a4074201021f516694eef5b917035c375e05390a5a4976` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 74 (alta) | alta | `c59eb755bf1ae526a437b9be70026c8ba11fa71464ca58ad9c7a940ddb8a061c` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:49 UTC |
| 74 (alta) | alta | `c569e00e1a929f2fcf18dda04f46a69ef03c4582fb055e83eeb4c922fe0908a0` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 74 (alta) | alta | `c56bab6942f5ed5b5eacb042382473f0759f45fe93c4d6c32c6582d5fb510567` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 73 (alta) | alta | `c563da502542ee60f589b10e7527829dba285de17d8feee007752a5ad201c849` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 72 (alta) | alta | `c5913f8db147f164efa92fb1449d69fd63384b26775c1b3ecd08ec571d88bd4f` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:49 UTC |
| 72 (alta) | alta | `c585cf3efd2e543fcd45dae0623efa1520f65bf5d456d9fc99f6adec217c6e39` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 71 (alta) | alta | `c56c00ca3f42026f17affef76b3752f268d1498f862b3143985ca7c1d33feb39` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 71 (alta) | alta | `176[.]65[.]139[.]206:80` | ip:port | Mirai | ThreatFox | 2026-09-10 05:13:47 UTC |
| 71 (alta) | media | `176[.]65[.]139[.]206:11121` | ip:port | Unknown malware | ThreatFox | 2026-09-10 05:12:59 UTC |
| 70 (alta) | alta | `c5861e298e0352018b982c381bc63dc0248bb45c939fe91eb69d72e5469a2460` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 68 (media) | alta | `c59878f34eb08565dde137d3da8f37185c07b01de149b4c210497703c737605a` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:49 UTC |
| 66 (media) | alta | `c55dffdcb320a06872faa4cc7777bafd81051a17533e919fbee3fc27e8f47135` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 64 (media) | alta | `64[.]89[.]160[.]225:7001` | ip:port | XWorm | ThreatFox | 2026-09-10 11:25:43 UTC |
| 62 (media) | alta | `c56d83b77f74c6539a9fd13f34652c4794e08ccb3f645be0baba6f1a704afcd6` | sha256_hash | AsyncRAT | ThreatFox | 2026-09-10 15:39:48 UTC |
| 61 (media) | alta | `64[.]225[.]107[.]48:8443` | ip:port | Aisuru | ThreatFox | 2026-09-10 11:07:59 UTC |
| 61 (media) | alta | `hxxp://91[.]92[.]242[.]236/files-129312398/files/file_c0d2eb6a8b73120b[.]exe` | url | Vidar | ThreatFox | 2026-09-10 05:13:01 UTC |
| 61 (media) | media | `144[.]172[.]65[.]54:80` | ip:port | VShell | ThreatFox | 2026-09-10 05:05:07 UTC |
| 60 (media) | media | `hxxp://hotaccents[.]com:5282` | url | Unknown malware | ThreatFox | 2026-09-10 15:51:38 UTC |
| 60 (media) | alta | `hxxp://91[.]92[.]242[.]236/files-129312398/files/file_b584670f7ec2f317[.]exe` | url | Stealc | ThreatFox | 2026-09-10 05:13:03 UTC |
| 59 (media) | alta | `hxxp://beautynams[.]com/nweke/fre[.]php` | url | Loki Password Stealer (PWS) | ThreatFox | 2026-09-10 10:45:06 UTC |
| 59 (media) | critica | `38[.]54[.]97[.]169:4321` | ip:port | AdaptixC2 | ThreatFox | 2026-09-10 09:46:39 UTC |
| 59 (media) | media | `192[.]241[.]151[.]6:8443` | ip:port | Evilginx | ThreatFox | 2026-09-09 19:44:56 UTC |
| 59 (media) | alta | `155[.]103[.]71[.]126:4142` | ip:port | Remcos | ThreatFox | 2026-09-09 16:43:01 UTC |
| 57 (media) | media | `hxxp://139[.]95[.]24[.]51:8081/?h=139[.]95[.]24[.]51&p=8081&t=tcp&a=w64&stage=true` | url | Rozena | ThreatFox | 2026-09-10 11:07:58 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2023-49105 | ownCloud ownCloud | 2026-08-27 | Unknown |
| CVE-2026-53362 | Linux Kernel | 2026-08-27 | Unknown |
| CVE-2026-66384 | JFrog Artifactory | 2026-08-27 | Unknown |
<!-- CTI:END -->
