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
**Última actualización:** 2026-09-15 04:33 UTC · **IOCs recolectados:** 1571 · **CVEs KEV recientes:** 23

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `130[.]12[.]181[.]118:7000` | ip:port | XWorm | ThreatFox | 2026-09-14 13:59:39 UTC |
| 73 (alta) | media | `9d24316bd0f8af89c590f6c37070f905cb60a15745fbe748b525e67d2a05b640` | sha256_hash | VShell | ThreatFox | 2026-09-14 06:00:00 UTC |
| 73 (alta) | media | `07a7afd2a891cbd8b1600d0327a6832d596b655011b9fc79265c7e068bc8fc85` | sha256_hash | VShell | ThreatFox | 2026-09-14 05:59:52 UTC |
| 72 (alta) | alta | `74a28581cdc96b69d58c1b2f640c2f3c6932d11eb4b53fb5bf9cf2e89ac30dd4` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-14 21:28:11 UTC |
| 70 (alta) | media | `052f0caff530a67f9a17df5795806d9b01a551f309e434cd4eb92fba8e024051` | sha256_hash | GCleaner | ThreatFox | 2026-09-14 21:28:11 UTC |
| 70 (alta) | alta | `4f92f1b658856b2662100c26dcd5f81525a74482b4fdebb16923ec27234f0a7e` | sha256_hash | Unknown Stealer | ThreatFox | 2026-09-14 06:00:01 UTC |
| 70 (alta) | alta | `6478842eda7a2fa9a6a9c51ea58a6b33b08863b9d499aa2c3d7fe49233667873` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:58 UTC |
| 70 (alta) | alta | `e0a2c9631991fd3b5a5b4fddc8cb9075c1f3d9823c6975fc4a5de9c3ec3cafbf` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:56 UTC |
| 69 (media) | alta | `b9956521c3fb26cfb49791e6c3b29faae02ab8ac12314c2207f4f1301534df90` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-15 03:28:38 UTC |
| 69 (media) | media | `46f4cd435ca39c8fc2f1814fd9740a7ee9716207f5351d21008672ab466149eb` | sha256_hash | VShell | ThreatFox | 2026-09-14 06:00:03 UTC |
| 69 (media) | media | `54e27f31669d1d0c56514ceb76cf62bfa5c606ad3ec24cfef430837d2a01f071` | sha256_hash | VShell | ThreatFox | 2026-09-14 05:59:59 UTC |
| 69 (media) | alta | `2201104c6a6b96a0c44738a7c6b6c4d1e0a6c1b5a6c5849d7dc6fc1131d46c1f` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:56 UTC |
| 69 (media) | alta | `abacc0fbfcb50f16fbe843e0b7dcd2708c07d0b0d5da16e99dcf22e25f3ca758` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:55 UTC |
| 69 (media) | alta | `03e2f013429e8d6e5a7ec62d6a7f421c5cd5cc770b051fdaccc11f453e58a7ae` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:55 UTC |
| 69 (media) | alta | `d67aa0999565f6a528f5dc624ff18feeb7c45525ebcf0ee07b491fb2e7586014` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:54 UTC |
| 69 (media) | alta | `1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:54 UTC |
| 69 (media) | alta | `c277e70f886e3172f2e8b8bd6a83313552cceb29f949cc4c2afa1a0e19ac2ce9` | sha256_hash | Mirai | ThreatFox | 2026-09-14 05:59:53 UTC |
| 69 (media) | media | `2921c54b7d2c0a8a9dd0789cce72cdc55e58366d1fa064d44c059a2cb87d5657` | sha256_hash | VShell | ThreatFox | 2026-09-14 05:59:51 UTC |
| 68 (media) | media | `hxxps://hashedsolver[.]icu/update1[.]ps1` | url | Unknown malware | ThreatFox, URLhaus | 2026-09-14 21:21:05 UTC |
| 68 (media) | critica | `45[.]38[.]20[.]151:31337` | ip:port | Sliver | ThreatFox | 2026-09-14 11:13:56 UTC |
| 68 (media) | media | `115[.]190[.]149[.]134:3333` | ip:port | Unknown malware | ThreatFox | 2026-09-14 11:13:11 UTC |
| 68 (media) | media | `160[.]119[.]66[.]206:80` | ip:port | Unknown malware | ThreatFox | 2026-09-14 05:59:53 UTC |
| 66 (media) | alta | `159[.]203[.]178[.]139:8080` | ip:port | Aisuru | ThreatFox | 2026-09-14 22:47:03 UTC |
| 66 (media) | alta | `159[.]203[.]178[.]139:8001` | ip:port | Aisuru | ThreatFox | 2026-09-14 19:24:06 UTC |
| 61 (media) | alta | `134[.]209[.]223[.]192:8080` | ip:port | Aisuru | ThreatFox | 2026-09-14 22:47:02 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-85046 | Google Chromium V8 | 2026-09-04 | Unknown |
| CVE-2026-59822 | BerriAI LiteLLM | 2026-09-02 | Unknown |
| CVE-2026-48710 | Kludex Starlette | 2026-09-02 | Unknown |
| CVE-2026-49869 | Kestra Kestra OSS | 2026-09-02 | Unknown |
| CVE-2026-82329 | JFrog Artifactory | 2026-09-02 | Unknown |
| CVE-2026-9586 | Sangoma Switchvox | 2026-09-02 | Unknown |
| CVE-2026-83548 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
| CVE-2026-83549 | SonicWall SMA1000 Appliances | 2026-09-02 | Unknown |
<!-- CTI:END -->
