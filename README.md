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
**Última actualización:** 2026-08-19 07:04 UTC · **IOCs recolectados:** 3142 · **CVEs KEV recientes:** 10

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 71 (alta) | alta | `46[.]151[.]182[.]30:7443` | ip:port | Unknown Stealer | ThreatFox | 2026-08-19 06:06:10 UTC |
| 71 (alta) | alta | `46[.]151[.]182[.]30:7080` | ip:port | Unknown Stealer | ThreatFox | 2026-08-19 06:06:09 UTC |
| 66 (media) | critica | `103[.]185[.]249[.]13:31337` | ip:port | Sliver | ThreatFox | 2026-08-18 12:01:33 UTC |
| 66 (media) | critica | `103[.]70[.]77[.]226:31337` | ip:port | Sliver | ThreatFox | 2026-08-18 12:01:29 UTC |
| 60 (media) | alta | `governorhobbies[.]cfd` | domain | Unknown Loader | ThreatFox | 2026-08-19 06:47:42 UTC |
| 59 (media) | alta | `snailsreading[.]xyz` | domain | Unknown Loader | ThreatFox | 2026-08-19 06:47:42 UTC |
| 59 (media) | alta | `195[.]177[.]94[.]60:7080` | ip:port | Unknown Stealer | ThreatFox | 2026-08-19 06:05:56 UTC |
| 59 (media) | alta | `196[.]251[.]107[.]252:24027` | ip:port | Remcos | ThreatFox | 2026-08-19 00:55:05 UTC |
| 58 (media) | media | `corrykro[.]icu` | domain | IClickFix | ThreatFox | 2026-08-19 06:51:18 UTC |
| 58 (media) | media | `indytravelclub[.]com` | domain | IClickFix | ThreatFox | 2026-08-19 06:45:17 UTC |
| 58 (media) | alta | `195[.]177[.]94[.]19:56003` | ip:port | PureRAT | ThreatFox | 2026-08-18 19:44:42 UTC |
| 58 (media) | media | `103[.]84[.]230[.]85:443` | ip:port | Unknown malware | ThreatFox | 2026-08-18 12:28:39 UTC |
| 58 (media) | media | `103[.]87[.]68[.]158:443` | ip:port | Unknown malware | ThreatFox | 2026-08-18 12:28:35 UTC |
| 58 (media) | media | `94[.]26[.]106[.]206:80` | ip:port | MooBot | ThreatFox | 2026-08-18 12:10:47 UTC |
| 57 (media) | media | `atomento10[.]icu` | domain | IClickFix | ThreatFox | 2026-08-19 06:51:17 UTC |
| 56 (media) | alta | `sofazinc[.]cfd` | domain | Unknown Loader | ThreatFox | 2026-08-19 06:47:42 UTC |
| 56 (media) | media | `enoria[.]se` | domain | IClickFix | ThreatFox | 2026-08-19 06:45:15 UTC |
| 56 (media) | alta | `43[.]134[.]49[.]218:9034` | ip:port | Aisuru | ThreatFox | 2026-08-19 06:05:09 UTC |
| 56 (media) | alta | `43[.]128[.]113[.]133:5555` | ip:port | Aisuru | ThreatFox | 2026-08-19 06:05:06 UTC |
| 56 (media) | alta | `168[.]144[.]188[.]31:8443` | ip:port | Aisuru | ThreatFox | 2026-08-19 06:04:57 UTC |
| 56 (media) | alta | `150[.]109[.]93[.]78:37215` | ip:port | Aisuru | ThreatFox | 2026-08-19 06:04:54 UTC |
| 56 (media) | alta | `43[.]134[.]49[.]218:12345` | ip:port | Aisuru | ThreatFox | 2026-08-19 06:04:54 UTC |
| 56 (media) | media | `hxxp://bravplo[.]click:7713/profiles` | url | Remus | ThreatFox | 2026-08-19 00:40:47 UTC |
| 56 (media) | alta | `62k1d7bn[.]shop-sightfresh[.]com` | domain | ClearFake | ThreatFox | 2026-08-18 17:22:21 UTC |
| 56 (media) | alta | `y01q42ad[.]theslimsplitsmethod[.]com` | domain | ClearFake | ThreatFox | 2026-08-18 17:18:28 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-33824 | Microsoft Internet Key Exchange (IKE) Service Extensions | 2026-08-18 | Unknown |
| CVE-2026-59310 | Broadcom VMware vCenter | 2026-08-18 | Unknown |
| CVE-2026-55040 | Microsoft SharePoint | 2026-08-18 | Unknown |
| CVE-2026-65400 | Apple macOS | 2026-08-18 | Unknown |
| CVE-2025-62593 | Ray-Project Ray | 2026-08-17 | Unknown |
| CVE-2026-20349 | Cisco Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD)  | 2026-08-11 | Unknown |
| CVE-2026-68820 | Microsoft Windows Ancillary Function Driver for WinSock  | 2026-08-11 | Unknown |
| CVE-2026-72898 | Metabase Metabase | 2026-08-11 | Unknown |
| CVE-2026-8037 | Progress LoadMaster | 2026-08-07 | Unknown |
| CVE-2026-63077 | JetBrains TeamCity | 2026-08-05 | Unknown |
<!-- CTI:END -->
