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
**Última actualización:** 2026-09-17 16:50 UTC · **IOCs recolectados:** 2366 · **CVEs KEV recientes:** 19

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | alta | `217[.]60[.]195[.]161:8001` | ip:port | Aisuru | ThreatFox | 2026-09-17 14:13:39 UTC |
| 71 (alta) | alta | `143[.]20[.]185[.]213:80` | ip:port | Mirai | ThreatFox | 2026-09-16 19:43:45 UTC |
| 71 (alta) | alta | `dc834c0c0982771016202f3ca1808d3bba329379eba79e1d04db31cafb1f43e1` | sha256_hash | Unknown Loader | ThreatFox | 2026-09-16 16:43:51 UTC |
| 62 (media) | media | `217[.]60[.]195[.]6:8443` | ip:port | CECbot | ThreatFox | 2026-09-17 05:41:43 UTC |
| 61 (media) | media | `hxxps://miamipcsupport[.]com/curl/57133df069b129caa0380eff96eb60ccfb5c58eb19f2d9dc8447618a1898b76a` | url | MacSync | ThreatFox | 2026-09-17 16:31:37 UTC |
| 61 (media) | critica | `22ae11d4d8971b1b1bc2c80b7a70e59dadd6112bc1ecfce750093d1d5f87e27f` | sha256_hash | PoshC2 | ThreatFox | 2026-09-17 05:41:37 UTC |
| 60 (media) | media | `hxxps://olympiapetemergency[.]com/curl/5b7250991558c1089d217b180d9418df77886996c22f8f319d7f640895e03381` | url | MacSync | ThreatFox | 2026-09-17 16:31:37 UTC |
| 60 (media) | media | `hxxps://customroofingcontractors[.]com/curl/b42a0ed9d1ecb72e42d6034502c304845d98805481d99cea4e259359f9ab206e` | url | MacSync | ThreatFox | 2026-09-17 16:31:35 UTC |
| 59 (media) | media | `hxxps://premierrentalpurchase[.]com/curl/5b7250991558c1089d217b180d9418df77886996c22f8f319d7f640895e03381` | url | MacSync | ThreatFox | 2026-09-17 16:31:38 UTC |
| 59 (media) | media | `hxxps://dallasirrigationservices[.]com/curl/fa90319c89e7a0272c859f9f1403c6c2f12793281d3a295ce283d6018d5dd1c3` | url | MacSync | ThreatFox | 2026-09-17 16:31:36 UTC |
| 59 (media) | media | `hxxps://elitefenceanddeck[.]com/curl/5b7250991558c1089d217b180d9418df77886996c22f8f319d7f640895e03381` | url | MacSync | ThreatFox | 2026-09-17 16:31:36 UTC |
| 59 (media) | media | `hxxps://cincycarpetcleaning[.]com/curl/6e2d25066bc1db68a10d55189c7c0bae6443d5178fd4310808270e261236ce30` | url | MacSync | ThreatFox | 2026-09-17 16:31:35 UTC |
| 59 (media) | media | `hxxps://byrnewealthmanagement[.]com/curl/5b7250991558c1089d217b180d9418df77886996c22f8f319d7f640895e03381` | url | MacSync | ThreatFox | 2026-09-17 16:31:34 UTC |
| 59 (media) | media | `hxxps://aidevmaster[.]com/curl/5b7250991558c1089d217b180d9418df77886996c22f8f319d7f640895e03381` | url | MacSync | ThreatFox | 2026-09-17 16:31:33 UTC |
| 59 (media) | media | `hxxps://alabamarecoverycenter[.]com/curl/b42a0ed9d1ecb72e42d6034502c304845d98805481d99cea4e259359f9ab206e` | url | MacSync | ThreatFox | 2026-09-17 16:31:33 UTC |
| 59 (media) | media | `130[.]94[.]30[.]168:8090` | ip:port | VShell | ThreatFox | 2026-09-16 21:05:08 UTC |
| 58 (media) | media | `hxxps://legacybuilderscolorado[.]com/curl/499a828191d39ffd2cf302b35184c87696d5e1325bc40406a88bc7d213ec83df` | url | MacSync | ThreatFox | 2026-09-17 16:31:37 UTC |
| 58 (media) | media | `hxxps://legacybuilderscolorado[.]com/curl/720e1e04c2690ac14874d54823354d6bd06336b23e8458debaffeb2b18f5be6a` | url | MacSync | ThreatFox | 2026-09-17 16:31:37 UTC |
| 58 (media) | media | `hxxps://legacybuilderscolorado[.]com/curl/eaed253ce468efe4a95d739c882b9694ad635169136238a4a5849734f5fd1bb8` | url | MacSync | ThreatFox | 2026-09-17 16:31:37 UTC |
| 58 (media) | media | `hxxps://oregoninteriors[.]com/curl/85cb26206d920216eee0c5f67e8de516b4d55bd1752025bb3c08a069a44fdbdf` | url | MacSync | ThreatFox | 2026-09-17 16:31:37 UTC |
| 58 (media) | media | `hxxps://hybridcustomhomes[.]com/curl/720e1e04c2690ac14874d54823354d6bd06336b23e8458debaffeb2b18f5be6a` | url | MacSync | ThreatFox | 2026-09-17 16:31:36 UTC |
| 58 (media) | media | `hxxps://criminallawyerpr[.]com/curl/720e1e04c2690ac14874d54823354d6bd06336b23e8458debaffeb2b18f5be6a` | url | MacSync | ThreatFox | 2026-09-17 16:31:35 UTC |
| 58 (media) | media | `hxxps://criminallawyerpr[.]com/curl/85cb26206d920216eee0c5f67e8de516b4d55bd1752025bb3c08a069a44fdbdf` | url | MacSync | ThreatFox | 2026-09-17 16:31:35 UTC |
| 58 (media) | media | `hxxps://criminallawyerpr[.]com/curl/8e92ee3f0bccc8211145e3aee82c34e9ae67058e9abf154e4b335a6575f97833` | url | MacSync | ThreatFox | 2026-09-17 16:31:35 UTC |
| 58 (media) | media | `hxxps://atlantaairporttaxiservice[.]com/curl/8e92ee3f0bccc8211145e3aee82c34e9ae67058e9abf154e4b335a6575f97833` | url | MacSync | ThreatFox | 2026-09-17 16:31:34 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-85046 | Google Chromium V8 | 2026-09-04 | Unknown |
<!-- CTI:END -->
