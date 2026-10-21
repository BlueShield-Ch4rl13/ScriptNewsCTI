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
**Última actualización:** 2026-10-21 11:41 UTC · **IOCs recolectados:** 2822 · **CVEs KEV recientes:** 20

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `178[.]16[.]53[.]56:9035` | ip:port | Aisuru | ThreatFox | 2026-10-21 10:19:44 UTC |
| 75 (alta) | media | `77[.]239[.]124[.]135:9111` | ip:port | Unknown malware | ThreatFox | 2026-10-21 05:31:44 UTC |
| 72 (alta) | alta | `3d22f41bee487415272e17f7b9d029500b076e75ae5aaea80c0799e0190e5529` | sha256_hash | Vidar | ThreatFox | 2026-10-21 11:07:33 UTC |
| 72 (alta) | media | `176[.]97[.]117[.]157:80` | ip:port | VShell | ThreatFox | 2026-10-21 00:05:08 UTC |
| 62 (media) | alta | `fd5418a9e34037f9b64da8cc72650c12cf303f2e39f783b76f7dd2e7f576aac2` | sha256_hash | Mirai | ThreatFox | 2026-10-20 20:54:24 UTC |
| 61 (media) | media | `7311a535954158323045282fef16e143a4f323a8b2916518854874957eba1d45` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:27:01 UTC |
| 61 (media) | media | `hxxp://45[.]9[.]2[.]239:24381/bins/payloads/c[.]sh` | url | Unknown malware | ThreatFox, URLhaus | 2026-10-21 07:26:58 UTC |
| 61 (media) | media | `hxxp://45[.]9[.]2[.]239:24381/bins/payloads/w[.]sh` | url | Unknown malware | ThreatFox, URLhaus | 2026-10-21 07:26:58 UTC |
| 61 (media) | alta | `878c7206ad7699a6d1db1422b83de0b8cc1fb5d9cb0a76c7eded858e9808638b` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-21 03:54:32 UTC |
| 61 (media) | alta | `7a65172b9a59f8d7e958871a5e55f215f32bb17d8ec4e167c891373f83669973` | sha256_hash | Mirai | ThreatFox | 2026-10-21 03:54:30 UTC |
| 60 (media) | media | `46[.]101[.]249[.]247:23004` | ip:port | Drifter | ThreatFox | 2026-10-21 08:30:26 UTC |
| 60 (media) | alta | `6a80656ba9750f7999eb71786bd9c38017022f5fdc8810572678863692a335b1` | sha256_hash | Mirai | ThreatFox | 2026-10-21 03:54:29 UTC |
| 60 (media) | alta | `a3ffb06d9250492d20f6e3b72508d3a305908607198790cdd75f7ab1b1acab35` | sha256_hash | Mirai | ThreatFox | 2026-10-21 03:54:27 UTC |
| 59 (media) | alta | `2261c63c17c6ae904a419f98f51a8fd7607a3a0a952d87c4e85c36aaea158387` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-21 03:54:34 UTC |
| 59 (media) | alta | `2d29b6ca233a505d01e7d48bd0055a7cd2fd8c590d7e9bd132b8e9b55891c826` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-20 20:54:25 UTC |
| 58 (media) | media | `fd3988f2fc8bd69ebe48397fdfb082344eceab69f2801c23880865e7fea8ebb1` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:21:53 UTC |
| 58 (media) | media | `157[.]230[.]122[.]72:23004` | ip:port | Drifter | ThreatFox | 2026-10-21 09:29:38 UTC |
| 58 (media) | alta | `47f831411856e1523ff9ad36f02e16ac5ac57682002ff54ad917877e4601ce3a` | sha256_hash | Mirai | ThreatFox | 2026-10-21 03:54:31 UTC |
| 58 (media) | media | `hxxp://netulse[.]sbs:5621/articles` | url | Remus | ThreatFox | 2026-10-20 21:21:07 UTC |
| 58 (media) | media | `hxxp://popeak[.]biz:8312/products` | url | Remus | ThreatFox | 2026-10-20 16:17:07 UTC |
| 58 (media) | media | `hxxp://echjho[.]biz:7713/tokens` | url | Remus | ThreatFox | 2026-10-20 16:12:27 UTC |
| 57 (media) | media | `1d6102cbdf119cd3655d9beb30698a97ab69d996f2a1b913c0bd95b32076d2ac` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:29:27 UTC |
| 57 (media) | media | `5e74c21baf3f640e4a6334ac58dd9e0f3d3a29041098eda1204f70a6eae8223b` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:28:37 UTC |
| 57 (media) | media | `0a285cb3601f22e80adffa49ea241996b0dcd06731687e16f90604aca038fc96` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:24:30 UTC |
| 57 (media) | media | `48be074eadb236d3c7fac5ff9ad9062bc18d8fc6777a5959d2f288e81ec75caf` | sha256_hash | AMOS | ThreatFox | 2026-10-21 11:19:16 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | 2026-10-20 | Unknown |
| CVE-2026-96656 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96655 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96654 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96652 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-110936 | Siemens Software Center | 2026-10-20 | Unknown |
| CVE-2026-102764 | BeyondTrust Remote Support | 2026-10-16 | Unknown |
| CVE-2025-61624 | Fortinet Multiple Products | 2026-10-16 | Unknown |
| CVE-2026-21589 | Atlassian Multiple Products | 2026-10-15 | Unknown |
| CVE-2026-105134 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-76519 | Cisco Secure Email Gateway | 2026-10-14 | Unknown |
| CVE-2026-105133 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-0322 | Palo Alto Networks PAN-OS | 2026-10-14 | Unknown |
| CVE-2026-104935 | Ivanti Connect Secure | 2026-10-13 | Unknown |
| CVE-2026-96951 | Microsoft Windows | 2026-10-13 | Unknown |
| CVE-2015-5477 | ISC BIND | 2026-10-08 | Unknown |
| CVE-2016-3081 | Apache Struts | 2026-10-08 | Unknown |
| CVE-2023-22894 | Strapi Strapi | 2026-10-08 | Unknown |
| CVE-2021-3199 | ONLYOFFICE Docs | 2026-10-08 | Unknown |
| CVE-2015-3306 | ProFTPD ProFTPD | 2026-10-08 | Unknown |
<!-- CTI:END -->
