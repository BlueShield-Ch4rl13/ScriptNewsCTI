# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Plataforma ligera de **Cyber Threat Intelligence** que se actualiza sola cada 6 horas mediante GitHub Actions. Responde a tres preguntas:

- **¿Qué CVE nuevos importan?** Los de la última semana (NVD), ordenados por **explotación real** y no solo por CVSS: primero lo que ya se explota (CISA KEV, SSVC de CISA), después lo que más probablemente se explotará (FIRST EPSS) y por último la gravedad.
- **¿Está en riesgo mi sistema?** Por tipo de sistema (Windows, Linux, Apple, Android, navegadores, red y VPN, routers e IoT, virtualización y nube, IA y agentes, industrial…): CVE nuevos, críticos y explotación activa en los últimos 30 días.
- **¿Está comprometido mi lenguaje?** Por lenguaje (JavaScript, Python, Java, .NET, PHP, Go, Rust, Ruby…): si **el propio lenguaje** (intérprete o runtime) tiene CVE explotados, y cuántos **paquetes maliciosos** y avisos graves han aparecido en su registro (npm, PyPI, Maven…).

Además recolecta IOCs de feeds públicos, los **fusiona entre fuentes**, los enriquece (GeoIP, VirusTotal, AbuseIPDB) y calcula un **score de confianza** y una **gravedad** por indicador. Todo se publica en un dashboard estático, en este README y en `data/` (JSON + CSV).

🌐 **Dashboard en vivo:** https://cti.carlosvillalbalagos.com

> ⚠️ Uso exclusivamente defensivo (TLP:CLEAR). Los IOCs se muestran defangueados.

## Fuentes

| Feed | Datos | API key |
|---|---|---|
| ThreatFox (abuse.ch) | IOCs de malware (IP, dominios, URLs, hashes) | Gratuita, obligatoria |
| URLhaus (abuse.ch) | URLs de distribución de malware | Gratuita, obligatoria |
| AlienVault OTX | Indicadores de pulses suscritos | Gratuita, opcional |
| CISA KEV | CVEs explotados activamente (catálogo completo) | No requiere |
| NVD API 2.0 | CVE publicados en los últimos 7 días: CVSS, CWE, CPE y SSVC de CISA | Gratuita, opcional (`NVD_API_KEY`: 50 peticiones/30 s en vez de 5) |
| FIRST EPSS | Probabilidad de explotación en los próximos 30 días de cada CVE | No requiere |
| GitHub Advisory Database | Paquetes maliciosos y avisos revisados por ecosistema (npm, PyPI, Maven, NuGet, Packagist, Go, crates.io, RubyGems, Hex, pub.dev, SwiftPM, Actions) | El `GITHUB_TOKEN` de solo lectura del propio workflow |
| VirusTotal | Reputación de hashes, dominios, URLs e IPs | Gratuita, opcional |
| AbuseIPDB | Reputación, país e ISP de IPs | Gratuita, opcional |
| DB-IP Country Lite | GeoIP offline para todas las IPs | No requiere |

## Arquitectura

```
feeds públicos ──> collectors.py ──> fusión multi-fuente (enrich.py)
                                             │
              estado histórico (data/ioc_state.json, en la caché de Actions)
                                             │
              enriquecimiento: GeoIP · VirusTotal · AbuseIPDB (caché + presupuesto)
                                             │
                              score de confianza + gravedad
                                             │
GitHub Actions (cron 6h) <── main.py ──> data/*.json|csv + README + dashboard
```

El frontend no realiza ninguna llamada externa: todo el enriquecimiento ocurre en el backend del pipeline y el dashboard solo lee `data/iocs_latest.json` y `data/vulns_latest.json`.

## Vulnerabilidades: cómo se prioriza

`vulnerabilidades.py` genera `data/vulns_latest.json`. Cada CVE de la semana recibe una prioridad:

| Prioridad | Criterio |
|---|---|
| **explotada** | Está en CISA KEV o CISA lo marca con SSVC *exploitation: active* |
| **urgente** | EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o con prueba de concepto pública (SSVC *poc*) |
| **alta** | CVSS ≥ 7, percentil EPSS ≥ 90 o prueba de concepto |
| **media / baja** | CVSS ≥ 4 / el resto |

Dentro de cada prioridad se ordena por EPSS y después por CVSS: un 7.5 que ya se explota va antes que un 9.8 que nadie ataca. Se usa la puntuación de NVD si la hay y, si el CVE aún espera análisis, la del CNA que lo publica.

**El fabricante** sale del catálogo KEV, del CPE de NVD o del CNA (Oracle, Google Chrome, Apple, Microsoft…), y la **categoría de sistema** de patrones sobre fabricante y producto o, si no hay, sobre la descripción. Muchos CVE nuevos aún no tienen CPE en NVD, así que una parte cae en «Otros».

**El propio lenguaje** solo se reconoce por fabricante y producto exactos (p. ej. *PHP Group / PHP*, *python / python*, *Oracle / Java SE*), nunca por la descripción: «PHP» o «Python» aparecen en miles de CVE que no son del lenguaje. Si CISA da por explotado el intérprete en los últimos 30 días, el lenguaje sale como **«El lenguaje se explota»**, por encima de los paquetes maliciosos.

La tabla del panel muestra los 600 CVE más prioritarios; las cifras cuentan todos. Si una fuente no responde, se anota en `fuentes` y se publica el resto.

## Score de confianza

Cada IOC recibe un score de 0 a 100 combinando señales del propio feed y validación externa, con decaimiento por antigüedad:

| Señal | Aporte |
|---|---|
| Fuente base | ThreatFox / URLhaus 40 · OTX 25 (se toma el máximo) |
| Multi-fuente | +10 por cada fuente adicional (máx. +20) |
| Confianza del feed | `confidence` × 0,15 (hasta +15) |
| AbuseIPDB | `abuseConfidenceScore` × 0,20 (hasta +20) |
| VirusTotal | ratio de detecciones × 25 (hasta +25) |
| Frescura | ×1,0 ≤7 días · ×0,85 ≤30 · ×0,6 ≤90 · ×0,3 resto, contando desde el `first_seen` del feed |

Sin claves de VirusTotal ni AbuseIPDB, el score refleja sobre todo la fuente y la confianza que da el propio feed, así que la mayoría de los IOCs quedan en la franja 40-59: la diferencia real la ponen las validaciones externas.

Antes de fusionar, cada indicador se normaliza: `1.2.3.4` y `1.2.3.4:443` cuentan como el mismo (y suman la bonificación multi-fuente), los tipos se unifican (`sha256_hash` y `FileHash-SHA256` → `filehash-sha256`), los CVE salen de la lista de IOCs (van en la lista KEV), los dominios de grandes proveedores (google.com, microsoft.com…) se descartan y los PTR de máquinas de Google Cloud se convierten en su IP.

Niveles: **alta** ≥70 · **media** 40–69 · **baja** <40.

## Gravedad

Dimensión independiente del score: el score mide *cuánto fiarse del indicador*; la gravedad, *el impacto de la amenaza si es real*. Un IOC puede ser score bajo + gravedad crítica (mención única y antigua de LockBit) o score alto + gravedad media (URL de payload confirmadísima).

| Gravedad | Criterio |
|---|---|
| **crítica** | ransomware (LockBit, Akira, RansomHub…) y frameworks C2 (Cobalt Strike, Sliver, Havoc, AdaptixC2…) |
| **alta** | RATs, stealers, loaders y botnets — familias conocidas o categoría genérica como palabra completa en el nombre («X Stealer», «Unknown RAT»…; «Operation» ya no cuenta como «rat») |
| **media** | resto de amenazas identificadas, o desconocidas con ratio de detecciones VT ≥ 0,3 |
| **baja** | sin familia identificada ni señal externa |

Las listas viven en `SEV_CRITICA` / `SEV_ALTA` / `SEV_ALTA_GENERICAS` de `enrich.py` y se amplían según aparecen familias nuevas en los feeds.

En OTX la amenaza sale de las familias de malware del pulse. Si el pulse no tiene ninguna y solo queda su título, la gravedad se limita a **media**: el título describe la campaña, no cada uno de sus indicadores.

## Enriquecimiento externo y límites

- **GeoIP**: base [DB-IP Country Lite](https://db-ip.com) (CC BY 4.0), sin registro ni clave. Se descarga bajo demanda (~10 MB) al directorio temporal del runner y los lookups son offline: sin límites, cubre todas las IPs.
- **VirusTotal** (4 req/min · 500/día en plan gratuito): 40 lookups por ejecución con pausa de 15,5 s.
- **AbuseIPDB** (1.000 checks/día): 150 IPs por ejecución.
- Los resultados se **cachean 7 días** en `data/ioc_state.json`, que vive en la caché de GitHub Actions y no en el repositorio (subirlo en cada ejecución hacía crecer el repo ~100 MB al año). Siempre se prioriza lo nuevo. Sin claves, el pipeline sigue funcionando con fusión + confianza del feed + frescura + gravedad + GeoIP.

Ajustable vía variables de entorno en el workflow: `VT_BUDGET`, `ABUSEIPDB_BUDGET`, `CTI_RECHECK_DAYS`, `CTI_RETENTION_DAYS`, `CTI_MAX_STATE`. `CTI_MAX_STATE` (6.000) es el tope del **estado** interno; lo que se publica en cada ejecución son los IOCs de las últimas 24 h de los feeds, normalmente unos 2.000.

### Seguridad del workflow

- Dos jobs: `generar` ejecuta el pipeline con permisos de solo lectura y sin el token de GitHub en el runner (`persist-credentials: false`); `publicar` solo copia los ficheros generados y hace commit.
- Acciones fijadas por SHA y dependencias instaladas con `--require-hashes` (`requirements.txt` sale de `requirements.in` con `pip-compile --generate-hashes`).

### Licencias de los datos

El código es MIT (`LICENSE`). Los datos republicados tienen sus propias condiciones: abuse.ch (ThreatFox, URLhaus) y CISA KEV permiten la redistribución; DB-IP Country Lite exige atribución (CC BY 4.0); **AlienVault OTX, VirusTotal y AbuseIPDB tienen términos de uso propios que hay que revisar antes de republicar sus resultados** (en particular, el plan gratuito de VirusTotal no permite uso comercial).

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
pip install --require-hashes -r requirements.txt
export ABUSECH_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"          # opcional
export VT_API_KEY="tu_clave"           # opcional
export ABUSEIPDB_API_KEY="tu_clave"    # opcional
python main.py
```

## Estructura

```
├── .github/workflows/cti-update.yml   # cron: generar (solo lectura) + publicar (commit)
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── enrich.py                          # fusión, estado histórico, GeoIP, reputación, score y gravedad
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
├── tests/                             # pruebas de fusión, edad, gravedad y depuración
└── data/                              # iocs_latest.json / .csv (el estado va en la caché de Actions)
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-10-26 12:48 UTC · **IOCs recolectados:** 5616 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `160[.]119[.]66[.]206:443` | ip:port | Unknown malware | ThreatFox | 2026-10-25 17:14:00 UTC |
| 74 (alta) | media | `94[.]154[.]43[.]195:9111` | ip:port | Unknown malware | ThreatFox | 2026-10-26 06:35:23 UTC |
| 74 (alta) | media | `217[.]60[.]103[.]135:65000` | ip:port | Unknown malware | ThreatFox | 2026-10-25 17:14:13 UTC |
| 72 (alta) | alta | `176[.]65[.]149[.]4:1367` | ip:port | Mirai | ThreatFox | 2026-10-26 06:36:23 UTC |
| 72 (alta) | media | `31[.]22[.]104[.]54:18899` | ip:port | XMRIG | ThreatFox | 2026-10-25 14:34:50 UTC |
| 71 (alta) | alta | `176[.]65[.]139[.]40:80` | ip:port | Mirai | ThreatFox | 2026-10-26 09:44:02 UTC |
| 71 (alta) | media | `104[.]194[.]155[.]122:19191` | ip:port | Bashlite | ThreatFox | 2026-10-26 06:36:16 UTC |
| 71 (alta) | media | `168[.]220[.]248[.]106:443` | ip:port | Unknown malware | ThreatFox | 2026-10-26 06:35:48 UTC |
| 71 (alta) | media | `36[.]255[.]97[.]197:443` | ip:port | Unknown malware | ThreatFox | 2026-10-26 06:35:39 UTC |
| 71 (alta) | media | `176[.]65[.]139[.]76:443` | ip:port | Unknown malware | ThreatFox | 2026-10-25 19:58:03 UTC |
| 71 (alta) | media | `91[.]92[.]43[.]221:443` | ip:port | Unknown malware | ThreatFox | 2026-10-25 19:58:00 UTC |
| 71 (alta) | media | `103[.]170[.]217[.]170:443` | ip:port | Unknown malware | ThreatFox | 2026-10-25 19:48:01 UTC |
| 71 (alta) | media | `109[.]123[.]243[.]121:443` | ip:port | Unknown malware | ThreatFox | 2026-10-25 19:47:58 UTC |
| 71 (alta) | alta | `103[.]119[.]19[.]218:443` | ip:port | Mirai | ThreatFox | 2026-10-25 19:23:51 UTC |
| 71 (alta) | alta | `102[.]129[.]229[.]131:443` | ip:port | Mirai | ThreatFox | 2026-10-25 19:23:50 UTC |
| 71 (alta) | alta | `101[.]36[.]104[.]239:443` | ip:port | Mirai | ThreatFox | 2026-10-25 19:03:43 UTC |
| 71 (alta) | media | `64[.]89[.]160[.]222:443` | ip:port | Bashlite | ThreatFox | 2026-10-25 19:03:38 UTC |
| 71 (alta) | media | `85[.]192[.]48[.]80:443` | ip:port | Unknown malware | ThreatFox | 2026-10-25 19:03:38 UTC |
| 70 (alta) | media | `13[.]143[.]132[.]242:443` | ip:port | Unknown malware | ThreatFox | 2026-10-26 06:35:33 UTC |
| 70 (alta) | media | `e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1` | filehash-sha256 | SalatStealer | ThreatFox | 2026-10-26 03:55:40 UTC |
| 70 (alta) | media | `47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b` | filehash-sha256 | SalatStealer | ThreatFox | 2026-10-26 03:55:39 UTC |
| 70 (alta) | media | `5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5` | filehash-sha256 | SalatStealer | ThreatFox | 2026-10-26 03:55:38 UTC |
| 70 (alta) | media | `087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9` | filehash-sha256 | SalatStealer | ThreatFox | 2026-10-26 03:55:37 UTC |
| 70 (alta) | media | `1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75` | filehash-sha256 | SalatStealer | ThreatFox | 2026-10-26 03:55:36 UTC |
| 70 (alta) | media | `d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0` | filehash-sha256 | SalatStealer | ThreatFox | 2026-10-26 03:55:35 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-114625 | Arista VeloCloud Orchestrator | 2026-10-23 | Unknown |
| CVE-2026-110447 | Collabora Collabora Online – Built-in CODE Server | 2026-10-23 | Unknown |
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
<!-- CTI:END -->
