# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Plataforma ligera de **Cyber Threat Intelligence** que se actualiza sola cada 3 horas mediante GitHub Actions. Responde a cuatro preguntas:

- **¿Qué fallos de seguridad están saliendo?** Los avisos de los últimos 7 días de **26 fuentes**: fabricantes (Microsoft, Cisco, Fortinet, Palo Alto, Ivanti, Chrome, Siemens…), CERT y gobiernos (**INCIBE-CERT**, CISA, CERT-EU, CERT-FR, CERT/CC), exploits e investigación (Zero Day Initiative, Exploit-DB, Project Zero, Wordfence) y noticias de vulnerabilidades (Una al Día, Segu-Info, The Hacker News…). Cada aviso se cruza con CISA KEV y EPSS y se marca si ya se explota, si es de día cero o si sale sin parche.
- **¿Qué CVE nuevos importan?** Los de la última semana (NVD), ordenados por **explotación real** y no solo por CVSS: primero lo que ya se explota (CISA KEV, SSVC de CISA), después lo que más probablemente se explotará (FIRST EPSS, o un exploit publicado en Exploit-DB) y por último la gravedad. Cada CVE dice si tiene exploit público, si lo usa el ransomware, si se explotó desde el primer día y qué avisos lo citan.
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
| Exploit-DB | Exploits públicos por CVE (`files_exploits.csv` completo, desde GitLab) | No requiere |
| PoC-in-GitHub (nomi-sec) | CVE con prueba de concepto en GitHub (sin verificar) | El mismo `GITHUB_TOKEN` |
| 26 feeds RSS/Atom de avisos | Fabricantes, CERT, exploits y noticias: ver [Avisos](#avisos-qué-fallos-van-saliendo) | No requiere |
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
GitHub Actions (cron 3h) <── main.py ──> data/*.json|csv + README + dashboard
                              │
     vulnerabilidades.py: NVD + EPSS + KEV + GitHub Advisory + Exploit-DB + PoC-in-GitHub
                              │
     avisos.py: 26 feeds de avisos, cruzados con lo anterior y con la ejecución previa
```

El frontend no realiza ninguna llamada externa: todo el enriquecimiento ocurre en el backend del pipeline y el dashboard solo lee `data/iocs_latest.json`, `data/vulns_latest.json` y `data/avisos_latest.json`.

## Vulnerabilidades: cómo se prioriza

`vulnerabilidades.py` genera `data/vulns_latest.json`. Cada CVE de la semana recibe una prioridad:

| Prioridad | Criterio |
|---|---|
| **explotada** | Está en CISA KEV o CISA lo marca con SSVC *exploitation: active* |
| **urgente** | EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o con prueba de concepto pública (SSVC *poc* o exploit en Exploit-DB) |
| **alta** | CVSS ≥ 7, percentil EPSS ≥ 90 o prueba de concepto |
| **media / baja** | CVSS ≥ 4 / el resto |

Dentro de cada prioridad se ordena por EPSS y después por CVSS: un 7.5 que ya se explota va antes que un 9.8 que nadie ataca. Se usa la puntuación de NVD si la hay y, si el CVE aún espera análisis, la del CNA que lo publica.

**El fabricante** sale del catálogo KEV, del CPE de NVD o del CNA (Oracle, Google Chrome, Apple, Microsoft…), y la **categoría de sistema** de patrones sobre fabricante y producto o, si no hay, sobre la descripción. Muchos CVE nuevos aún no tienen CPE en NVD, así que una parte cae en «Otros».

**El propio lenguaje** solo se reconoce por fabricante y producto exactos (p. ej. *PHP Group / PHP*, *python / python*, *Oracle / Java SE*), nunca por la descripción: «PHP» o «Python» aparecen en miles de CVE que no son del lenguaje. Si CISA da por explotado el intérprete en los últimos 30 días, el lenguaje sale como **«El lenguaje se explota»**, por encima de los paquetes maliciosos.

**Señales de cada CVE:** *EXPLOIT* (hay exploit en Exploit-DB, enlazado), *PoC* (hay una prueba de concepto en GitHub según PoC-in-GitHub: sin verificar, puede ser falsa o llevar malware, así que no cambia la prioridad ni se enlaza), *RANSOMWARE* (CISA KEV: usada en campañas de ransomware) y *DÍA 0* (CISA la metió en KEV antes, el mismo día o al día siguiente de publicarse). Debajo de la descripción, los avisos de la semana que lo citan.

La tabla del panel muestra los 600 CVE más prioritarios; las cifras cuentan todos. Si una fuente no responde, se anota en `fuentes` y se publica el resto.

## Avisos: qué fallos van saliendo

`avisos.py` genera `data/avisos_latest.json` con los avisos de los últimos 7 días de estas fuentes:

| Tipo | Fuentes |
|---|---|
| CERT y gobiernos | INCIBE-CERT (general e industrial), CISA (incluye los de ICS), CERT-EU, CERT-FR (alertas y avisos), CERT/CC |
| Fabricantes | Microsoft (MSRC), Cisco, Fortinet, Palo Alto Networks, Ivanti, Google Chrome, Siemens ProductCERT, GitLab, Ubuntu, Debian |
| Exploits e investigación | Zero Day Initiative, Exploit-DB, Google Project Zero, Wordfence |
| Noticias | Una al Día (Hispasec), Segu-Info, The Hacker News, BleepingComputer, SecurityWeek (solo titulares que hablan de una vulnerabilidad) |

De cada aviso se publica **solo el titular, el enlace, la fecha y los CVE que cita**; el texto es de su autor y solo se lee para sacar los CVE y las señales. Las señales:

| Señal | Cuándo |
|---|---|
| **Ya se explota** | Alguno de sus CVE está en CISA KEV, o el texto lo dice (*exploited in the wild*, *actively exploited*, *explotada activamente*, *activement exploitée*…) |
| **Día cero** | El texto habla de *zero-day* / *día cero*, o Chrome avisa de que el exploit *exists in the wild* |
| **Sin parche** | ZDI lo publica como *(0Day)* (el fabricante no lo corrigió a tiempo) o el texto dice que no hay parche |
| **Crítica** | El titular lo dice, o alguno de sus CVE tiene CVSS ≥ 9 |

«De qué se habla» lista los CVE que citan a la vez **varias fuentes distintas** (tres avisos de Siemens cuentan como una). Como algunos feeds solo traen sus últimas 10 entradas (INCIBE, Ubuntu…), cada ejecución conserva los avisos de la anterior que siguen dentro de la semana (hasta 60 por fuente), y una fuente que hoy no responde mantiene los suyos. Cada feed se descarga con un tope de 8 MB, se rechaza si declara entidades XML y solo se aceptan enlaces `http(s)`.

CCN-CERT no está porque su web rechaza las descargas automáticas (HTTP 403 desde GitHub Actions).

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
- **AbuseIPDB** (1.000 checks/día): 120 IPs por ejecución (8 ejecuciones al día = 960).
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
5. Listo: el cron lo ejecutará cada 3 h (hora UTC) y el bot hará commit de los cambios.

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
├── vulnerabilidades.py                # CVE de la semana: NVD, EPSS, KEV, GitHub Advisory, Exploit-DB, PoC-in-GitHub
├── avisos.py                          # avisos de fabricantes, CERT, exploits y noticias (26 feeds)
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
├── tests/                             # fusión, gravedad, prioridad de CVE, lectura de feeds y señales
└── data/                              # iocs, vulns y avisos (_latest.json) + CSV (el estado va en la caché de Actions)
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-11-01 19:31 UTC · **IOCs recolectados:** 2469 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 78 (alta) | alta | `31[.]56[.]209[.]35:8080` | ip:port | Unknown RAT | ThreatFox | 2026-11-01 12:44:35 UTC |
| 68 (media) | alta | `9b151f4ffa47622d8b0823c33dfb2471af4b619f1ef6296fbdb9089c076d5abf` | filehash-sha256 | Quasar RAT | ThreatFox | 2026-11-01 06:40:35 UTC |
| 68 (media) | media | `198[.]98[.]58[.]199:9205` | ip:port | Unknown malware | ThreatFox | 2026-11-01 05:18:49 UTC |
| 68 (media) | media | `34[.]97[.]167[.]85` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-01 00:09:17 UTC |
| 67 (media) | alta | `2[.]27[.]154[.]146:80` | ip:port | Mirai | ThreatFox | 2026-11-01 15:19:34 UTC |
| 66 (media) | alta | `db3587693b2199cd5ae490cca7c8bc5d35a388a6a00bf5d7108c64d080375fac` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:34 UTC |
| 66 (media) | alta | `3a19068222da0cbcae683ed9172f4122788daa2acf7eb3840def074723b6f806` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:34 UTC |
| 66 (media) | alta | `58b070fb7173b12de35917b8b949dccb8b52fdee3a7e2adf0dfcbfe043a60516` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:34 UTC |
| 66 (media) | alta | `048d2f354e35b1f6ecb6a6554016f9643e2c456bf9ea5b3d79e8bfd59fb4ca5c` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:33 UTC |
| 66 (media) | alta | `f3223d582b73ceae6cd3f35413554b18714b51524141149ceac811a3e341ec27` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:32 UTC |
| 66 (media) | alta | `656b337b580a1b5c726ff5b24799bdef03d73e8e6b0505239cd13bcde6b477cf` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:30 UTC |
| 66 (media) | alta | `ea50bd7f1db06a6676220ea7b64e26a53e400b733e2906f786b628096d92a50f` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:29 UTC |
| 66 (media) | alta | `dafbd79d183b0d4abd915f17daa6be9dfa437a688a1dedde9276e4e481e6b020` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 12:44:28 UTC |
| 63 (media) | media | `136[.]108[.]254[.]34` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-01 15:39:05 UTC |
| 62 (media) | alta | `763ead1b18e68bf48e5e1972a4ea64a5df78c4592823b774544f1fd0f78113d0` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 17:56:32 UTC |
| 62 (media) | alta | `aa11324ac0c1125db38f785d73231ca5a6e59be901f87a65410fda65a2288d07` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 17:56:31 UTC |
| 61 (media) | alta | `ffbc0bb6737736962ea732ad2fc92ea9e3c16fa876086146a1aeeab376b26372` | filehash-sha256 | Mirai | ThreatFox | 2026-11-01 17:56:33 UTC |
| 61 (media) | media | `136[.]115[.]36[.]75` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-01 16:52:29 UTC |
| 59 (media) | media | `f91bfcd2571820acef8619adaa13931d865034d983421967a5673340c7ad6251` | filehash-sha256 | AMOS | ThreatFox | 2026-11-01 18:37:05 UTC |
| 58 (media) | alta | `fb79b3cf3fe1752b147354c574106f6c89ed6cfeeec3b1919a0f30ccbcb856df` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-01 18:56:27 UTC |
| 57 (media) | alta | `hxxp://158[.]94[.]209[.]8/data` | url | Unknown Stealer | ThreatFox | 2026-11-01 18:54:14 UTC |
| 57 (media) | alta | `141[.]98[.]10[.]112:8001` | ip:port | Aisuru | ThreatFox | 2026-11-01 18:11:47 UTC |
| 57 (media) | critica | `23[.]227[.]203[.]239:64522` | ip:port | Cobalt Strike | ThreatFox | 2026-11-01 18:05:05 UTC |
| 57 (media) | critica | `38[.]76[.]190[.]209:8443` | ip:port | Cobalt Strike | ThreatFox | 2026-11-01 01:05:07 UTC |
| 57 (media) | media | `106[.]54[.]41[.]209:21117` | ip:port | Unknown malware | ThreatFox | 2026-10-31 20:05:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-118527 | Ivanti Connect Secure | 2026-10-30 | Unknown |
| CVE-2026-111357 | Ivanti Connect Secure | 2026-10-30 | Unknown |
| CVE-2026-97229 | GitLab Community Edition and Enterprise Edition | 2026-10-29 | Unknown |
| CVE-2026-76418 | Cisco Secure Firewall ASA Software and Cisco Secure FTD Software | 2026-10-29 | Unknown |
| CVE-2026-41709 | Broadcom VMware ESX | 2026-10-28 | Unknown |
| CVE-2026-46300 | Linux Kernel | 2026-10-28 | Unknown |
| CVE-2026-48356 | Adobe Commerce and Magento | 2026-10-27 | Unknown |
| CVE-2026-111497 | Google Brotli | 2026-10-27 | Unknown |
| CVE-2026-109618 | PHP Group PHP | 2026-10-26 | Unknown |
| CVE-2026-109619 | PHP Group PHP | 2026-10-26 | Unknown |
| CVE-2026-114625 | Arista VeloCloud Orchestrator | 2026-10-23 | Unknown |
| CVE-2026-110447 | Collabora Collabora Online – Built-in CODE Server | 2026-10-23 | Unknown |
| CVE-2026-106931 | EG Secure Solutions SiteGuard Server Edition | 2026-10-20 | Unknown |
| CVE-2026-96656 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96655 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96654 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-96652 | Plex Media Server | 2026-10-20 | Unknown |
| CVE-2026-110936 | Siemens Software Center | 2026-10-20 | Unknown |

### Avisos de seguridad de los últimos 7 días

**327** avisos de 24/26 fuentes (fabricantes, CERT, exploits y noticias) · **74** de algo que ya se explota · **7** de día cero · **31** sin parche

**Lo más citado:** CVE-2026-109618 (9 fuentes, KEV) · CVE-2026-111497 (9 fuentes, KEV) · CVE-2026-109619 (8 fuentes, KEV) · CVE-2026-76418 (5 fuentes, KEV) · CVE-2026-105482 (3 fuentes) · CVE-2026-105483 (3 fuentes) · CVE-2026-106069 (3 fuentes) · CVE-2026-97229 (3 fuentes, KEV)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-10-31 | Microsoft | [Chromium: CVE-2026-118305 Memory corruption in Turbolev](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118305) | crítica |
| 2026-10-31 | Microsoft | [Chromium: CVE-2026-118306 Memory corruption in FileSystem](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118306) | crítica |
| 2026-10-31 | Microsoft | [Chromium: CVE-2026-118340 Memory corruption in Skia](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118340) | crítica |
| 2026-10-31 | The Hacker News | [Attackers Chain Three Ivanti Connect Secure Flaws to Gain Unauthenticated Root Access](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html) | explotada |
| 2026-10-31 | Palo Alto Networks | [CVE-2026-111497 Portfolio Status: Impact of Brotli Vulnerability (CVE-2026-111497) on Palo Alto Networks Produ](https://security.paloaltonetworks.com/CVE-2026-111497) | explotada, crítica |
| 2026-10-30 | BleepingComputer | [Critical Linux kernel flaw allows remote root attacks on MPTCP servers](https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/) | crítica |
| 2026-10-30 | Cisco | [Vulnerabilities in Node.js Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-10-30 | Cisco | [Vulnerabilities in PHP Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20PHP%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-10-30 | BleepingComputer | [CISA says max severity GitLab flaw now exploited in the wild](https://www.bleepingcomputer.com/news/security/hackers-now-exploiting-max-severity-gitlab-flaw-in-attacks/) | explotada |
| 2026-10-30 | CISA | [CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/10/30/cisa-adds-two-known-exploited-vulnerabilities-catalog) | explotada |
| 2026-10-30 | SecurityWeek | [Drupal Commerce Core Vulnerability Exploited Against Online Stores](https://www.securityweek.com/drupal-commerce-core-vulnerability-exploited-against-online-stores/) | explotada |
| 2026-10-30 | BleepingComputer | [Drupal warns of critical Commerce Core flaw exploited in attacks](https://www.bleepingcomputer.com/news/security/drupal-warns-of-critical-commerce-core-flaw-exploited-in-attacks/) | explotada, crítica |
| 2026-10-30 | SecurityWeek | [Max-Severity GitLab Vulnerability Exploited Against Alpine Linux](https://www.securityweek.com/max-severity-gitlab-vulnerability-exploited-against-alpine-linux/) | explotada |
| 2026-10-30 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos de PEAK-System de HMS Networks](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-de-peak-system-de-hms-networks) | explotada |
| 2026-10-30 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en SMART EMS de Welotec](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-smart-ems-de-welotec) | explotada |
| 2026-10-30 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos de Contec](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-de-contec) | explotada |
| 2026-10-30 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos ASPECT de ABB](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-aspect-de-abb) | explotada |
| 2026-10-30 | The Hacker News | [Hackers Actively Exploit Highly Critical Drupal Commerce Core Authorization Bypass Flaw](https://thehackernews.com/2026/10/hackers-actively-exploit-highly.html) | explotada, crítica |
| 2026-10-30 | The Hacker News | [CISA Adds Actively Exploited GitLab RCE and Cisco Firewall DoS Flaws to KEV](https://thehackernews.com/2026/10/cisa-adds-actively-exploited-gitlab-rce.html) | explotada |
| 2026-10-30 | Siemens ProductCERT | [SSA-566435 V1.4 (Last Update: 2026-10-30): PHP2Shell Vulnerabilities in Siemens Software Products](https://cert-portal.siemens.com/productcert/html/ssa-566435.html) | explotada |
| 2026-10-30 | Siemens ProductCERT | [SSA-045512 V1.0: Node2Shell Vulnerabilities in Siemens Products](https://cert-portal.siemens.com/productcert/html/ssa-045512.html) | explotada |
| 2026-10-30 | Siemens ProductCERT | [SSA-898633 V1.0: Node2Shell Vulnerability in Palo Alto Networks PAN-OS on RUGGEDCOM APE1808 Devices](https://cert-portal.siemens.com/productcert/html/ssa-898633.html) | explotada |
| 2026-10-30 | Siemens ProductCERT | [SSA-443410 V1.0: Node2Shell Vulnerability in Industrial Edge Management Applications](https://cert-portal.siemens.com/productcert/html/ssa-443410.html) | explotada |
| 2026-10-29 | Palo Alto Networks | [CVE-2026-109618 Impact of Critical Vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619) on Palo Alto Netw](https://security.paloaltonetworks.com/CVE-2026-109618) | explotada, crítica |
| 2026-10-29 | Wordfence (WordPress) | [WordPress 7.1.4 Patches Unauthenticated Upgrade-Window RCE; Exploitation Attempts Detected After Release](https://www.wordfence.com/blog/2026/10/wordpress-7-1-4-security-release-rce/) | explotada, sin parche |

### Vulnerabilidades de los últimos 7 días

**3413** CVE publicados · **1** ya explotados · **34** urgentes · **263** con CVSS ≥ 9 · **244** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **1** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-76418 | Cisco | 8.6 | 0.8 % | 2026-10-28 |
| urgente | CVE-2026-116485 | — | 9.8 | 2.3 % | 2026-10-26 |
| urgente | CVE-2026-93680 | Langflow | 9.8 | 2.2 % | 2026-10-29 |
| urgente | CVE-2026-120195 | Wavlink | 10.0 | 2.1 % | 2026-11-01 |
| urgente | CVE-2026-120198 | Wavlink | 10.0 | 2.1 % | 2026-11-01 |
| urgente | CVE-2026-116506 | TOTOLINK | 9.9 | 1.9 % | 2026-10-26 |
| urgente | CVE-2026-120196 | Wavlink | 9.9 | 1.7 % | 2026-11-01 |
| urgente | CVE-2026-120197 | Wavlink | 9.9 | 1.7 % | 2026-11-01 |
| urgente | CVE-2026-90868 | Windows | 9.9 | 1.5 % | 2026-10-29 |
| urgente | CVE-2026-97854 | — | 9.3 | 1.4 % | 2026-10-29 |
| urgente | CVE-2025-31704 | Dahua | 9.8 | 1.4 % | 2026-10-30 |
| urgente | CVE-2026-120189 | D-Link | 10.0 | 1.3 % | 2026-11-01 |
| urgente | CVE-2026-112352 | — | 9.1 | 1.3 % | 2026-10-27 |
| urgente | CVE-2026-104353 | Adobe | 9.9 | 1.3 % | 2026-10-27 |
| urgente | CVE-2026-110879 | — | 9.8 | 1.2 % | 2026-10-28 |
| urgente | CVE-2026-90865 | Windows | 9.0 | 1.1 % | 2026-10-29 |
| urgente | CVE-2026-82119 | — | 9.8 | 1.0 % | 2026-10-27 |
| urgente | CVE-2026-107092 | Nexopos | 9.8 | 1.0 % | 2026-10-26 |
| urgente | CVE-2026-119706 | — | 9.8 | 1.0 % | 2026-10-30 |
| urgente | CVE-2026-112346 | — | 9.8 | 1.0 % | 2026-10-26 |
| urgente | CVE-2026-78845 | — | 9.8 | 0.8 % | 2026-10-27 |
| urgente | CVE-2026-110799 | Código abierto (GitHub) | 9.8 | 0.7 % | 2026-10-30 |
| urgente | CVE-2026-31158 | — | 9.8 | 0.7 % | 2026-10-26 |
| urgente | CVE-2026-116508 | TOTOLINK | 9.3 | 0.6 % | 2026-10-26 |
| urgente | CVE-2026-63190 | Código abierto (GitHub) | 9.4 | 0.5 % | 2026-10-28 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 216 | 2 / 47 |
| Python (PyPI) | 🔴 paquetes maliciosos | 27 | 5 / 43 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 5 |
| .NET (C#) (NuGet) | 🟡 avisos altos | 0 | 0 / 1 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 12 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 1 / 13 |
| Rust (crates.io) | 🟠 avisos críticos | 0 | 2 / 4 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 1 | 0 / 1 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟠 avisos críticos | 0 | 1 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 909 | 70 | 2 |
| Software empresarial | 🔴 explotación activa | 100 | 16 | 4 |
| Windows y Microsoft | 🔴 explotación activa | 84 | 10 | 1 |
| Red, VPN y firewalls | 🔴 explotación activa | 30 | 6 | 9 |
| Linux | 🔴 explotación activa | 184 | 4 | 1 |
| Virtualización y nube | 🔴 explotación activa | 28 | 3 | 1 |
| Servidores y servicios | 🔴 explotación activa | 10 | 0 | 4 |
| Industrial (OT · ICS) | 🔴 explotación activa | 1 | 0 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Otros | 🔴 explotación activa | 1026 | 91 | 10 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 33 | 16 | 0 |
| Librerías de código abierto | 🟠 riesgo alto | 387 | 30 | 0 |
| Apple (macOS · iOS) | 🟠 riesgo alto | 335 | 1 | 0 |
| Navegadores | 🟠 riesgo alto | 254 | 16 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 25 | 0 | 0 |
| Android | 🟢 vigilar | 7 | 0 | 0 |
<!-- CTI:END -->
