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
**Última actualización:** 2026-11-03 05:08 UTC · **IOCs recolectados:** 2795 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | alta | `180[.]93[.]193[.]100:80` | ip:port | Mirai | ThreatFox | 2026-11-02 09:43:55 UTC |
| 72 (alta) | alta | `5[.]39[.]10[.]241:3778` | ip:port | Mirai | ThreatFox | 2026-11-02 08:24:25 UTC |
| 71 (alta) | alta | `217[.]60[.]195[.]98:8808` | ip:port | XWorm | ThreatFox | 2026-11-02 13:59:04 UTC |
| 70 (alta) | media | `c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3` | filehash-sha256 | VShell | ThreatFox | 2026-11-03 03:56:40 UTC |
| 68 (media) | media | `34[.]77[.]99[.]151` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-03 00:06:47 UTC |
| 68 (media) | media | `34[.]174[.]2[.]35` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-02 21:11:26 UTC |
| 68 (media) | media | `178[.]62[.]79[.]141:3129` | ip:port | XMRIG | ThreatFox | 2026-11-02 16:04:12 UTC |
| 67 (media) | media | `103[.]192[.]80[.]81:1088` | ip:port | XMRIG | ThreatFox | 2026-11-02 19:13:38 UTC |
| 65 (media) | alta | `b732b3c5371ebf687f15fcef52b7ea412c571d931ed8dae8556c44d434cc90cc` | filehash-sha256 | Mirai | ThreatFox | 2026-11-02 08:56:32 UTC |
| 64 (media) | alta | `ec52166d2ef0ba71df7efdac3a5106a0ab40b6388cf85e93b90e9688299fb7d9` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 04:30:09 UTC |
| 64 (media) | alta | `6e0d6099f51f8a9d88842f9ff4d29ed862007c10ffc6f9ae2557ed96577bd8eb` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 04:30:09 UTC |
| 64 (media) | media | `144[.]172[.]118[.]166:8085` | ip:port | Unknown malware | ThreatFox | 2026-11-02 06:28:59 UTC |
| 64 (media) | media | `e6400ea4ea364afbc1dd39f6836ddcab26b6653d2c22751aac847112874ad45b` | filehash-sha256 | WARDENStealer | ThreatFox | 2026-11-02 06:27:44 UTC |
| 62 (media) | alta | `c8ef25d664803cd43b5a877f059b699021215c1226383fb39279f37119434079` | filehash-sha256 | Remcos | ThreatFox | 2026-11-02 09:56:33 UTC |
| 61 (media) | alta | `fc36de78d6ab0afbf8241584965917d350cadbdcf5bf40a402c9b107706cefa6` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 04:30:09 UTC |
| 61 (media) | media | `a9859c49d20baf131d1e9253acb0118fac412acaa97938d87c7c8daa7554cd54` | filehash-sha256 | CECbot | ThreatFox | 2026-11-02 08:56:48 UTC |
| 61 (media) | alta | `10d73ec46db3c4dac279459dd6560c1c6ee456a0d2076d7c40b602b0e947a9bf` | filehash-sha256 | Mirai | ThreatFox | 2026-11-02 08:56:33 UTC |
| 60 (media) | critica | `168[.]144[.]40[.]127:443` | ip:port | AdaptixC2 | ThreatFox | 2026-11-02 22:05:04 UTC |
| 60 (media) | media | `176[.]65[.]139[.]50:1337` | ip:port | Unknown malware | ThreatFox | 2026-11-02 06:27:21 UTC |
| 59 (media) | alta | `3dd5b61bb1350d119d1fa35b6ad8388f2780dfc93e77eca64b9b541eaa74abd1` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 03:56:44 UTC |
| 59 (media) | alta | `85ab90e421d0383755510c23515a4837355af4f92d4efa09b7c3a6d771ea34af` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 03:56:41 UTC |
| 59 (media) | media | `089688db8500d0776501de520205209535bf0e5104d0a728f484dde75c1ed9c2` | filehash-sha256 | Jackskid | ThreatFox | 2026-11-02 08:56:48 UTC |
| 58 (media) | media | `cff8d39682d616d4e0846ec66e5c2a654016767d00290b18d31d4d0a52fcddd7` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-02 08:55:58 UTC |
| 57 (media) | alta | `7cdf57c7e6017583df56cb081f8e488f6fe45782e059a97515e049487c0e6f4f` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 03:56:43 UTC |
| 57 (media) | media | `38[.]55[.]252[.]139:8088` | ip:port | Unknown malware | ThreatFox | 2026-11-03 03:05:07 UTC |

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

**289** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **68** de algo que ya se explota · **9** de día cero · **30** sin parche

**Lo más citado:** CVE-2026-111497 (9 fuentes, KEV) · CVE-2026-109618 (7 fuentes, KEV) · CVE-2026-109619 (7 fuentes, KEV) · CVE-2026-76418 (5 fuentes, KEV) · CVE-2026-97229 (3 fuentes, KEV) · CVE-2026-111357 (3 fuentes, KEV) · CVE-2026-98432 (3 fuentes) · CVE-2026-105482 (2 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-02 | Cisco | [Vulnerabilities in Node.js Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-02 | Wordfence (WordPress) | [HTTP2Shell: What the Critical Brotli Vulnerability Means for WordPress Sites](https://www.wordfence.com/blog/2026/11/http2shell-wordpress-brotli/) | explotada, crítica |
| 2026-11-02 | BleepingComputer | [Over 1,000 GitLab servers vulnerable to ongoing RCE attacks](https://www.bleepingcomputer.com/news/security/over-1-000-gitlab-servers-vulnerable-to-code-execution-attacks/) | explotada, sin parche |
| 2026-11-02 | Segu-Info | [PHP2Shell, por qué un exploit no funciona en todas partes](http://blog.segu-info.com.ar/2026/11/php2shell-por-que-un-exploit-no.html) | explotada |
| 2026-11-02 | The Hacker News | [Critical Langflow Flaws Could Let Unauthenticated Attackers Run Code on Servers](https://thehackernews.com/2026/11/critical-langflow-flaws-could-let.html) | crítica |
| 2026-11-02 | BleepingComputer | [Ivanti patches two more Connect Secure zero-days chained in attacks](https://www.bleepingcomputer.com/news/security/ivanti-patches-two-more-connect-secure-zero-days-chained-in-attacks/) | explotada, día cero |
| 2026-11-02 | SecurityWeek | [Ivanti Patches Two More Zero-Days Exploited in Connect Secure Attack Chain](https://www.securityweek.com/ivanti-patches-two-more-zero-days-exploited-in-connect-secure-attack-chain/) | explotada, día cero |
| 2026-11-02 | CERT-FR · avisos | [Multiples vulnérabilités dans Ivanti Connect Secure (02 novembre 2026)](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1442/) | explotada |
| 2026-10-31 | Microsoft | [Chromium: CVE-2026-118305 Memory corruption in Turbolev](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118305) | crítica |
| 2026-10-31 | Microsoft | [Chromium: CVE-2026-118306 Memory corruption in FileSystem](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118306) | crítica |
| 2026-10-31 | Microsoft | [Chromium: CVE-2026-118340 Memory corruption in Skia](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118340) | crítica |
| 2026-10-31 | The Hacker News | [Attackers Chain Three Ivanti Connect Secure Flaws to Gain Unauthenticated Root Access](https://thehackernews.com/2026/10/attackers-chain-three-ivanti-connect.html) | explotada |
| 2026-10-31 | Palo Alto Networks | [CVE-2026-111497 Portfolio Status: Impact of Brotli Vulnerability (CVE-2026-111497) on Palo Alto Networks Produ](https://security.paloaltonetworks.com/CVE-2026-111497) | explotada, crítica |
| 2026-10-30 | BleepingComputer | [Critical Linux kernel flaw allows remote root attacks on MPTCP servers](https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/) | crítica |
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

### Vulnerabilidades de los últimos 7 días

**3121** CVE publicados · **1** ya explotados · **36** urgentes · **266** con CVSS ≥ 9 · **197** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **1** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-76418 | Cisco | 8.6 | 0.8 % | 2026-10-28 |
| urgente | CVE-2026-120229 | Wavlink | 9.1 | 2.8 % | 2026-11-01 |
| urgente | CVE-2026-120230 | Wavlink | 9.9 | 2.2 % | 2026-11-01 |
| urgente | CVE-2026-93680 | Langflow | 9.8 | 2.2 % | 2026-10-29 |
| urgente | CVE-2026-120195 | Wavlink | 10.0 | 2.1 % | 2026-11-01 |
| urgente | CVE-2026-120198 | Wavlink | 9.3 | 2.1 % | 2026-11-01 |
| urgente | CVE-2026-120196 | Wavlink | 9.9 | 1.7 % | 2026-11-01 |
| urgente | CVE-2026-120238 | Wavlink | 9.9 | 1.7 % | 2026-11-01 |
| urgente | CVE-2026-90868 | Windows | 9.9 | 1.5 % | 2026-10-29 |
| urgente | CVE-2026-97854 | — | 9.3 | 1.4 % | 2026-10-29 |
| urgente | CVE-2025-31704 | Dahua | 9.8 | 1.4 % | 2026-10-30 |
| urgente | CVE-2026-120189 | D-Link | 10.0 | 1.3 % | 2026-11-01 |
| urgente | CVE-2026-112352 | — | 9.1 | 1.3 % | 2026-10-27 |
| urgente | CVE-2026-104353 | Adobe | 9.9 | 1.3 % | 2026-10-27 |
| urgente | CVE-2026-110879 | — | 9.8 | 1.2 % | 2026-10-28 |
| urgente | CVE-2026-90865 | Windows | 9.0 | 1.1 % | 2026-10-29 |
| urgente | CVE-2026-82119 | — | 9.8 | 1.0 % | 2026-10-27 |
| urgente | CVE-2026-119706 | — | 9.8 | 1.0 % | 2026-10-30 |
| urgente | CVE-2026-78845 | — | 9.8 | 0.8 % | 2026-10-27 |
| urgente | CVE-2026-110799 | Código abierto (GitHub) | 9.8 | 0.7 % | 2026-10-30 |
| urgente | CVE-2026-116692 | Código abierto (GitHub) | 9.8 | 0.7 % | 2026-10-27 |
| urgente | CVE-2026-44179 | Código abierto (GitHub) | 9.9 | 0.7 % | 2026-10-28 |
| urgente | CVE-2026-63190 | Código abierto (GitHub) | 9.4 | 0.5 % | 2026-10-28 |
| urgente | CVE-2026-61567 | Código abierto (GitHub) | 10.0 | 0.5 % | 2026-10-28 |
| urgente | CVE-2026-107015 | — | 9.1 | 0.5 % | 2026-10-29 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 175 | 2 / 48 |
| Python (PyPI) | 🔴 paquetes maliciosos | 19 | 5 / 43 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 5 |
| .NET (C#) (NuGet) | 🟡 avisos altos | 0 | 0 / 1 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 12 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 1 / 13 |
| Rust (crates.io) | 🟠 avisos críticos | 0 | 2 / 4 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 3 | 0 / 1 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟠 avisos críticos | 0 | 1 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Software empresarial | 🔴 explotación activa | 111 | 17 | 4 |
| Windows y Microsoft | 🔴 explotación activa | 71 | 10 | 1 |
| Red, VPN y firewalls | 🔴 explotación activa | 34 | 6 | 9 |
| Aplicaciones web y CMS | 🔴 explotación activa | 856 | 76 | 2 |
| Linux | 🔴 explotación activa | 202 | 6 | 1 |
| Virtualización y nube | 🔴 explotación activa | 28 | 2 | 1 |
| Servidores y servicios | 🔴 explotación activa | 8 | 0 | 4 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Industrial (OT · ICS) | 🔴 explotación activa | 0 | 0 | 1 |
| Otros | 🔴 explotación activa | 996 | 87 | 8 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 36 | 17 | 0 |
| Librerías de código abierto | 🟠 riesgo alto | 344 | 27 | 0 |
| Navegadores | 🟠 riesgo alto | 256 | 16 | 0 |
| IA y agentes (LLM · MCP) | 🟠 riesgo alto | 23 | 1 | 0 |
| Apple (macOS · iOS) | 🟠 riesgo alto | 11 | 1 | 0 |
| Android | 🟢 vigilar | 145 | 0 | 0 |
<!-- CTI:END -->
