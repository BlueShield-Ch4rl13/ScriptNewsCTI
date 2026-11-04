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
**Última actualización:** 2026-11-04 19:24 UTC · **IOCs recolectados:** 1588 · **CVEs KEV recientes:** 13

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 71 (alta) | media | `141[.]98[.]10[.]86:80` | ip:port | Unknown malware | ThreatFox | 2026-11-04 07:25:09 UTC |
| 70 (alta) | media | `b76c4ae848e95322207563381a4cc40a1804b75df32b68971b84a04ef53a0614` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-04 18:57:26 UTC |
| 69 (media) | media | `f5275a2ef863386b0d7ce9d95a2bec1dd85891379094d32259cc528db49a2687` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-04 18:57:26 UTC |
| 68 (media) | media | `34[.]156[.]56[.]208` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-04 14:46:54 UTC |
| 67 (media) | media | `5865fb8b29d8c03175897e123910f5a1082b4b7d12dc9e455af0d88ccef83127` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-04 07:25:16 UTC |
| 67 (media) | alta | `e1b5e175d4ffef096a2e6ae28cbc80983afb09dde44446297ac78290c46b5a59` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-04 00:56:54 UTC |
| 67 (media) | media | `7c80253e43ad1808c820e408205816d29fcfdf0af68f15c89e8ca2a9847ce73f` | filehash-sha256 | Floxif | ThreatFox | 2026-11-04 00:56:49 UTC |
| 66 (media) | alta | `4be99a11476bddcad97559a7638b9be55493818c361eda83de42730d00084bdc` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 09:56:58 UTC |
| 66 (media) | alta | `59f6039ac5293d05c26444bf3e4ebe4cae73dc94da9ef29d7ea163f0aa125749` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 09:56:57 UTC |
| 66 (media) | alta | `5d61a76fc29ab6c0bd0dbe06a3cb084939e48af2f20af131df7fdec0b93dab98` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 09:56:55 UTC |
| 66 (media) | media | `ff5a20d1976646be3fbedc058bef40d95161dcdd7cc197c23b25bf82d5079706` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-04 07:25:16 UTC |
| 63 (media) | alta | `f5b02b77825a8fa5503940639e8e28822cfd390954c61a6152c12ca6fc39057f` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 00:56:53 UTC |
| 63 (media) | alta | `60c3986439f423123eeb6e04e04dac447883863fe79dd8b664283cc4d20ec96d` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 23:56:50 UTC |
| 63 (media) | alta | `8623a88ed250f5d1a515698a514326e7be5bc89dd66bef4e9a424eb0f1f492c3` | filehash-sha256 | Mirai | ThreatFox | 2026-11-03 19:56:47 UTC |
| 62 (media) | alta | `75cd53e5ff76cffea431a9f640c156c6d2c8617c692c5445ee6b7a8486069d0b` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 09:57:01 UTC |
| 62 (media) | alta | `59ae87b9ddbb7d557e075d089f10b7710c8bd4cafc946b425d41e1171a27ae42` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 00:56:50 UTC |
| 61 (media) | media | `172[.]233[.]14[.]200:443` | ip:port | Jackskid | ThreatFox | 2026-11-04 11:52:25 UTC |
| 61 (media) | alta | `193[.]187[.]91[.]224:50810` | ip:port | Remcos | ThreatFox | 2026-11-04 09:05:11 UTC |
| 61 (media) | media | `35[.]185[.]157[.]183` | ipv4 | php.shin_webshell | ThreatFox | 2026-11-03 20:03:31 UTC |
| 60 (media) | alta | `31[.]57[.]216[.]6:8848` | ip:port | DCRat | ThreatFox | 2026-11-04 09:44:56 UTC |
| 59 (media) | media | `docsign[.]blog` | domain | IClickFix | ThreatFox | 2026-11-04 19:06:51 UTC |
| 59 (media) | alta | `bbabf5a7acfcf3fcf66f8ad80adc43b19f51492620bf67f9dbe0c8f7fa244591` | filehash-sha256 | Mirai | ThreatFox | 2026-11-04 09:57:00 UTC |
| 59 (media) | media | `168[.]144[.]176[.]164:443` | ip:port | Jackskid | ThreatFox | 2026-11-04 02:52:50 UTC |
| 59 (media) | media | `2ffcecf20d5601ccbed1d74da694d41673d06b759681e3d9585faa241f5bb7f9` | filehash-sha256 | Rugmi | ThreatFox | 2026-11-04 00:56:51 UTC |
| 59 (media) | media | `26539975049a135b6d47537264556da7a0d2c5a73bb7402acf3922c23381ebcc` | filehash-sha256 | AMOS | ThreatFox | 2026-11-04 00:31:46 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-119977 | WordPress WordPress Core | 2026-11-03 | Unknown |
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

### Avisos de seguridad de los últimos 7 días

**315** avisos de 25/26 fuentes (fabricantes, CERT, exploits y noticias) · **73** de algo que ya se explota · **6** de día cero · **17** sin parche

**Lo más citado:** CVE-2026-111497 (7 fuentes, KEV) · CVE-2026-109618 (5 fuentes, KEV) · CVE-2026-109619 (5 fuentes, KEV) · CVE-2026-98432 (4 fuentes) · CVE-2026-76418 (4 fuentes, KEV) · CVE-2026-119977 (4 fuentes, KEV) · CVE-2026-97229 (3 fuentes, KEV) · CVE-2026-111357 (3 fuentes, KEV)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-04 | Cisco | [Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20and%20Brotli%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-04 | The Hacker News | [SonicWall Won't Patch EoL GMS Flaws That Could Expose Files, Alter Database Records](https://thehackernews.com/2026/11/sonicwall-wont-patch-eol-gms-flaws-that.html) | crítica |
| 2026-11-04 | The Hacker News | [APT29-Linked Hackers Hijack Web Analytics Script to Deliver iOS and Android Exploits](https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html) | explotada |
| 2026-11-04 | Segu-Info | [Vulnerabilidad crítica en WordPress explotada activamente (CVE-2026-119977)](http://blog.segu-info.com.ar/2026/11/vulnerabilidad-critica-en-wordpress.html) | explotada, crítica |
| 2026-11-04 | BleepingComputer | [CISA flags WordPress RCE flaw as actively exploited in attacks](https://www.bleepingcomputer.com/news/security/cisa-flags-wordpress-rce-flaw-as-actively-exploited-in-attacks/) | explotada |
| 2026-11-04 | The Hacker News | [Critical Rails Flaw Lets Attackers Write Server Files via Crafted ImageMagick Uploads](https://thehackernews.com/2026/11/critical-rails-flaw-lets-attackers.html) | crítica |
| 2026-11-04 | The Hacker News | [China-Aligned Hackers Hijack Sogou Input Method DNS Requests to Deploy DarkVigil Backdoor](https://thehackernews.com/2026/11/china-aligned-hackers-hijack-sogou.html) | explotada |
| 2026-11-04 | SecurityWeek | [Chrome 157 Rolls Out With 213 Security Fixes, Seven Rated Critical](https://www.securityweek.com/chrome-157-rolls-out-with-213-security-fixes-seven-rated-critical/) | crítica |
| 2026-11-04 | INCIBE-CERT | [Escritura fuera de límites en productos de Citrix](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/escritura-fuera-de-limites-en-productos-de-citrix) | explotada |
| 2026-11-04 | INCIBE-CERT | [Múltiples vulnerabilidades en GMS de SonicWall](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-gms-de-sonicwall) | sin parche, crítica |
| 2026-11-04 | INCIBE-CERT | [Múltiples vulnerabilidades en Dameware de SolarWinds](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-dameware-de-solarwinds) | explotada, crítica |
| 2026-11-04 | INCIBE-CERT | [Múltiples vulnerabilidades en Fabric Composer de HPE](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-fabric-composer-de-hpe) | crítica |
| 2026-11-04 | The Hacker News | [Google Issues Patches for Critical Android Flaw That Could Allow RCE Without User Interaction](https://thehackernews.com/2026/11/google-patches-critical-android-flaw.html) | crítica |
| 2026-11-04 | The Hacker News | [CISA Confirms Hackers Exploiting WordPress Core Flaw During Software Upgrades](https://thehackernews.com/2026/11/cisa-confirms-hackers-exploiting.html) | explotada |
| 2026-11-04 | Siemens ProductCERT | [SSA-566512 V1.2 (Last Update: 2026-11-04): PHP2Shell Vulnerabilities in Palo Alto Networks PAN-OS on RUGGEDCOM](https://cert-portal.siemens.com/productcert/html/ssa-566512.html) | explotada |
| 2026-11-04 | Siemens ProductCERT | [SSA-566435 V1.6 (Last Update: 2026-11-04): PHP2Shell Vulnerabilities in Siemens Software Products](https://cert-portal.siemens.com/productcert/html/ssa-566435.html) | explotada |
| 2026-11-04 | Siemens ProductCERT | [SSA-045512 V1.1 (Last Update: 2026-11-04): Node2Shell Vulnerability in Siemens Products](https://cert-portal.siemens.com/productcert/html/ssa-045512.html) | explotada |
| 2026-11-03 | BleepingComputer | [Hackers hijack cPGuard autoupdate to deploy backdoor, steal data](https://www.bleepingcomputer.com/news/security/hackers-hijack-cpguard-autoupdate-to-deploy-backdoor-steal-data/) | explotada |
| 2026-11-03 | Google Chrome | [Stable Channel Update for Desktop](http://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop.html) | crítica |
| 2026-11-03 | Google Chrome | [Extended Stable Update for Desktop](http://chromereleases.googleblog.com/2026/11/extended-stable-update-for-desktop.html) | crítica |
| 2026-11-03 | Ubuntu | [USN-8987-1: libuser vulnerabilities](https://ubuntu.com/security/notices/USN-8987-1) | explotada |
| 2026-11-03 | Cisco | [Cisco Secure Email Gateway SQL Injection Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Email%20Gateway%20SQL%20Injection%20Vulnerability%26vs_k=1) | explotada |
| 2026-11-03 | The Hacker News | [Barracuda Flaws Could Be Chained to Bypass Authorization and Gain Root Access](https://thehackernews.com/2026/11/barracuda-flaws-could-be-chained-to.html) | crítica |
| 2026-11-03 | BleepingComputer | [Barracuda warns of critical flaws allowing root access to devices](https://www.bleepingcomputer.com/news/security/barracuda-warns-of-critical-flaws-allowing-root-access-to-devices/) | crítica |
| 2026-11-03 | SecurityWeek | [Critical Node-RED Flaw Exploited in Attacks](https://www.securityweek.com/critical-node-red-flaw-exploited-in-attacks/) | explotada, crítica |

### Vulnerabilidades de los últimos 7 días

**2968** CVE publicados · **3** ya explotados · **58** urgentes · **273** con CVSS ≥ 9 · **338** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **2** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-119977 | WordPress | 8.1 | 1.0 % | 2026-10-31 |
| explotada | CVE-2026-118527 | Ivanti | 4.3 | 0.8 % | 2026-11-03 |
| explotada | CVE-2026-76418 | Cisco | 8.6 | 0.8 % | 2026-10-28 |
| urgente | CVE-2026-77690 | — | 8.8 | 15.6 % | 2026-11-04 |
| urgente | CVE-2026-120276 | Wavlink | 10.0 | 3.2 % | 2026-11-02 |
| urgente | CVE-2026-120229 | Wavlink | 9.1 | 2.8 % | 2026-11-01 |
| urgente | CVE-2026-120277 | Wavlink | 10.0 | 2.5 % | 2026-11-02 |
| urgente | CVE-2026-120230 | Wavlink | 9.9 | 2.2 % | 2026-11-01 |
| urgente | CVE-2026-93680 | Langflow | 9.8 | 2.2 % | 2026-10-29 |
| urgente | CVE-2026-120195 | Wavlink | 10.0 | 2.1 % | 2026-11-01 |
| urgente | CVE-2026-120198 | Wavlink | 9.3 | 2.1 % | 2026-11-01 |
| urgente | CVE-2026-120280 | Wavlink | 10.0 | 2.0 % | 2026-11-02 |
| urgente | CVE-2026-120345 | Wavlink | 10.0 | 2.0 % | 2026-11-02 |
| urgente | CVE-2026-121607 | — | 10.0 | 2.0 % | 2026-11-04 |
| urgente | CVE-2026-120279 | Wavlink | 9.3 | 2.0 % | 2026-11-02 |
| urgente | CVE-2026-120344 | Wavlink | 9.3 | 2.0 % | 2026-11-02 |
| urgente | CVE-2026-120196 | Wavlink | 9.9 | 1.7 % | 2026-11-01 |
| urgente | CVE-2026-120238 | Wavlink | 9.9 | 1.7 % | 2026-11-01 |
| urgente | CVE-2026-28336 | SolarWinds | 9.9 | 1.6 % | 2026-11-03 |
| urgente | CVE-2026-90868 | Windows | 9.9 | 1.5 % | 2026-10-29 |
| urgente | CVE-2026-86596 | WordPress (plugins) | 9.8 | 1.5 % | 2026-11-02 |
| urgente | CVE-2026-97854 | — | 9.3 | 1.4 % | 2026-10-29 |
| urgente | CVE-2025-31704 | Dahua | 9.8 | 1.4 % | 2026-10-30 |
| urgente | CVE-2026-120189 | D-Link | 10.0 | 1.3 % | 2026-11-01 |
| urgente | CVE-2026-90865 | Windows | 9.0 | 1.1 % | 2026-10-29 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 307 | 3 / 39 |
| Python (PyPI) | 🔴 paquetes maliciosos | 25 | 1 / 22 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 3 |
| .NET (C#) (NuGet) | 🟡 avisos altos | 0 | 0 / 2 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 5 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 1 / 8 |
| Rust (crates.io) | 🟠 avisos críticos | 0 | 2 / 4 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 6 | 0 / 1 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟠 avisos críticos | 0 | 1 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 825 | 65 | 3 |
| Software empresarial | 🔴 explotación activa | 103 | 9 | 4 |
| Windows y Microsoft | 🔴 explotación activa | 44 | 11 | 1 |
| Red, VPN y firewalls | 🔴 explotación activa | 17 | 6 | 8 |
| Linux | 🔴 explotación activa | 110 | 4 | 1 |
| Virtualización y nube | 🔴 explotación activa | 29 | 3 | 1 |
| Servidores y servicios | 🔴 explotación activa | 10 | 0 | 4 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Industrial (OT · ICS) | 🔴 explotación activa | 0 | 0 | 1 |
| Otros | 🔴 explotación activa | 1080 | 84 | 8 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 41 | 25 | 0 |
| Librerías de código abierto | 🟠 riesgo alto | 295 | 30 | 0 |
| Navegadores | 🟠 riesgo alto | 254 | 31 | 0 |
| Android | 🟠 riesgo alto | 143 | 3 | 0 |
| IA y agentes (LLM · MCP) | 🟠 riesgo alto | 9 | 1 | 0 |
| Apple (macOS · iOS) | 🟠 riesgo alto | 8 | 1 | 0 |
<!-- CTI:END -->
