# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Plataforma ligera de **Cyber Threat Intelligence** que se actualiza sola cada 3 horas mediante GitHub Actions. Responde a cuatro preguntas:

- **¿Qué fallos de seguridad están saliendo?** Los avisos de los últimos 7 días de **26 fuentes**: fabricantes (Microsoft, Cisco, Fortinet, Palo Alto, Ivanti, Chrome, Siemens…), CERT y gobiernos (**INCIBE-CERT**, CISA, CERT-EU, CERT-FR, CERT/CC), exploits e investigación (Zero Day Initiative, Exploit-DB, Project Zero, Wordfence) y noticias de vulnerabilidades (Una al Día, Segu-Info, The Hacker News…). Cada aviso se cruza con CISA KEV y EPSS y se marca si ya se explota, si es de día cero o si sale sin parche.
- **¿Qué CVE nuevos importan?** Los de la última semana (NVD), ordenados por **explotación real** y no solo por CVSS: primero lo que ya se explota (CISA KEV, SSVC de CISA), después lo que más probablemente se explotará (FIRST EPSS, o un exploit publicado en Exploit-DB) y por último la gravedad. Cada CVE dice si tiene exploit público, si lo usa el ransomware, si se explotó desde el primer día y qué avisos lo citan.
- **¿Está en riesgo mi sistema?** Por tipo de sistema (Windows, Linux, Apple, Android, navegadores, red y VPN, routers e IoT, virtualización y nube, IA y agentes, industrial…): CVE nuevos, críticos y explotación activa en los últimos 30 días.
- **¿Está comprometido mi lenguaje?** Por lenguaje (JavaScript, Python, Java, .NET, PHP, Go, Rust, Ruby…): si **el propio lenguaje** (intérprete o runtime) tiene CVE explotados, y cuántos **paquetes maliciosos** y avisos graves han aparecido en su registro (npm, PyPI, Maven…).

Además recolecta IOCs de feeds públicos, los **fusiona entre fuentes**, los enriquece (GeoIP, VirusTotal, AbuseIPDB) y calcula un **score de confianza** y una **gravedad** por indicador. Todo se publica en un dashboard estático, en este README y en `data/` (JSON + CSV), y sale también hacia otras herramientas: **feed Atom** de los avisos importantes, **feed de MISP** con los IOCs, **alertas** a un webhook (n8n → Telegram) y un **histórico diario** con gráficas de tendencia. En el panel, un **buscador** mira a la vez en avisos, CVE e IOCs (con veredicto «sí aparece / no aparece» para un CVE, IP, dominio o hash concreto), cuatro **gráficas** resumen la semana, y cada visitante puede guardar su **lista de vigilancia** (productos y fabricantes) y ver qué avisos y CVE de la semana la citan.

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

## Feeds, alertas y lista de vigilancia

`exportar.py` se ejecuta al final de cada actualización; si falla, lo demás se publica igual.

| Salida | Dónde | Para qué |
|---|---|---|
| Feed Atom | `https://cti.carlosvillalbalagos.com/data/avisos.xml` | Los avisos que ya se explotan, de día cero o críticos (60 como máximo), para un lector de feeds, Outlook, Teams o n8n |
| Feed de MISP | `https://cti.carlosvillalbalagos.com/data/misp` | Los IOCs en formato «MISP Feed»: `manifest.json`, un evento por día y `hashes.csv`. El evento del día suma los IOCs de cada ejecución sin repetir; los de más de 7 días se retiran. `ip:port` → `ip-dst\|port`; los hashes → `md5`/`sha1`/`sha256`; `to_ids` si el score es ≥ 50 |
| Histórico | `data/historico.json` | Una fila por día (la última ejecución del día) con IOCs, KEV, CVE y avisos: las gráficas de «Tendencia». Arranca con 109 días sacados del historial de git |
| Alertas | El webhook de `N8N_WEBHOOK_URL` | Los avisos **nuevos en esta ejecución** que ya se explotan, son de día cero o citan algo de `CTI_VIGILAR`. La primera ejecución no avisa de nada (mandaría la semana entera) |

**Añadir el feed a MISP:** *Sync Actions → Feeds → Add Feed*, con URL `https://cti.carlosvillalbalagos.com/data/misp`, *Source Format* «MISP Feed» e *Input Source* «Network». Después, *Fetch and store all feed data*.

**Alertas a Telegram con n8n:**
1. En n8n, un flujo con un nodo **Webhook** (POST, autenticación por cabecera `Authorization: Bearer <token>`) y un nodo **Telegram** que envía `{{$json.body.texto}}` a tu chat. El cuerpo trae también `novedades` (título, enlace, fuente, CVE, KEV, señales, EPSS) por si quieres darle otro formato.
2. En el repo, *Settings → Secrets and variables → Actions*: los secretos `N8N_WEBHOOK_URL` (la URL de producción del webhook, `https://…`) y `N8N_WEBHOOK_TOKEN`; y, en la pestaña *Variables*, `CTI_VIGILAR` con lo que quieras vigilar separado por comas (`Fortinet, Splunk, Wazuh`).
3. Sin `N8N_WEBHOOK_URL` no se envía nada. La URL nunca se escribe en el log.

**Buscador del panel:** escribe un CVE, un producto, un fabricante, una IP, un dominio o un hash (también defangueado: `evil[.]com`, `hxxp://…`) y busca a la vez en avisos, CVE de la semana, IOCs, sistemas y lenguajes, sin tildes ni mayúsculas y con todas las palabras en cualquier orden. Con un identificador concreto da un veredicto: si es un IOC, de qué amenaza, qué fuente y con qué confianza. `/` o `Ctrl+K` lo abren desde cualquier sitio, las flechas y `Enter` llevan a la fila en su tabla y la búsqueda queda en la URL (`#q=fortinet`) para compartirla. Usa los datos que la página ya ha descargado: no pide nada más.

**Lista de vigilancia en el panel:** cada visitante añade sus productos o fabricantes y el panel marca, cuenta y filtra los avisos y CVE de la semana que los citan (por palabra completa: «SAP» no casa con «sapphire»). Se guarda solo en su navegador (`localStorage`); no sale de ahí.

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
   - `NVD_API_KEY` (opcional, gratis en nvd.nist.gov: NVD tarda segundos en vez de minutos)
   - `N8N_WEBHOOK_URL` y `N8N_WEBHOOK_TOKEN` (opcionales: alertas, ver arriba)
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
├── .github/workflows/pruebas.yml      # ruff + pytest en cada PR y push de código
├── .github/workflows/codeql.yml       # análisis de seguridad (Python, JS, Actions), semanal y en cada PR
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── enrich.py                          # fusión, estado histórico, GeoIP, reputación, score y gravedad
├── vulnerabilidades.py                # CVE de la semana: NVD, EPSS, KEV, GitHub Advisory, Exploit-DB, PoC-in-GitHub
├── avisos.py                          # avisos de fabricantes, CERT, exploits y noticias (26 feeds)
├── exportar.py                        # feed Atom, feed de MISP, histórico diario y alertas al webhook
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
├── tests/                             # fusión, gravedad, prioridad de CVE, feeds, señales, MISP y alertas
└── data/                              # iocs, vulns y avisos (_latest.json), CSV, avisos.xml, historico.json y misp/
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-11-12 05:32 UTC · **IOCs recolectados:** 1988 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `94[.]26[.]106[.]200:9506` | ip:port | Mirai | ThreatFox | 2026-11-11 21:40:03 UTC |
| 75 (alta) | media | `77[.]239[.]124[.]167:29444` | ip:port | Unknown malware | ThreatFox | 2026-11-11 13:49:35 UTC |
| 75 (alta) | alta | `5[.]178[.]101[.]94:18129` | ip:port | Mirai | ThreatFox | 2026-11-11 08:06:07 UTC |
| 75 (alta) | alta | `45[.]156[.]87[.]230:6666` | ip:port | Mirai | ThreatFox | 2026-11-11 08:06:06 UTC |
| 75 (alta) | alta | `181[.]215[.]115[.]186:60195` | ip:port | Mirai | ThreatFox | 2026-11-11 08:06:06 UTC |
| 75 (alta) | alta | `176[.]65[.]132[.]37:60195` | ip:port | Mirai | ThreatFox | 2026-11-11 08:06:05 UTC |
| 72 (alta) | alta | `77[.]239[.]124[.]15:1995` | ip:port | Mirai | ThreatFox | 2026-11-11 08:06:07 UTC |
| 71 (alta) | media | `202[.]170[.]75[.]111:56002` | ip:port | PureRAT | ThreatFox | 2026-11-11 19:44:09 UTC |
| 69 (media) | critica | `104[.]251[.]180[.]129:31337` | ip:port | Sliver | ThreatFox | 2026-11-12 05:12:53 UTC |
| 69 (media) | media | `34[.]62[.]246[.]24` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-11 12:04:18 UTC |
| 68 (media) | media | `34[.]62[.]11[.]175` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-11 20:50:29 UTC |
| 68 (media) | media | `34[.]79[.]37[.]102` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-11 19:42:42 UTC |
| 68 (media) | media | `35[.]187[.]35[.]191` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-11 17:37:56 UTC |
| 68 (media) | alta | `5d9e4bdee8c8fcb0b534f6336ecace4696d8ed3038de42a969c6e037e41d1de5` | filehash-sha256 | Mirai | ThreatFox | 2026-11-11 13:49:38 UTC |
| 68 (media) | media | `146[.]70[.]179[.]199:28471` | ip:port | PureRAT | ThreatFox | 2026-11-11 05:52:54 UTC |
| 68 (media) | media | `206[.]189[.]194[.]247:3333` | ip:port | Unknown malware | ThreatFox | 2026-11-11 05:52:12 UTC |
| 66 (media) | alta | `1175119ef24f85cdc0b16380f6571eeb160808698e3d7b16545ad622dc247e32` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 11:58:09 UTC |
| 65 (media) | alta | `fcf0a44fe8460fd3a744b0e2da531699c3566be614163868cb703cac2e35b5c0` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 12:58:14 UTC |
| 65 (media) | alta | `de42ffde032f59f18bc9d579128005767bde708ce24e44dba761dd44761232ed` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 11:58:13 UTC |
| 65 (media) | alta | `aef368d20ff8e9176ac8c13d5b204bded10ae0b77be7d50872c42f0da0529c1c` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 11:58:12 UTC |
| 65 (media) | alta | `80e636ef6b32c1bc8af8d530686bc225809a386d9771d9aafa488e638e154a02` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 11:58:10 UTC |
| 65 (media) | media | `67[.]207[.]86[.]184:3333` | ip:port | Unknown malware | ThreatFox | 2026-11-11 05:52:24 UTC |
| 64 (media) | alta | `f9e369c099fc30efd04f7d08621d7a63d4c9e846320047a0e6a67eacb5a92d82` | filehash-sha256 | Mirai | ThreatFox | 2026-11-11 13:49:40 UTC |
| 64 (media) | alta | `69922def78dad0c1816e45b700d375af75a458c431d55263ffdb1790668ccc05` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 12:58:17 UTC |
| 64 (media) | alta | `ac9f6c05de524a7e39602fa18a88db663790162aae943be5eac9decc1d9d067e` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-11 11:58:11 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-124194 | Microsoft Office | 2026-11-10 | Unknown |
| CVE-2026-111793 | Openwave Messaging Limited Webtop Media Transcoder | 2026-11-10 | Unknown |
| CVE-2026-20320 | Cisco BroadWorks | 2026-11-10 | Unknown |
| CVE-2026-111560 | Barracuda Networks Multiple Products | 2026-11-10 | Unknown |
| CVE-2026-116606 | Barracuda Networks Barracuda Email Security Gateway (ESG) | 2026-11-10 | Unknown |
| CVE-2026-125350 | Google Chromium | 2026-11-10 | Unknown |
| CVE-2026-102895 | GPUStack GPUStack | 2026-11-09 | Unknown |
| CVE-2026-123158 | OpenBSD OpenSSH | 2026-11-09 | Unknown |
| CVE-2026-116779 | SignalWire FreeSwitch | 2026-11-09 | Unknown |
| CVE-2026-123218 | IBM Aspera Faspex | 2026-11-09 | Unknown |
| CVE-2026-19868 | SonicWall SonicOS SSLVPN | 2026-11-06 | Unknown |
| CVE-2024-27834 | Apple Multiple Products | 2026-11-04 | Unknown |
| CVE-2026-119977 | WordPress WordPress Core | 2026-11-03 | Unknown |
| CVE-2026-118527 | Ivanti Connect Secure | 2026-10-30 | Unknown |
| CVE-2026-111357 | Ivanti Connect Secure | 2026-10-30 | Unknown |
| CVE-2026-97229 | GitLab Community Edition and Enterprise Edition | 2026-10-29 | Unknown |
| CVE-2026-76418 | Cisco Secure Firewall ASA Software and Cisco Secure FTD Software | 2026-10-29 | Unknown |

### Avisos de seguridad de los últimos 7 días

**406** avisos de 25/26 fuentes (fabricantes, CERT, exploits y noticias) · **49** de algo que ya se explota · **13** de día cero · **47** sin parche

**Lo más citado:** CVE-2026-111497 (4 fuentes, KEV) · CVE-2026-125350 (4 fuentes, KEV) · CVE-2026-123158 (4 fuentes, KEV) · CVE-2026-124194 (4 fuentes, KEV) · CVE-2026-19868 (4 fuentes, KEV) · CVE-2026-123218 (3 fuentes, KEV) · CVE-2026-20320 (3 fuentes, KEV) · CVE-2026-109467 (2 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-12 | The Hacker News | [Critical Apache HTTP/2 Flaw Could Let Unauthenticated Attackers Execute Code Remotely](https://thehackernews.com/2026/11/critical-apache-http2-flaw-could-let.html) | crítica |
| 2026-11-11 | Segu-Info | [Microsoft corrige 1.259 vulnerabilidades, incluida una falla en Outlook que ya está siendo explotada y que pod](http://blog.segu-info.com.ar/2026/11/microsoft-corrige-1259-vulnerabilidades.html) | explotada |
| 2026-11-11 | The Hacker News | [Critical Zoom Workplace Flaw Could Allow Unauthenticated Remote Privilege Escalation](https://thehackernews.com/2026/11/critical-zoom-workplace-flaw-could.html) | crítica |
| 2026-11-11 | SecurityWeek | [Critical Xen Orchestra Flaws Exploited in Attacks](https://www.securityweek.com/critical-xen-orchestra-flaws-exploited-in-attacks/) | explotada, crítica |
| 2026-11-11 | Segu-Info | [Fortinet2Shell: vulnerabilidad crítica en FortiClient permite ejecutar código](http://blog.segu-info.com.ar/2026/11/fortinet2shell-vulnerabilidad-critica.html) | crítica |
| 2026-11-11 | The Hacker News | [Hackers Target Qlik Sense Servers With Reverse Shells, Stage ActiveMQ and Veeam Exploits](https://thehackernews.com/2026/11/hackers-target-qlik-sense-servers-with.html) | explotada |
| 2026-11-11 | SecurityWeek | [Citrix, Ivanti Patch Critical and High-Severity Vulnerabilities](https://www.securityweek.com/citrix-ivanti-patch-critical-and-high-severity-vulnerabilities/) | crítica |
| 2026-11-11 | BleepingComputer | [N-able releases security hotfixes for zero-day vulnerabilities](https://www.bleepingcomputer.com/news/security/n-able-releases-security-hotfixes-for-zero-day-vulnerabilities/) | día cero |
| 2026-11-11 | BleepingComputer | [CISA flags Cisco BroadWorks flaw as actively exploited in attacks](https://www.bleepingcomputer.com/news/security/cisa-flags-cisco-broadworks-flaw-as-actively-exploited-in-attacks/) | explotada |
| 2026-11-11 | SecurityWeek | [Threat Actors Exploit Openwave, Cisco BroadWorks Vulnerabilities](https://www.securityweek.com/threat-actors-exploit-openwave-cisco-broadworks-vulnerabilities/) | explotada |
| 2026-11-11 | INCIBE-CERT | [Ejecución remota de código en Confluence Data Center de Atlassian](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/ejecucion-remota-de-codigo-en-confluence-data-center-de-atlassian) | crítica |
| 2026-11-11 | INCIBE-CERT | [Boletín de seguridad de SAP de noviembre de 2026](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/boletin-de-seguridad-de-sap-de-noviembre-de-2026) | crítica |
| 2026-11-11 | INCIBE-CERT | [Boletín de seguridad de Microsoft de noviembre de 2026](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/boletin-de-seguridad-de-microsoft-de-noviembre-de-2026) | explotada |
| 2026-11-11 | INCIBE-CERT | [Múltiples vulnerabilidades en N-central de N-able](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-n-central-de-n-able) | crítica |
| 2026-11-11 | INCIBE-CERT · industrial | [Boletín de seguridad de Siemens de noviembre de 2026](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/boletin-de-seguridad-de-siemens-de-noviembre-de-2026) | explotada |
| 2026-11-11 | SecurityWeek | [Recently Patched Barracuda Vulnerabilities Exploited in Attacks](https://www.securityweek.com/recently-patched-barracuda-vulnerabilities-exploited-in-attacks/) | explotada |
| 2026-11-11 | The Hacker News | [Cisco BroadWorks and Openwave Flaws Actively Exploited Despite Available Patches](https://thehackernews.com/2026/11/cisco-broadworks-and-openwave-flaws.html) | explotada |
| 2026-11-10 | Cisco | [Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20and%20Brotli%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-10 | BleepingComputer | [Hackers exploit trusted AWS access to breach multiple cloud environments](https://www.bleepingcomputer.com/news/security/hackers-exploit-trusted-aws-access-to-breach-multiple-cloud-environments/) | explotada |
| 2026-11-10 | SecurityWeek | [Exploited Outlook Zero-Day Among 1,094 Flaws Patched by Microsoft](https://www.securityweek.com/exploited-outlook-zero-day-among-1094-flaws-patched-by-microsoft/) | explotada, día cero |
| 2026-11-10 | BleepingComputer | [Microsoft November 2026 Patch Tuesday fixes 1,235 flaws, Outlook zero-day](https://www.bleepingcomputer.com/news/microsoft/microsoft-november-2026-patch-tuesday-fixes-1-235-flaws-outlook-zero-day/) | explotada, día cero |
| 2026-11-10 | The Hacker News | [Hackers Exploit Critical Xen Orchestra Auth Bypass Flaw to Gain Admin Access](https://thehackernews.com/2026/11/hackers-exploit-critical-xen-orchestra.html) | explotada, crítica |
| 2026-11-10 | BleepingComputer | [Critical Xen Orchestra auth bypass flaw exploited to hijack VM servers](https://www.bleepingcomputer.com/news/security/critical-xen-orchestra-auth-bypass-flaw-exploited-to-hijack-vm-servers/) | explotada, crítica |
| 2026-11-10 | The Hacker News | [Attackers Exploit AhsayCBS Flaws to Deploy Sandbox-Evading Python Backdoor](https://thehackernews.com/2026/11/attackers-exploit-ahsaycbs-flaws-to.html) | explotada |
| 2026-11-10 | Segu-Info | [SAP parchea cuatro fallas de CVSS 10.0, incluidas dos que permiten la ejecución remota de código](http://blog.segu-info.com.ar/2026/11/sap-parchea-cuatro-fallas-de-cvss-100.html) | crítica |

### Vulnerabilidades de los últimos 7 días

**4921** CVE publicados · **6** ya explotados · **28** urgentes · **323** con CVSS ≥ 9 · **542** paquetes maliciosos en los registros · **2** con exploit en Exploit-DB · **3** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-123158 | OpenBSD | 8.1 | 16.5 % | 2026-11-05 |
| explotada | CVE-2026-116779 | SignalWire | 9.8 | 2.2 % | 2026-11-05 |
| explotada | CVE-2026-123218 | IBM | 9.8 | 0.7 % | 2026-11-07 |
| explotada | CVE-2026-19868 | SonicWall | 7.5 | 0.5 % | 2026-11-06 |
| explotada | CVE-2026-125350 | Google | 8.8 | — | 2026-11-10 |
| explotada | CVE-2026-124194 | Microsoft | 6.5 | — | 2026-11-10 |
| urgente | CVE-2026-124580 | — | 10.0 | 2.8 % | 2026-11-09 |
| urgente | CVE-2026-118066 | WordPress (plugins) | 9.1 | 2.3 % | 2026-11-07 |
| urgente | CVE-2026-124585 | — | 9.9 | 2.2 % | 2026-11-09 |
| urgente | CVE-2026-124577 | — | 9.8 | 2.1 % | 2026-11-09 |
| urgente | CVE-2026-17402 | IBM | 9.9 | 1.9 % | 2026-11-07 |
| urgente | CVE-2026-122193 | — | 9.3 | 1.6 % | 2026-11-06 |
| urgente | CVE-2026-59105 | Microsoft | 9.3 | 1.4 % | 2026-11-06 |
| urgente | CVE-2026-114630 | WordPress (plugins) | 9.1 | 1.3 % | 2026-11-06 |
| urgente | CVE-2026-54143 | Código abierto (GitHub) | 9.8 | 1.2 % | 2026-11-05 |
| urgente | CVE-2026-83542 | Apache | 9.8 | 1.1 % | 2026-11-05 |
| urgente | CVE-2026-113363 | Windows | 9.3 | 1.1 % | 2026-11-09 |
| urgente | CVE-2026-116785 | Freeswitch | 9.1 | 1.0 % | 2026-11-05 |
| urgente | CVE-2026-123966 | Tenda | 9.3 | 1.0 % | 2026-11-07 |
| urgente | CVE-2026-123198 | — | 9.3 | 0.8 % | 2026-11-05 |
| urgente | CVE-2026-54141 | Código abierto (GitHub) | 9.0 | 0.8 % | 2026-11-05 |
| urgente | CVE-2026-68935 | Código abierto (GitHub) | 9.1 | 0.6 % | 2026-11-06 |
| urgente | CVE-2026-123807 | Código abierto (GitHub) | 9.8 | 0.5 % | 2026-11-09 |
| urgente | CVE-2026-48705 | Código abierto (GitHub) | 9.3 | 0.5 % | 2026-11-05 |
| urgente | CVE-2026-63438 | Código abierto (GitHub) | 9.8 | 0.5 % | 2026-11-06 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 499 | 4 / 14 |
| Python (PyPI) | 🔴 paquetes maliciosos | 36 | 5 / 8 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 2 |
| .NET (C#) (NuGet) | 🟡 avisos altos | 0 | 0 / 23 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 0 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 9 / 13 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 2 | 0 / 0 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 5 | 0 / 4 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Windows y Microsoft | 🔴 explotación activa | 1142 | 30 | 2 |
| Aplicaciones web y CMS | 🔴 explotación activa | 806 | 56 | 3 |
| Software empresarial | 🔴 explotación activa | 614 | 98 | 4 |
| Navegadores | 🔴 explotación activa | 199 | 8 | 1 |
| Red, VPN y firewalls | 🔴 explotación activa | 146 | 24 | 12 |
| Servidores y servicios | 🔴 explotación activa | 128 | 0 | 5 |
| Linux | 🔴 explotación activa | 140 | 6 | 1 |
| Virtualización y nube | 🔴 explotación activa | 26 | 4 | 1 |
| Apple (macOS · iOS) | 🔴 explotación activa | 13 | 1 | 1 |
| Industrial (OT · ICS) | 🔴 explotación activa | 6 | 1 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Otros | 🔴 explotación activa | 1250 | 52 | 7 |
| Librerías de código abierto | 🟠 riesgo alto | 397 | 38 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 28 | 4 | 0 |
| Android | 🟠 riesgo alto | 17 | 1 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 9 | 0 | 0 |
<!-- CTI:END -->
