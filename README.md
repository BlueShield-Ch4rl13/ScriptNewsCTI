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
**Última actualización:** 2026-11-14 19:50 UTC · **IOCs recolectados:** 951 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `45[.]227[.]255[.]157:7443` | ip:port | Unknown malware | ThreatFox | 2026-11-14 07:05:06 UTC |
| 74 (alta) | media | `d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f` | filehash-sha256 | ValleyRAT | ThreatFox | 2026-11-14 02:58:39 UTC |
| 72 (alta) | media | `5ecf14994419b1f8b5d9a8d60623ce2cffa7f4b6ecec1751100d5b7a71302313` | filehash-sha256 | kkRAT | ThreatFox | 2026-11-14 18:13:31 UTC |
| 72 (alta) | media | `1fd6f65f7a6626dda9b7bd8c82c18ae22be95e1a` | filehash-sha1 | kkRAT | ThreatFox | 2026-11-14 18:13:31 UTC |
| 72 (alta) | media | `f01933e12039d516f14b61b6cc303a0c` | filehash-md5 | kkRAT | ThreatFox | 2026-11-14 18:13:31 UTC |
| 72 (alta) | media | `7c9baba95531d4c908f15c9befbde8a56a1114c2e006c969695ec0a0de7878e4` | filehash-sha256 | kkRAT | ThreatFox | 2026-11-14 18:13:30 UTC |
| 72 (alta) | media | `7cc466a1da22db8671a178a80a976626a12d9a27` | filehash-sha1 | kkRAT | ThreatFox | 2026-11-14 18:13:30 UTC |
| 72 (alta) | media | `a2b4e06181d15e3d5384d65cb6cf8793` | filehash-md5 | kkRAT | ThreatFox | 2026-11-14 18:13:30 UTC |
| 72 (alta) | alta | `196[.]251[.]121[.]237:777` | ip:port | DCRat | ThreatFox | 2026-11-13 19:44:06 UTC |
| 71 (alta) | media | `43[.]157[.]55[.]140:6666` | ip:port | ValleyRAT | ThreatFox | 2026-11-14 00:15:18 UTC |
| 69 (media) | alta | `b43866cec329650bff964813ff8cebb93b50a537434ff7fc561a542891f74e8d` | filehash-sha256 | Unknown Stealer | ThreatFox | 2026-11-14 18:58:44 UTC |
| 69 (media) | media | `c55f494f75b7c64c1fad204711a13960` | filehash-md5 | ZStealer | ThreatFox | 2026-11-14 18:13:09 UTC |
| 69 (media) | media | `aaa05c178844b47e2e9e80a61af679d576cae6eaad26ab7e589cb7da0cdea9a1` | filehash-sha256 | ZStealer | ThreatFox | 2026-11-14 18:13:08 UTC |
| 69 (media) | media | `8e5dadc3e663e6a9efbfc2f7a5272b39a4accdb4` | filehash-sha1 | ZStealer | ThreatFox | 2026-11-14 18:13:08 UTC |
| 68 (media) | media | `e309f32903408d9905c4865fada530331c0bca22` | filehash-sha1 | ZStealer | ThreatFox | 2026-11-14 18:13:13 UTC |
| 68 (media) | media | `99be07a212f36deae58e7b1515abb080` | filehash-md5 | ZStealer | ThreatFox | 2026-11-14 18:13:13 UTC |
| 68 (media) | media | `baed59715b1cd5c31f10172d38af9f8f7d6eae5b6cdf045c5212e05d06b093cd` | filehash-sha256 | ZStealer | ThreatFox | 2026-11-14 18:13:12 UTC |
| 68 (media) | media | `570dd04491a56ae3b0ae916cea6b89f73e1811d8` | filehash-sha1 | ZStealer | ThreatFox | 2026-11-14 18:13:10 UTC |
| 68 (media) | media | `a4c66dac353589c79de43e3df37f7c41` | filehash-md5 | ZStealer | ThreatFox | 2026-11-14 18:13:10 UTC |
| 68 (media) | media | `924224c6a919a869efee395f69dce99fe1a76d35bef71a49422a88e448a09ee4` | filehash-sha256 | ZStealer | ThreatFox | 2026-11-14 18:13:09 UTC |
| 68 (media) | media | `229de7f7340d45e74749978d25f99deb` | filehash-md5 | ZStealer | ThreatFox | 2026-11-14 18:13:07 UTC |
| 68 (media) | media | `1c741595f6392c2d6167648a9563e1650b0f001ecd2655aa7dac6557f0cd0895` | filehash-sha256 | ZStealer | ThreatFox | 2026-11-14 18:13:06 UTC |
| 68 (media) | media | `fcc829f4a247883d5310ab4b20e6d45082501ec8` | filehash-sha1 | ZStealer | ThreatFox | 2026-11-14 18:13:06 UTC |
| 68 (media) | media | `d79f8157bbe699679fee210fc9579a21ac781910` | filehash-sha1 | ZStealer | ThreatFox | 2026-11-14 18:13:01 UTC |
| 68 (media) | media | `76b2f4634f805a29604346adcef2a566` | filehash-md5 | ZStealer | ThreatFox | 2026-11-14 18:13:01 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-114713 | UnrealIRCd UnrealIRCd | 2026-11-13 | Unknown |
| CVE-2026-123039 | Check Point Multiple Products | 2026-11-13 | Unknown |
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

### Avisos de seguridad de los últimos 7 días

**464** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **57** de algo que ya se explota · **18** de día cero · **12** sin parche

**Lo más citado:** CVE-2026-111497 (6 fuentes, KEV) · CVE-2026-119618 (6 fuentes) · CVE-2026-124194 (4 fuentes, KEV) · CVE-2026-125350 (4 fuentes, KEV) · CVE-2026-20320 (4 fuentes, KEV) · CVE-2026-109618 (3 fuentes, KEV) · CVE-2026-109619 (3 fuentes, KEV) · CVE-2026-120868 (3 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-14 | The Hacker News | [Attackers Exploit UnrealIRCd Flaw That Enables Server-Level Command Injection](https://thehackernews.com/2026/11/attackers-exploit-unrealircd-flaw-that.html) | explotada |
| 2026-11-13 | Cisco | [Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20and%20Brotli%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-13 | Cisco | [Cisco BroadWorks Out-of-Band Blind XML External Entity Injection Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bworks-xxe-uwUd7CEt?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20BroadWorks%20Out-of-Band%20Blind%20XML%20External%20Entity%20Injection%20Vulnerability%26vs_k=1) | explotada |
| 2026-11-13 | CISA | [CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/13/cisa-adds-two-known-exploited-vulnerabilities-catalog) | explotada |
| 2026-11-13 | BleepingComputer | [Check Point warns of zero-day flaw exploited for root access](https://www.bleepingcomputer.com/news/security/check-point-patches-zero-day-that-lets-hackers-get-root-access/) | día cero |
| 2026-11-13 | INCIBE-CERT | [Múltiples vulnerabilidades en productos de Check Point](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-check-point-0) | explotada, sin parche |
| 2026-11-13 | SecurityWeek | [Citrix Patches 10 Critical NetScaler Vulnerabilities](https://www.securityweek.com/citrix-patches-10-critical-netscaler-vulnerabilities/) | crítica |
| 2026-11-13 | SecurityWeek | [Nightmare Eclipse Drops Windows Zero-Day Exploit ‘SignDrop’](https://www.securityweek.com/nightmare-eclipse-drops-windows-zero-day-exploit-signdrop/) | explotada, día cero |
| 2026-11-13 | The Hacker News | [Hackers Exploit PHP2Shell Flaws in Check Point Gateways to Deploy TSGA Backdoor and Wipe ESXi Files](https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html) | explotada, sin parche |
| 2026-11-13 | SecurityWeek | [PHP2Shell Exploited in Destructive Check Point Gateway Attacks](https://www.securityweek.com/php2shell-exploited-in-destructive-check-point-gateway-attacks/) | explotada |
| 2026-11-13 | SecurityWeek | [Hackers Exploit New N-central Zero-Day Hours After PoC Publication](https://www.securityweek.com/hackers-exploit-new-n-central-zero-day-hours-after-poc-publication/) | explotada, día cero |
| 2026-11-13 | The Hacker News | [Hackers Exploit N-central Flaws to Infect 21 Servers, Including 19 Running Hotfix 2](https://thehackernews.com/2026/11/hackers-exploit-n-central-flaws-to.html) | explotada |
| 2026-11-12 | BleepingComputer | [New N-able "4EverAble2Shell" zero-day exploited hours after PoC released](https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/) | explotada, día cero |
| 2026-11-12 | BleepingComputer | [Apache HTTP Server patches critical HTTP/2 remote code execution flaw](https://www.bleepingcomputer.com/news/security/apache-http-server-patches-critical-http-2-remote-code-execution-flaw/) | crítica |
| 2026-11-12 | CERT-EU | [2026-020: Critical Vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway](https://cert.europa.eu/publications/security-advisories/2026-020/) | crítica |
| 2026-11-12 | The Hacker News | [New SignDrop Zero-Day Exploit Turns Windows CLFS Security Feature Into SYSTEM Access](https://thehackernews.com/2026/11/new-signdrop-zero-day-exploit-turns.html) | explotada, día cero |
| 2026-11-12 | The Hacker News | [Critical Red Hat Quay Flaw Lets Attackers Read and Overwrite All Private Container Images in a Registry](https://thehackernews.com/2026/11/critical-red-hat-quay-flaw-lets.html) | crítica |
| 2026-11-12 | BleepingComputer | [New Windows SignDrop zero-day gives hackers SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/) | explotada, día cero |
| 2026-11-12 | Microsoft | [CVE-2026-111497 Google: CVE-2026-111497 Buffer overflow vulnerability in the Brotli decoder](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111497) | explotada |
| 2026-11-12 | SecurityWeek | [Apache Patches Critical HTTP Server RCE Found by Anthropic, Google](https://www.securityweek.com/apache-patches-critical-http-server-rce-found-by-anthropic-google/) | crítica |
| 2026-11-12 | Segu-Info | [Falla crítica en el módulo HTTP/2 de Apache (CVE-2026-119618) permite ejecución remota de código sin autentica](http://blog.segu-info.com.ar/2026/11/falla-critica-en-el-modulo-http2-de.html) | sin parche, crítica |
| 2026-11-12 | Wordfence (WordPress) | [PSA: Critical Apache HTTP/2 Vulnerability: What WordPress Site Owners Should Know](https://www.wordfence.com/blog/2026/11/cve-2026-119618-apache-http2/) | crítica |
| 2026-11-12 | CISA | [Siemens Desigo, Gridscale](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-02) | explotada |
| 2026-11-12 | CISA | [Siemens RUGGEDCOM APE1808](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-05) | explotada |
| 2026-11-12 | CISA | [Siemens RUGGEDCOM APE1808](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-04) | explotada |

### Vulnerabilidades de los últimos 7 días

**4782** CVE publicados · **4** ya explotados · **71** urgentes · **306** con CVSS ≥ 9 · **1075** paquetes maliciosos en los registros · **1** con exploit en Exploit-DB · **3** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-123039 | Check Point | 7.8 | 2.2 % | 2026-11-12 |
| explotada | CVE-2026-124194 | Microsoft | 6.5 | 1.6 % | 2026-11-10 |
| explotada | CVE-2026-125350 | Google | 8.8 | 1.0 % | 2026-11-10 |
| explotada | CVE-2026-114713 | UnrealIRCd | 8.6 | 0.5 % | 2026-11-08 |
| urgente | CVE-2026-75869 | — | 8.8 | 20.4 % | 2026-11-12 |
| urgente | CVE-2026-12507 | — | 9.1 | 9.4 % | 2026-11-12 |
| urgente | CVE-2026-124002 | — | 9.3 | 3.2 % | 2026-11-12 |
| urgente | CVE-2026-124010 | — | 9.3 | 3.1 % | 2026-11-12 |
| urgente | CVE-2026-124580 | — | 9.3 | 2.8 % | 2026-11-09 |
| urgente | CVE-2026-126148 | Fortinet | 9.8 | 2.4 % | 2026-11-11 |
| urgente | CVE-2026-123270 | — | 9.8 | 2.4 % | 2026-11-09 |
| urgente | CVE-2026-19422 | Windows | 9.1 | 2.2 % | 2026-11-12 |
| urgente | CVE-2026-124007 | — | 9.2 | 2.1 % | 2026-11-12 |
| urgente | CVE-2026-121653 | Ivanti | 9.8 | 2.0 % | 2026-11-10 |
| urgente | CVE-2026-126187 | Código abierto (GitHub) | 9.5 | 1.8 % | 2026-11-10 |
| urgente | CVE-2026-12591 | — | 9.9 | 1.7 % | 2026-11-12 |
| urgente | CVE-2026-103813 | — | 9.1 | 1.4 % | 2026-11-13 |
| urgente | CVE-2026-119077 | WordPress (plugins) | 9.8 | 1.3 % | 2026-11-13 |
| urgente | CVE-2026-121349 | Adobe | 9.6 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-119958 | Microsoft | 9.8 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-113579 | Adobe | 9.9 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-113580 | Adobe | 9.9 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-121892 | Adobe | 9.9 | 1.2 % | 2026-11-10 |
| urgente | CVE-2026-126065 | Código abierto (GitHub) | 9.8 | 1.2 % | 2026-11-10 |
| urgente | CVE-2026-121887 | Adobe | 9.9 | 1.2 % | 2026-11-10 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 1000+ | 4 / 15 |
| Python (PyPI) | 🔴 paquetes maliciosos | 62 | 6 / 21 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 2 |
| .NET (C#) (NuGet) | 🟠 avisos críticos | 0 | 2 / 25 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 0 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 2 / 11 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 4 | 0 / 0 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 9 | 1 / 6 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Software empresarial | 🔴 explotación activa | 369 | 42 | 4 |
| Windows y Microsoft | 🔴 explotación activa | 1134 | 29 | 1 |
| Aplicaciones web y CMS | 🔴 explotación activa | 816 | 66 | 2 |
| Red, VPN y firewalls | 🔴 explotación activa | 179 | 34 | 10 |
| Virtualización y nube | 🔴 explotación activa | 31 | 5 | 1 |
| Navegadores | 🔴 explotación activa | 199 | 15 | 1 |
| Linux | 🔴 explotación activa | 110 | 5 | 1 |
| Servidores y servicios | 🔴 explotación activa | 126 | 0 | 5 |
| Apple (macOS · iOS) | 🔴 explotación activa | 13 | 1 | 1 |
| Industrial (OT · ICS) | 🔴 explotación activa | 6 | 1 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Otros | 🔴 explotación activa | 1456 | 88 | 7 |
| Librerías de código abierto | 🟠 riesgo alto | 299 | 15 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 28 | 5 | 0 |
| Android | 🟢 vigilar | 10 | 0 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 6 | 0 | 0 |
<!-- CTI:END -->
