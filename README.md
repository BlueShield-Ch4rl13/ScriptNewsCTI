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
**Última actualización:** 2026-11-23 23:25 UTC · **IOCs recolectados:** 5971 · **CVEs KEV recientes:** 23

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `77[.]239[.]124[.]181:9052` | ip:port | Unknown malware | ThreatFox | 2026-11-23 07:46:48 UTC |
| 75 (alta) | media | `194[.]147[.]58[.]39:7002` | ip:port | Unknown malware | ThreatFox | 2026-11-23 07:46:47 UTC |
| 71 (alta) | media | `142[.]86[.]119[.]86:443` | ip:port | Unknown malware | ThreatFox | 2026-11-23 20:14:12 UTC |
| 67 (media) | alta | `147[.]185[.]221[.]217:59000` | ip:port | XWorm | ThreatFox | 2026-11-23 06:45:25 UTC |
| 64 (media) | alta | `83733d52f442159d1fe89665fa8bffe54829902e5d352b613225ba00e3e2c828` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-23 11:00:38 UTC |
| 64 (media) | alta | `48[.]102[.]206[.]68:9931` | ip:port | Mirai | ThreatFox | 2026-11-23 07:46:49 UTC |
| 63 (media) | alta | `36e4651fdfe7656e8598c8d4c40f95b01062ae27d07e6fb0b37be93db5cb5c25` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-23 11:00:39 UTC |
| 63 (media) | alta | `4a5a96612e7316586a4c61a4d7dd28dfadf087be9ccfa2c04b06206cca610de7` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 11:00:22 UTC |
| 63 (media) | alta | `4ae22b6594b63a45a694f9d7e969c33395b5fab3cf3c411557d40338dfc671af` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 01:01:00 UTC |
| 63 (media) | media | `2981b646744db3a45fbebe6d9fba548ecf584997aa17856a1f66c0eceb2ca3db` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-23 01:00:33 UTC |
| 63 (media) | media | `e2f7b8efce5cd7b9ea16a6398e627bcd4394ea758346d63ba2706209d96a03dc` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-23 01:00:32 UTC |
| 63 (media) | alta | `5108f3faf10f7d8573c22464b1f46f4d2aeed95f9d4e78701f727a7db376cce2` | filehash-sha256 | Vidar | ThreatFox | 2026-11-23 01:00:31 UTC |
| 63 (media) | media | `e51979b91c53a6c03fdcc1d5b1fc43c96edf52b911b5987a5732ae87a5142c01` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-23 01:00:30 UTC |
| 63 (media) | media | `1132c348deebd0ce769c4b84a84c90a57252d7eb9c0860d1bb54d8cfb4487560` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-23 01:00:29 UTC |
| 62 (media) | alta | `11f5289599801ba00a82cc6a9e9c945266a48dad0eca55bf98206fa49e9a44fe` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-23 22:00:28 UTC |
| 62 (media) | media | `160[.]30[.]55[.]183:8787` | ip:port | Unknown malware | ThreatFox | 2026-11-23 20:13:44 UTC |
| 62 (media) | media | `38[.]242[.]156[.]206:31337` | ip:port | Unknown malware | ThreatFox | 2026-11-23 20:12:28 UTC |
| 62 (media) | alta | `46b13d2a8165aa30eada85f43c8b698f531c39e6a42dfb64316f0a2ec0198c3e` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 11:00:36 UTC |
| 62 (media) | alta | `178[.]95[.]255[.]21:1543` | ip:port | Mirai | ThreatFox | 2026-11-23 05:49:56 UTC |
| 62 (media) | alta | `d922912101f732cbe027d5a0fb8cb6a30d35ff86dccfbcfa9c7c1d9aa76adfc7` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 01:01:01 UTC |
| 62 (media) | alta | `f611607cac4a351cd3636bef2cf1dfa8b6af65527c2348271eb3c398ce801ed5` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 01:00:59 UTC |
| 62 (media) | media | `59fee70c5e84627486ca0df976f30fae5da07e7bcea92c0a0b7940174910899d` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-23 01:00:52 UTC |
| 62 (media) | alta | `5fc7177deae9f182f77237e2daec4ecc5d2266fce91215565240ed2d19cd7ddd` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 01:00:51 UTC |
| 62 (media) | alta | `3211e50ffde5e1401a01168219e965588248e9b71e09757c5c6b79c14adac73a` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 01:00:50 UTC |
| 62 (media) | alta | `2707eaf1d459d71ea9b233aa14af029bd69a9a1faf8b413d087ef66ad9ed9e0b` | filehash-sha256 | Mirai | ThreatFox | 2026-11-23 01:00:49 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-133968 | Project MONAI MONAI Label | 2026-11-23 | Unknown |
| CVE-2026-134624 | N-able MailAssure | 2026-11-23 | Unknown |
| CVE-2026-129448 | Apache Roller | 2026-11-20 | Unknown |
| CVE-2026-123890 | Broadcom VMware vCenter | 2026-11-20 | Unknown |
| CVE-2025-42884 | SAP NetWeaver | 2026-11-20 | Unknown |
| CVE-2026-76466 | Cisco Expressway Series | 2026-11-20 | Unknown |
| CVE-2024-10441 | Synology DiskStation Manager (DSM) | 2026-11-18 | Known |
| CVE-2026-40217 | BerriAI LiteLLM | 2026-11-18 | Unknown |
| CVE-2026-90817 | Vanderbilt University Research Electronic Data Capture (REDCap) | 2026-11-18 | Unknown |
| CVE-2026-90436 | Apache Axis | 2026-11-18 | Unknown |
| CVE-2026-115731 | Perforce Puppet Enterprise | 2026-11-17 | Unknown |
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

### Avisos de seguridad de los últimos 7 días

**401** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **43** de algo que ya se explota · **11** de día cero · **43** sin parche

**Lo más citado:** CVE-2026-114938 (11 fuentes) · CVE-2026-123007 (11 fuentes) · CVE-2026-123633 (9 fuentes) · CVE-2026-113425 (6 fuentes) · CVE-2026-121810 (6 fuentes) · CVE-2026-123634 (6 fuentes) · CVE-2026-111497 (5 fuentes, KEV) · CVE-2026-115560 (5 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-23 | Cisco | [Vulnerability in PHP Affecting Cisco Products: November 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phpaftershell-nov-2026-kT9pL4Xe?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerability%20in%20PHP%20Affecting%20Cisco%20Products:%20November%202026%26vs_k=1) | crítica |
| 2026-11-23 | Cisco | [Vulnerabilities in nginx Affecting Cisco Products: November 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nginx-nov-2026-e8jska2s?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20nginx%20Affecting%20Cisco%20Products:%20November%202026%26vs_k=1) | crítica |
| 2026-11-23 | Cisco | [Cisco Expressway Series Remote Code Execution Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vcs-static-cred-hr7EWZ8t?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Expressway%20Series%20Remote%20Code%20Execution%20Vulnerability%26vs_k=1) | explotada |
| 2026-11-23 | SecurityWeek | [N-able Patches Critical Flaw Disclosed After Mail Assure Cyberattack](https://www.securityweek.com/n-able-patches-critical-flaw-disclosed-after-mail-assure-cyberattack/) | crítica |
| 2026-11-23 | The Hacker News | [Critical binary-parser Flaw Enables JavaScript Injection via Malicious Parser Definitions](https://thehackernews.com/2026/11/critical-binary-parser-flaw-enables.html) | crítica |
| 2026-11-23 | The Hacker News | [Hackers Exploit Critical ScreenConnect Flaw to Hijack MSP Technician PCs Without Warning](https://thehackernews.com/2026/11/hackers-exploit-critical-screenconnect.html) | explotada, crítica |
| 2026-11-23 | The Hacker News | [N-able Discloses Critical Mail Assure Vulnerability Found During Breach Investigation](https://thehackernews.com/2026/11/n-able-discloses-critical-mail-assure.html) | explotada, crítica |
| 2026-11-23 | CISA | [CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/23/cisa-adds-two-known-exploited-vulnerabilities-catalog) | explotada, crítica |
| 2026-11-23 | SecurityWeek | [SAP NetWeaver, Cisco Expressway Flaws Exploited in Attacks](https://www.securityweek.com/sap-netweaver-cisco-expressway-flaws-exploited-in-attacks/) | explotada |
| 2026-11-23 | The Hacker News | [Hackers Exploit Critical ASP.NET Anti-CSRF Library Flaw Allowing Unauthenticated RCE](https://thehackernews.com/2026/11/hackers-exploit-critical-aspnet-anti.html) | explotada, crítica |
| 2026-11-23 | The Hacker News | [Hackers Exploited GL.iNet Cloud Flaw to Install Malware on Routers and KVM Devices](https://thehackernews.com/2026/11/hackers-exploited-glinet-cloud-flaw-to.html) | explotada |
| 2026-11-23 | INCIBE-CERT | [Múltiples vulnerabilidades en productos de Synology](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-synology-0) | crítica |
| 2026-11-23 | INCIBE-CERT | [Múltiples vulnerabilidades en productos de Cisco](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-cisco-20) | crítica |
| 2026-11-23 | INCIBE-CERT | [Múltiples vulnerabilidades en el núcleo de Linux](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-el-nucleo-de-linux) | crítica |
| 2026-11-23 | INCIBE-CERT | [Múltiples vulnerabilidades en productos de Palo Alto Networks](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-palo-alto-networks) | crítica |
| 2026-11-23 | INCIBE-CERT · industrial | [Uso de credenciales predeterminadas en controladores de refrigeración de Danfoss](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/uso-de-credenciales-predeterminadas-en-controladores-de-refrigeracion-de-danfoss) | crítica |
| 2026-11-23 | BleepingComputer | [CISA flags critical Cisco RCE flaw as actively exploited in attacks](https://www.bleepingcomputer.com/news/security/cisa-flags-critical-cisco-expressway-rce-flaw-as-actively-exploited/) | explotada, crítica |
| 2026-11-22 | BleepingComputer | [Hackers exploit GL.iNet cloud flaw to infect routers, KVM devices](https://www.bleepingcomputer.com/news/security/hackers-exploit-glinet-cloud-flaw-to-infect-routers-kvm-devices/) | explotada |
| 2026-11-22 | Segu-Info | [FastUnlock: Zero-Day en Bitlocker](http://blog.segu-info.com.ar/2026/11/fastunlock-zero-day-en-bitlocker.html) | día cero |
| 2026-11-21 | SecurityWeek | [Amazon: China-Linked Hackers’ AI Agents Exploited Medical Software Zero-Day](https://www.securityweek.com/amazon-china-linked-hackers-ai-agents-exploited-medical-software-zero-day/) | día cero |
| 2026-11-21 | The Hacker News | [GnuPG Warns Critical GPGME Flaw Could Expose App Data via Malicious OpenPGP Keys](https://thehackernews.com/2026/11/gnupg-warns-critical-gpgme-flaw-could.html) | crítica |
| 2026-11-21 | The Hacker News | [Attackers' AI Agents Found a Zero-Day in Medical-Imaging Software and Gained Root Access](https://thehackernews.com/2026/11/attackers-ai-agents-found-zero-day-in.html) | día cero |
| 2026-11-21 | The Hacker News | [Hackers Exploit Critical VMware, Cisco, and Apache Flaws as Espionage Attacks Emerge](https://thehackernews.com/2026/11/hackers-exploit-critical-vmware-cisco.html) | explotada, crítica |
| 2026-11-20 | Palo Alto Networks | [CVE-2026-123633 Portfolio Status: Impact of NGINX Vulnerabilities (CVE-2026-123633, CVE-2026-123007) on Palo A](https://security.paloaltonetworks.com/CVE-2026-123633) | crítica |
| 2026-11-20 | Wordfence (WordPress) | [CVE-2026-129289 and Other Critical PHP Vulnerabilities: What WordPress Site Owners Need to Know](https://www.wordfence.com/blog/2026/11/cve-2026-129289-wordpress-php-vulnerabilities/) | sin parche, crítica |

### Vulnerabilidades de los últimos 7 días

**4690** CVE publicados · **4** ya explotados · **89** urgentes · **367** con CVSS ≥ 9 · **710** paquetes maliciosos en los registros · **5** con exploit en Exploit-DB · **2** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-129448 | Apache | 9.8 | 5.5 % | 2026-11-17 |
| explotada | CVE-2026-133968 | Project MONAI | 9.8 | 3.7 % | 2026-11-20 |
| explotada | CVE-2026-123890 | Broadcom | 9.8 | 3.5 % | 2026-11-19 |
| explotada | CVE-2026-134624 | N-able | 9.3 | 0.4 % | 2026-11-22 |
| urgente | CVE-2026-115560 | — | 9.2 | 73.1 % | 2026-11-19 |
| urgente | CVE-2026-114938 | Oracle | 8.1 | 57.3 % | 2026-11-17 |
| urgente | CVE-2026-95645 | Windows | 9.1 | 28.8 % | 2026-11-18 |
| urgente | CVE-2026-123007 | F5 | 9.2 | 27.8 % | 2026-11-18 |
| urgente | CVE-2026-95643 | — | 9.1 | 24.4 % | 2026-11-18 |
| urgente | CVE-2026-123633 | F5 | 9.2 | 17.5 % | 2026-11-18 |
| urgente | CVE-2026-123634 | F5 | 9.2 | 17.1 % | 2026-11-18 |
| urgente | CVE-2026-121810 | F5 | 9.2 | 16.4 % | 2026-11-18 |
| urgente | CVE-2026-129289 | — | 9.2 | 16.2 % | 2026-11-19 |
| urgente | CVE-2026-113425 | F5 | 9.2 | 13.9 % | 2026-11-18 |
| urgente | CVE-2026-126714 | — | 9.2 | 13.3 % | 2026-11-19 |
| urgente | CVE-2026-129538 | — | 6.9 | 12.8 % | 2026-11-19 |
| urgente | CVE-2026-129474 | — | 9.2 | 9.3 % | 2026-11-19 |
| urgente | CVE-2026-129182 | — | 9.2 | 8.5 % | 2026-11-19 |
| urgente | CVE-2026-129496 | — | 9.2 | 8.1 % | 2026-11-19 |
| urgente | CVE-2026-127027 | — | 9.2 | 4.2 % | 2026-11-20 |
| urgente | CVE-2026-133493 | D-Link | 9.3 | 3.7 % | 2026-11-20 |
| urgente | CVE-2026-129481 | — | 9.2 | 3.5 % | 2026-11-19 |
| urgente | CVE-2026-133500 | — | 9.1 | 3.0 % | 2026-11-20 |
| urgente | CVE-2026-116448 | — | 9.8 | 2.9 % | 2026-11-18 |
| urgente | CVE-2026-134882 | TOTOLINK | 10.0 | 2.5 % | 2026-11-23 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 660 | 3 / 17 |
| Python (PyPI) | 🔴 paquetes maliciosos | 40 | 4 / 34 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 7 |
| .NET (C#) (NuGet) | 🟠 avisos críticos | 0 | 3 / 3 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 3 / 11 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 4 / 21 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 1 | 1 / 6 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 9 | 1 / 0 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 880 | 56 | 2 |
| Red, VPN y firewalls | 🔴 explotación activa | 199 | 17 | 9 |
| Windows y Microsoft | 🔴 explotación activa | 51 | 16 | 1 |
| Software empresarial | 🔴 explotación activa | 698 | 61 | 6 |
| Linux | 🔴 explotación activa | 556 | 13 | 1 |
| Virtualización y nube | 🔴 explotación activa | 30 | 2 | 2 |
| Apple (macOS · iOS) | 🔴 explotación activa | 20 | 5 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 1 | 0 | 2 |
| Navegadores | 🔴 explotación activa | 209 | 18 | 1 |
| Servidores y servicios | 🔴 explotación activa | 8 | 1 | 1 |
| Otros | 🔴 explotación activa | 1677 | 129 | 10 |
| Librerías de código abierto | 🟠 riesgo alto | 314 | 44 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 17 | 4 | 0 |
| Industrial (OT · ICS) | 🟠 riesgo alto | 1 | 1 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 20 | 0 | 0 |
| Android | 🟢 vigilar | 9 | 0 | 0 |
<!-- CTI:END -->
