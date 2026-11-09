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
**Última actualización:** 2026-11-09 22:01 UTC · **IOCs recolectados:** 1214 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 73 (alta) | alta | `45[.]141[.]148[.]75:24040` | ip:port | Remcos | ThreatFox | 2026-11-09 14:26:02 UTC |
| 71 (alta) | critica | `45[.]227[.]253[.]132:58336` | ip:port | Cobalt Strike | ThreatFox | 2026-11-09 03:45:52 UTC |
| 68 (media) | media | `35[.]195[.]85[.]59` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-09 08:25:56 UTC |
| 68 (media) | media | `35[.]194[.]143[.]194` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-08 22:28:51 UTC |
| 68 (media) | media | `34[.]22[.]196[.]121` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-08 22:16:35 UTC |
| 67 (media) | alta | `298b2d2cf81f6435744a15d6c83d9dfdcb4d854d6e5d6f4ca96380a1a4bb15b8` | filehash-sha256 | Mirai | ThreatFox | 2026-11-08 22:57:43 UTC |
| 67 (media) | alta | `38cbdf411e85b4136c8d4b725f7b46530919d45799a8065965d408db5ebcc15d` | filehash-sha256 | Mirai | ThreatFox | 2026-11-08 22:57:42 UTC |
| 66 (media) | alta | `90b0fb1dffe679e5c6087cf9dd0f8fb3ca9ae3ab68fa247313e7a6427dd79ed7` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 18:57:50 UTC |
| 66 (media) | alta | `055fda12b59a50e3411b58e175be5436a80d980a8b2c58a5567e8f2537c76388` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:56 UTC |
| 66 (media) | alta | `d37cf20d19df7c0eaea4b53e88c4c511fefc0e525d0f10e734ce57e6e973fda9` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:54 UTC |
| 66 (media) | alta | `eb060a69accdb82964baf879505b4fd0fd2913ee0f468683a3ef831182b6e0e1` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:53 UTC |
| 66 (media) | alta | `ca0778678eeca1df0b5e352e99f8e77de231508d51c6e622a30ff2ead9221a34` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:49 UTC |
| 66 (media) | alta | `e086dbbd2bdf9ceb9fe151281472658b63902e115c2b3eecc5ea8b75353b2338` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:47 UTC |
| 66 (media) | alta | `869f3b57d1a954ca6d75e1b2f0b37c062ee2ecc6190b4f47f67992f18f7a39dc` | filehash-sha256 | Mirai | ThreatFox | 2026-11-08 22:57:45 UTC |
| 65 (media) | alta | `ccb60cbbea00ef03381e58674abb1ff8d5c2ddb5ee0cd45b5da91e5d1f574490` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:52 UTC |
| 64 (media) | alta | `49aa23fd990f9f43fab75f94b6485b74713a14759c20fab55d59afbae64da553` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:58 UTC |
| 64 (media) | alta | `84dbf2717cc84ffc1bdcee1208e058411a6923fe0fd4a75e2b12fefb22cebbd2` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:55 UTC |
| 64 (media) | alta | `7fdf9499f94e7ce839d7dade6ff8b4a30ef983a131eff8d1ee3d2a89c1c23bab` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:51 UTC |
| 63 (media) | alta | `0d1e89169b0f0b1f1d455e8c9b9fe98f540e0311df5eaa102c93be2d5a58accf` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-09 18:57:53 UTC |
| 63 (media) | alta | `bac1393a58c35de2ed4bf7327498a86241c7e94550f3d11204240680e1c36712` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-09 09:57:59 UTC |
| 63 (media) | alta | `0c449f8b0f2ef8b0b32a6506b778ce10f0e0d4df3054065207a3f9fbb784ee1e` | filehash-sha256 | Mirai | ThreatFox | 2026-11-09 09:57:50 UTC |
| 63 (media) | critica | `45[.]227[.]254[.]143:50150` | ip:port | Cobalt Strike | ThreatFox | 2026-11-09 06:54:39 UTC |
| 63 (media) | media | `34[.]148[.]201[.]229` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-09 02:49:16 UTC |
| 62 (media) | alta | `2cd018935a1e04a0f18f37b36698399ea10c324f7962f8c035bf90e657415a31` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-09 20:57:52 UTC |
| 62 (media) | alta | `8189d6ed5f86e79e70c2c321d615699a266d027bd9e0c7d739ace8f4b0381c43` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-09 18:57:54 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-41709 | Broadcom VMware ESX | 2026-10-28 | Unknown |
| CVE-2026-46300 | Linux Kernel | 2026-10-28 | Unknown |
| CVE-2026-48356 | Adobe Commerce and Magento | 2026-10-27 | Unknown |
| CVE-2026-111497 | Google Brotli | 2026-10-27 | Unknown |
| CVE-2026-109618 | PHP Group PHP | 2026-10-26 | Unknown |
| CVE-2026-109619 | PHP Group PHP | 2026-10-26 | Unknown |

### Avisos de seguridad de los últimos 7 días

**295** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **52** de algo que ya se explota · **5** de día cero · **16** sin parche

**Lo más citado:** CVE-2026-111497 (5 fuentes, KEV) · CVE-2026-123158 (5 fuentes, KEV) · CVE-2026-119977 (4 fuentes, KEV) · CVE-2026-19868 (4 fuentes, KEV) · CVE-2026-109618 (3 fuentes, KEV) · CVE-2026-109619 (3 fuentes, KEV) · CVE-2026-98432 (2 fuentes) · CVE-2024-27834 (2 fuentes, KEV)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-09 | Cisco | [Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20and%20Brotli%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-09 | BleepingComputer | [N-able takes cloud platform offline after 30+ "zero-days" published](https://www.bleepingcomputer.com/news/security/n-able-takes-cloud-platform-offline-after-30-plus-zero-days-published/) | día cero |
| 2026-11-09 | Palo Alto Networks | [CVE-2026-111497 Portfolio Status: Impact of Brotli Vulnerability (CVE-2026-111497) on Palo Alto Networks Produ](https://security.paloaltonetworks.com/CVE-2026-111497) | explotada, crítica |
| 2026-11-09 | The Hacker News | [Hackers Exploit Qubole's Trusted AWS Access to Breach Customer Accounts and Steal Data](https://thehackernews.com/2026/11/hackers-exploit-quboles-trusted-aws.html) | explotada |
| 2026-11-09 | BleepingComputer | [Hackers exploit SSHole OpenSSH flaw to breach Linux systems](https://www.bleepingcomputer.com/news/security/hackers-exploit-sshole-openssh-flaw-to-breach-linux-systems/) | explotada |
| 2026-11-09 | SecurityWeek | [Hackers Exploiting ‘SSHole’ Authentication Bypass in OpenSSH](https://www.securityweek.com/hackers-exploiting-sshole-authentication-bypass-in-openssh/) | explotada |
| 2026-11-09 | CISA | [CISA Adds Four Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/09/cisa-adds-four-known-exploited-vulnerabilities-catalog) | explotada, crítica |
| 2026-11-09 | INCIBE-CERT | [Múltiples vulnerabilidades en SonicOS de SonicWall](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-sonicos-de-sonicwall) | explotada |
| 2026-11-09 | The Hacker News | [CISA Flags SonicWall SonicOS MFA Bypass Flaw Amid Reports of Possible Exploitation](https://thehackernews.com/2026/11/cisa-flags-sonicwall-sonicos-mfa-bypass.html) | explotada |
| 2026-11-07 | SecurityWeek | [SonicWall Patches Exploited SonicOS Vulnerability That Weakens VPN Logins](https://www.securityweek.com/sonicwall-patches-exploited-sonicos-bug-that-weakens-vpn-logins/) | explotada |
| 2026-11-07 | BleepingComputer | [SonicWall warns of new SSL-VPN MFA bypass flaw exploited in attacks](https://www.bleepingcomputer.com/news/security/sonicwall-warns-of-new-ssl-vpn-mfa-bypass-flaw-exploited-in-attacks/) | explotada |
| 2026-11-06 | The Hacker News | [Installing the Fix for an Exploited WordPress Flaw Can Expose Some Sites One Last Time](https://thehackernews.com/2026/11/installing-fix-for-exploited-wordpress.html) | explotada, sin parche |
| 2026-11-06 | The Hacker News | [Hackers Target OpenSSH SSHole Flaw Within Hours of Disclosure, Gain Root on Honeypot](https://thehackernews.com/2026/11/hackers-exploited-openssh-sshole-flaw.html) | explotada |
| 2026-11-06 | Cisco | [Vulnerabilities in PHP Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20PHP%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-06 | Segu-Info | [Cloudflare lanza Zero Wire: para realizar un seguimiento de CVE críticos, exploits activos y correcciones de s](http://blog.segu-info.com.ar/2026/11/cloudflare-lanza-zero-wire-para.html) | crítica |
| 2026-11-06 | BleepingComputer | [D-Link warns of multiple zero-days in DGS-3130 Series switches](https://www.bleepingcomputer.com/news/security/d-link-warns-of-multiple-zero-days-in-dgs-3130-series-switches/) | día cero, sin parche |
| 2026-11-06 | CISA | [CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/06/cisa-adds-one-known-exploited-vulnerability-catalog) | explotada |
| 2026-11-06 | INCIBE-CERT | [Omisión de autenticación por contraseña en OpenSSH de Alpine Linux](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/omision-de-autenticacion-por-contrasena-en-openssh-de-alpine-linux) | explotada |
| 2026-11-06 | Siemens ProductCERT | [SSA-443410 V1.1 (Last Update: 2026-11-06): Node2Shell Vulnerability in Industrial Edge Management Applications](https://cert-portal.siemens.com/productcert/html/ssa-443410.html) | explotada |
| 2026-11-06 | Siemens ProductCERT | [SSA-045512 V1.2 (Last Update: 2026-11-06): Node2Shell Vulnerability in Siemens Products](https://cert-portal.siemens.com/productcert/html/ssa-045512.html) | explotada |
| 2026-11-05 | Wordfence (WordPress) | [Attackers Actively Probing for Upgrade-Window RCE Vulnerability in WordPress Core](https://www.wordfence.com/blog/2026/11/attackers-actively-probing-for-upgrade-window-rce-vulnerability-in-wordpress-core/) | explotada, sin parche |
| 2026-11-05 | SecurityWeek | [Zyxel Switch Hacks Blamed on Patched Flaw Actually Exploited a Zero-Day](https://www.securityweek.com/zyxel-switch-hacks-blamed-on-patched-flaw-actually-exploited-a-zero-day/) | explotada, día cero |
| 2026-11-05 | INCIBE-CERT | [Múltiples vulnerabilidades en AuthPoint Gateway de WatchGuard](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-authpoint-gateway-de-watchguard) | crítica |
| 2026-11-05 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos de Phoenix Contact](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-de-phoenix-contact-9) | explotada |
| 2026-11-05 | INCIBE-CERT · industrial | [Escritura fuera de límites en Advanced Batch Management de ABB](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/escritura-fuera-de-limites-en-advanced-batch-management-de-abb) | explotada |

### Vulnerabilidades de los últimos 7 días

**3233** CVE publicados · **6** ya explotados · **46** urgentes · **285** con CVSS ≥ 9 · **415** paquetes maliciosos en los registros · **1** con exploit en Exploit-DB · **2** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-116779 | SignalWire | 9.8 | 1.3 % | 2026-11-05 |
| explotada | CVE-2026-123158 | OpenBSD | 8.1 | 1.0 % | 2026-11-05 |
| explotada | CVE-2026-118527 | Ivanti | 4.3 | 0.8 % | 2026-11-03 |
| explotada | CVE-2026-19868 | SonicWall | 7.5 | 0.6 % | 2026-11-06 |
| explotada | CVE-2026-123218 | IBM | 9.8 | 0.4 % | 2026-11-07 |
| explotada | CVE-2026-102895 | GPUStack | 9.8 | 0.3 % | 2026-11-04 |
| urgente | CVE-2026-77690 | — | 8.8 | 15.6 % | 2026-11-04 |
| urgente | CVE-2026-124580 | — | 10.0 | 2.8 % | 2026-11-09 |
| urgente | CVE-2026-122051 | Edimax | 9.3 | 2.6 % | 2026-11-05 |
| urgente | CVE-2026-121932 | Linksys | 9.3 | 2.4 % | 2026-11-04 |
| urgente | CVE-2026-124585 | — | 9.9 | 2.2 % | 2026-11-09 |
| urgente | CVE-2026-124577 | — | 9.8 | 2.1 % | 2026-11-09 |
| urgente | CVE-2026-121607 | — | 9.3 | 2.0 % | 2026-11-04 |
| urgente | CVE-2026-17402 | IBM | 9.9 | 1.9 % | 2026-11-07 |
| urgente | CVE-2026-28336 | SolarWinds | 9.9 | 1.6 % | 2026-11-03 |
| urgente | CVE-2026-122193 | — | 9.3 | 1.6 % | 2026-11-06 |
| urgente | CVE-2026-86596 | WordPress (plugins) | 9.8 | 1.5 % | 2026-11-02 |
| urgente | CVE-2026-59105 | Microsoft | 9.3 | 1.4 % | 2026-11-06 |
| urgente | CVE-2026-114630 | WordPress (plugins) | 9.1 | 1.3 % | 2026-11-06 |
| urgente | CVE-2026-54143 | Código abierto (GitHub) | 9.8 | 1.2 % | 2026-11-05 |
| urgente | CVE-2026-13594 | — | 9.1 | 1.1 % | 2026-11-03 |
| urgente | CVE-2026-83542 | Apache | 9.8 | 1.1 % | 2026-11-05 |
| urgente | CVE-2026-113363 | Windows | 9.3 | 1.1 % | 2026-11-09 |
| urgente | CVE-2026-116785 | Código abierto (GitHub) | 9.1 | 1.0 % | 2026-11-05 |
| urgente | CVE-2026-123966 | Tenda | 10.0 | 1.0 % | 2026-11-07 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 362 | 2 / 6 |
| Python (PyPI) | 🔴 paquetes maliciosos | 43 | 3 / 6 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 3 |
| .NET (C#) (NuGet) | 🟡 avisos altos | 0 | 0 / 2 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 0 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 7 / 10 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 1 | 0 / 0 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 9 | 0 / 0 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 758 | 50 | 3 |
| Software empresarial | 🔴 explotación activa | 452 | 66 | 4 |
| Windows y Microsoft | 🔴 explotación activa | 35 | 6 | 1 |
| Red, VPN y firewalls | 🔴 explotación activa | 15 | 4 | 9 |
| Servidores y servicios | 🔴 explotación activa | 127 | 0 | 5 |
| Virtualización y nube | 🔴 explotación activa | 20 | 5 | 1 |
| Linux | 🔴 explotación activa | 117 | 3 | 1 |
| Apple (macOS · iOS) | 🔴 explotación activa | 0 | 0 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Industrial (OT · ICS) | 🔴 explotación activa | 0 | 0 | 1 |
| Otros | 🔴 explotación activa | 1103 | 69 | 6 |
| Librerías de código abierto | 🟠 riesgo alto | 328 | 36 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 32 | 13 | 0 |
| Navegadores | 🟠 riesgo alto | 219 | 32 | 0 |
| Android | 🟠 riesgo alto | 15 | 1 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 12 | 0 | 0 |
<!-- CTI:END -->
