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
**Última actualización:** 2026-11-21 02:07 UTC · **IOCs recolectados:** 1209 · **CVEs KEV recientes:** 21

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 75 (alta) | media | `51[.]81[.]92[.]176:80` | ip:port | Unknown malware | ThreatFox | 2026-11-20 12:26:17 UTC |
| 75 (alta) | media | `162[.]141[.]167[.]33:8443` | ip:port | Unknown malware | ThreatFox | 2026-11-20 09:10:19 UTC |
| 72 (alta) | media | `37[.]221[.]79[.]4:80` | ip:port | Unknown malware | ThreatFox | 2026-11-21 01:48:40 UTC |
| 72 (alta) | media | `171[.]221[.]160[.]227:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:25 UTC |
| 71 (alta) | media | `193[.]90[.]12[.]62:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:26 UTC |
| 71 (alta) | media | `109[.]160[.]32[.]45:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:23 UTC |
| 71 (alta) | media | `109[.]160[.]32[.]146:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:23 UTC |
| 71 (alta) | media | `109[.]160[.]32[.]131:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:23 UTC |
| 71 (alta) | media | `109[.]160[.]32[.]39:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:23 UTC |
| 71 (alta) | media | `80[.]94[.]92[.]179:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:22 UTC |
| 71 (alta) | media | `194[.]147[.]58[.]39:8123` | ip:port | Unknown malware | ThreatFox | 2026-11-20 20:23:38 UTC |
| 71 (alta) | alta | `2[.]27[.]160[.]45:48108` | ip:port | Unknown RAT | ThreatFox | 2026-11-20 15:10:34 UTC |
| 69 (media) | media | `193[.]32[.]162[.]84:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:24 UTC |
| 69 (media) | media | `27[.]79[.]5[.]137:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:23 UTC |
| 69 (media) | media | `171[.]243[.]149[.]120:22` | ip:port | Unknown malware | ThreatFox | 2026-11-20 23:58:23 UTC |
| 69 (media) | media | `44f08e83abd27fb12e0bc636835e04407ee06adbf292b26bab8f7b65424bfde3` | filehash-sha256 | WannaCryptor | ThreatFox | 2026-11-20 09:48:15 UTC |
| 69 (media) | media | `169[.]58[.]115[.]94:8443` | ip:port | Unknown malware | ThreatFox | 2026-11-20 09:10:19 UTC |
| 68 (media) | media | `104[.]199[.]22[.]169` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-20 13:18:04 UTC |
| 68 (media) | alta | `37[.]221[.]79[.]128:12121` | ip:port | Mirai | ThreatFox | 2026-11-20 13:14:06 UTC |
| 68 (media) | alta | `176[.]65[.]149[.]156:3778` | ip:port | Mirai | ThreatFox | 2026-11-20 13:13:54 UTC |
| 68 (media) | media | `34[.]140[.]72[.]151` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-20 13:10:20 UTC |
| 68 (media) | alta | `45[.]198[.]224[.]89:80` | ip:port | Mirai | ThreatFox | 2026-11-20 07:24:10 UTC |
| 65 (media) | media | `38[.]55[.]215[.]36:8443` | ip:port | Unknown malware | ThreatFox | 2026-11-20 09:10:20 UTC |
| 63 (media) | alta | `09c3edd9f5f909f78c42bf15422edfec919f990707fa205d12a2c5cde67ab889` | filehash-sha256 | Mirai | ThreatFox | 2026-11-21 01:00:29 UTC |
| 63 (media) | alta | `1942f23cc0b2fc32749d4e35394e8637e2ccc4ccc5c4cd9dd5a88bc1e1a9544f` | filehash-sha256 | Mirai | ThreatFox | 2026-11-21 01:00:28 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-129448 | Apache Roller | 2026-11-20 | Unknown |
| CVE-2026-123890 | Broadcom VMware vCenter | 2026-11-20 | Unknown |
| CVE-2025-42884 | SAP NetWeaver | 2026-11-20 | Unknown |
| CVE-2026-76466 | Cisco Expressway Series | 2026-11-20 | Unknown |
| CVE-2024-10441 | Synology DiskStation Manager (DSM) | 2026-11-18 | Unknown |
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

**376** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **38** de algo que ya se explota · **8** de día cero · **44** sin parche

**Lo más citado:** CVE-2026-114938 (11 fuentes) · CVE-2026-123007 (11 fuentes) · CVE-2026-123633 (9 fuentes) · CVE-2026-113425 (6 fuentes) · CVE-2026-121810 (6 fuentes) · CVE-2026-123634 (6 fuentes) · CVE-2026-111497 (5 fuentes, KEV) · CVE-2026-115560 (5 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-20 | Palo Alto Networks | [CVE-2026-123633 Portfolio Status: Impact of NGINX Vulnerabilities (CVE-2026-123633, CVE-2026-123007) on Palo A](https://security.paloaltonetworks.com/CVE-2026-123633) | crítica |
| 2026-11-20 | Wordfence (WordPress) | [CVE-2026-129289 and Other Critical PHP Vulnerabilities: What WordPress Site Owners Need to Know](https://www.wordfence.com/blog/2026/11/cve-2026-129289-wordpress-php-vulnerabilities/) | sin parche, crítica |
| 2026-11-20 | BleepingComputer | [Hackers use autonomous AI tool Cairn to find zero-day, take over server](https://www.bleepingcomputer.com/news/security/hackers-use-autonomous-ai-tool-cairn-to-find-zero-day-take-over-server/) | día cero |
| 2026-11-20 | Palo Alto Networks | [CVE-2026-114938 Portfolio Status: Impact of Java Vulnerability (CVE-2026-114938) on Palo Alto Networks Product](https://security.paloaltonetworks.com/CVE-2026-114938) | crítica |
| 2026-11-20 | Cisco | [Vulnerabilities in nginx Affecting Cisco Products: November 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nginx-nov-2026-e8jska2s?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20nginx%20Affecting%20Cisco%20Products:%20November%202026%26vs_k=1) | crítica |
| 2026-11-20 | Wordfence (WordPress) | [Wordfence Intelligence Weekly WordPress Vulnerability Report (November 9, 2026 to November 15, 2026)](https://www.wordfence.com/blog/2026/11/wordfence-intelligence-weekly-wordpress-vulnerability-report-november-9-2026-to-november-15-2026/) | sin parche, crítica |
| 2026-11-20 | Segu-Info | [Vulnerabilidad crítica de omisión de autenticación en VMware vCenter Server](http://blog.segu-info.com.ar/2026/11/vulnerabilidad-critica-de-omision-de.html) | explotada, día cero, crítica |
| 2026-11-20 | CISA | [CISA Adds Four Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/20/cisa-adds-four-known-exploited-vulnerabilities-catalog) | explotada, crítica |
| 2026-11-20 | BleepingComputer | [F5 releases emergency patches for critical BIG-IP RCE flaws](https://www.bleepingcomputer.com/news/security/f5-releases-emergency-patches-for-critical-big-ip-rce-flaws/) | crítica |
| 2026-11-20 | The Hacker News | [SonicWall Warns Gen 6 Firewalls Won't Get Security Patches, Even for Critical Flaws](https://thehackernews.com/2026/11/sonicwall-warns-gen-6-firewalls-wont.html) | crítica |
| 2026-11-20 | The Hacker News | [Hackers Exploit Critical Cisco Expressway Flaw, Breach Four Devices and Reach Internal Network](https://thehackernews.com/2026/11/hackers-exploit-critical-cisco.html) | explotada, crítica |
| 2026-11-20 | The Hacker News | [China-Linked Hackers Exploit Critical VMware vCenter Zero-Day to Gain Admin Access and Steal Data](https://thehackernews.com/2026/11/china-linked-hackers-exploit-critical.html) | explotada, día cero, crítica |
| 2026-11-20 | INCIBE-CERT | [Múltiples vulnerabilidades en Dimension de WatchGuard](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-dimension-de-watchguard) | crítica |
| 2026-11-20 | INCIBE-CERT | [Múltiples vulnerabilidades en PHP](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-php-0) | crítica |
| 2026-11-20 | INCIBE-CERT | [Múltiples vulnerabilidades en productos de Broadcom](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-broadcom-0) | explotada, sin parche, crítica |
| 2026-11-20 | Fortinet | [NGINX vulnerabilities](https://fortiguard.fortinet.com/psirt/FG-IR-26-279) | crítica |
| 2026-11-20 | The Hacker News | [New Unpatched Windows 0-Day FastUnlock Lets Someone Holding a Locked PC Run Programs on It](https://thehackernews.com/2026/11/new-unpatched-windows-0-day-fastunlock.html) | día cero, sin parche |
| 2026-11-20 | BleepingComputer | [VMware patches vCenter zero-day exploited in attacks since September](https://www.bleepingcomputer.com/news/security/vmware-patches-vcenter-zero-day-exploited-in-attacks-since-september/) | explotada, día cero |
| 2026-11-20 | Siemens ProductCERT | [SSA-935812 V1.0: NGINX2Root Vulnerability in Industrial Edge](https://cert-portal.siemens.com/productcert/html/ssa-935812.html) | crítica |
| 2026-11-20 | Siemens ProductCERT | [SSA-566435 V1.7 (Last Update: 2026-11-20): PHP2Shell Vulnerabilities in Siemens Software Products](https://cert-portal.siemens.com/productcert/html/ssa-566435.html) | explotada |
| 2026-11-20 | GitLab | [GitLab Critical Patch Release: 19.6.1, 19.5.8, 19.4.10](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-6-1-released/) | crítica |
| 2026-11-19 | BleepingComputer | [ASUS warns of critical hard-coded key flaw in Control Center Express](https://www.bleepingcomputer.com/news/security/asus-warns-of-critical-hard-coded-key-flaw-in-control-center-express/) | crítica |
| 2026-11-19 | SecurityWeek | [Newly Patched VMware vCenter Flaw Exploited as Zero-Day by Chinese APT](https://www.securityweek.com/newly-patched-vmware-vcenter-flaw-exploited-as-zero-day-by-chinese-apt/) | explotada, día cero |
| 2026-11-19 | The Hacker News | [phpAfterShell Explained: How Hackers Could Turn a PHP Session Flaw Into Code Execution](https://thehackernews.com/2026/11/phpaftershell-explained-how-hackers.html) | crítica |
| 2026-11-19 | BleepingComputer | [PHP security updates fix 18 flaws, including critical RCE bugs](https://www.bleepingcomputer.com/news/security/php-security-updates-fix-18-flaws-including-critical-rce-bugs/) | crítica |

### Vulnerabilidades de los últimos 7 días

**4302** CVE publicados · **2** ya explotados · **76** urgentes · **352** con CVSS ≥ 9 · **592** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **1** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-129448 | Apache | 9.8 | 1.2 % | 2026-11-17 |
| explotada | CVE-2026-123890 | Broadcom | 9.8 | 0.8 % | 2026-11-19 |
| urgente | CVE-2026-115560 | — | 9.2 | 56.4 % | 2026-11-19 |
| urgente | CVE-2026-95645 | Windows | 9.1 | 25.7 % | 2026-11-18 |
| urgente | CVE-2026-95643 | — | 9.1 | 21.7 % | 2026-11-18 |
| urgente | CVE-2026-126714 | — | 9.2 | 17.6 % | 2026-11-19 |
| urgente | CVE-2026-129289 | — | 9.2 | 17.0 % | 2026-11-19 |
| urgente | CVE-2026-129538 | — | 6.9 | 12.8 % | 2026-11-19 |
| urgente | CVE-2026-129182 | — | 9.2 | 11.0 % | 2026-11-19 |
| urgente | CVE-2026-129496 | — | 9.2 | 10.0 % | 2026-11-19 |
| urgente | CVE-2026-129474 | — | 9.2 | 8.6 % | 2026-11-19 |
| urgente | CVE-2026-123633 | F5 | 9.2 | 6.1 % | 2026-11-18 |
| urgente | CVE-2026-123007 | F5 | 9.2 | 6.0 % | 2026-11-18 |
| urgente | CVE-2026-129481 | — | 9.2 | 4.5 % | 2026-11-19 |
| urgente | CVE-2026-133500 | — | 9.1 | 3.7 % | 2026-11-20 |
| urgente | CVE-2026-133493 | D-Link | 9.3 | 2.5 % | 2026-11-20 |
| urgente | CVE-2026-129433 | — | 9.4 | 2.4 % | 2026-11-14 |
| urgente | CVE-2026-132622 | — | 9.4 | 2.3 % | 2026-11-19 |
| urgente | CVE-2026-116448 | — | 9.8 | 2.1 % | 2026-11-18 |
| urgente | CVE-2026-116449 | — | 9.8 | 2.1 % | 2026-11-18 |
| urgente | CVE-2026-111508 | — | 9.1 | 2.0 % | 2026-11-18 |
| urgente | CVE-2026-73969 | Código abierto (GitHub) | 9.8 | 2.0 % | 2026-11-18 |
| urgente | CVE-2026-129353 | D-Link | 9.3 | 1.8 % | 2026-11-15 |
| urgente | CVE-2011-10042 | — | 9.8 | 1.7 % | 2026-11-14 |
| urgente | CVE-2026-121810 | F5 | 9.2 | 1.7 % | 2026-11-18 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 539 | 2 / 17 |
| Python (PyPI) | 🔴 paquetes maliciosos | 43 | 4 / 37 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 4 |
| .NET (C#) (NuGet) | 🟠 avisos críticos | 0 | 3 / 3 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 3 / 10 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 4 / 20 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 1 | 1 / 6 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 9 | 1 / 0 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 746 | 56 | 3 |
| Red, VPN y firewalls | 🔴 explotación activa | 204 | 18 | 10 |
| Windows y Microsoft | 🔴 explotación activa | 35 | 5 | 1 |
| Software empresarial | 🔴 explotación activa | 693 | 62 | 6 |
| Linux | 🔴 explotación activa | 574 | 4 | 1 |
| Virtualización y nube | 🔴 explotación activa | 27 | 2 | 2 |
| Apple (macOS · iOS) | 🔴 explotación activa | 20 | 1 | 1 |
| Navegadores | 🔴 explotación activa | 208 | 18 | 1 |
| Servidores y servicios | 🔴 explotación activa | 7 | 1 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 1 | 0 | 2 |
| Otros | 🔴 explotación activa | 1384 | 133 | 8 |
| Librerías de código abierto | 🟠 riesgo alto | 360 | 45 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 21 | 6 | 0 |
| Industrial (OT · ICS) | 🟠 riesgo alto | 1 | 1 | 0 |
| Android | 🟢 vigilar | 12 | 0 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 9 | 0 | 0 |
<!-- CTI:END -->
