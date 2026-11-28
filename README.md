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
**Última actualización:** 2026-11-28 01:09 UTC · **IOCs recolectados:** 2262 · **CVEs KEV recientes:** 27

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | media | `f77dbed714575efb8146899633f87b268aa81c20db6fa5abbb3bdbdbb96ca3d0` | filehash-sha256 | WannaCryptor | ThreatFox | 2026-11-27 06:50:39 UTC |
| 72 (alta) | media | `206[.]189[.]40[.]120:9999` | ip:port | Unknown malware | ThreatFox | 2026-11-27 06:51:23 UTC |
| 72 (alta) | alta | `91[.]92[.]40[.]4:80` | ip:port | Mirai | ThreatFox | 2026-11-27 06:51:22 UTC |
| 71 (alta) | alta | `143[.]203[.]219[.]50:87` | ip:port | Mirai | ThreatFox | 2026-11-27 22:39:56 UTC |
| 71 (alta) | media | `176[.]65[.]134[.]52:3434` | ip:port | Hook | ThreatFox | 2026-11-27 21:05:00 UTC |
| 70 (alta) | media | `103[.]215[.]78[.]42:9087` | ip:port | Unknown malware | ThreatFox | 2026-11-28 00:27:09 UTC |
| 67 (media) | media | `107[.]172[.]5[.]167:8899` | ip:port | Unknown malware | ThreatFox | 2026-11-27 06:51:27 UTC |
| 64 (media) | media | `b4fad9d8b9511c41564f9ec02cbd6a071317f222ca0c5a16e129a875e979f1d8` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:00:57 UTC |
| 64 (media) | media | `401160df5cf715cf34ccce95de888290529e6323d09437c421bdee9d56d8ddb2` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:00:56 UTC |
| 64 (media) | media | `a91cdc82394ec03bb61b2d61575a2e2788fd6499fdcd6f05100bafe1eebb9364` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:00:55 UTC |
| 63 (media) | media | `839a141e6988a96ba5614e738d12299a33a7810d54ff8d2e83fe4127c69e3400` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:09 UTC |
| 63 (media) | media | `d27a85b67bf3f89d7b37c7c93b931f180c67a319b62b468c4d5becaf4223a711` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:08 UTC |
| 63 (media) | media | `6a1b935842ae02f21c5ed5dedf5fb8d1175e136b1b69adb7b500d51c7b4d271b` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:07 UTC |
| 63 (media) | media | `5e9bb7196ea21cc7240c03b5ee445266fa74b7b834d41d01162d098c2fe8308a` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:06 UTC |
| 63 (media) | media | `f1caf5e5df288b1c0231c47435895ef5beebbdfaff87c5f99ba7ffcfbadd7a02` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:05 UTC |
| 63 (media) | media | `9b735bdaedfa6dbae7406c2a54763c33ac9cf9567e3d177821a40ed73b75cc2b` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:04 UTC |
| 63 (media) | media | `8ead1f56da636ec03e067f233d4b6f9cc967c875c86a8509e071d158b8d78537` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:03 UTC |
| 63 (media) | media | `e2554ab0a47ef97f13d527641bc087441181e52ba7b8db1dee5176cd1aacfe30` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:02 UTC |
| 63 (media) | media | `35bc6282a1e92b318b550b3a1fc79cfa5743783a41a41ef967247d07e599e6ba` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:01 UTC |
| 63 (media) | alta | `3c7bf50b9a0c0f38bc5ddaa559eccfb25895c4f33f49ecc9c0269f66e8a60362` | filehash-sha256 | Mirai | ThreatFox | 2026-11-27 03:01:00 UTC |
| 63 (media) | alta | `39904a6f69cf843b8bf6be3fdd3054d7ec068149f1086af924997e56b7c90cb8` | filehash-sha256 | Mirai | ThreatFox | 2026-11-27 03:00:59 UTC |
| 62 (media) | media | `af54b578066d6933cdf9be8ffe12e510aa21a549f663af43e86fad1ca5475196` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:15 UTC |
| 62 (media) | media | `44b1a6ed6dfd906245a888539bf9b8e77cb508216e5963b38099de36e21628a3` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:14 UTC |
| 62 (media) | media | `2f0349fe54d7d78fab6948e288e01e448e0dd58bc6d48a38e2af543cad4829a8` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-27 03:01:13 UTC |
| 62 (media) | alta | `05dad40cc8cc98d74bb3fe5f7fd73751948012cdc914f68d6e03301d87cb1a1c` | filehash-sha256 | Mirai | ThreatFox | 2026-11-27 03:01:12 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-120705 | OSGeo GeoServer | 2026-11-27 | Unknown |
| CVE-2026-129243 | OSGeo GeoServer | 2026-11-27 | Unknown |
| CVE-2026-136716 | Drupal Core | 2026-11-27 | Unknown |
| CVE-2026-103406 | Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router | 2026-11-25 | Unknown |
| CVE-2026-133469 | Vates Xen Orchestra | 2026-11-25 | Unknown |
| CVE-2025-41450 | Danfoss AK-SM 800A Series | 2026-11-25 | Unknown |
| CVE-2023-25914 | Danfoss AK-SM 800A Series | 2026-11-25 | Unknown |
| CVE-2023-25915 | Danfoss AK-SM 800A Series | 2026-11-25 | Unknown |
| CVE-2026-133324 | Mitel MiCollab | 2026-11-25 | Unknown |
| CVE-2026-133275 | Mitel MiCollab | 2026-11-25 | Unknown |
| CVE-2026-133311 | Mitel MiCollab | 2026-11-25 | Unknown |
| CVE-2026-133303 | Mitel MiCollab | 2026-11-25 | Unknown |
| CVE-2026-133323 | Mitel MiCollab | 2026-11-25 | Unknown |
| CVE-2026-132224 | Optimizely Web Experimentation | 2026-11-24 | Unknown |
| CVE-2026-131914 | Idunno AntiCsrf | 2026-11-24 | Unknown |
| CVE-2026-132165 | Drupal Core | 2026-11-24 | Unknown |
| CVE-2026-133968 | Project MONAI MONAI Label | 2026-11-23 | Unknown |
| CVE-2026-134624 | N-able MailAssure | 2026-11-23 | Unknown |
| CVE-2026-129448 | Apache Roller | 2026-11-20 | Unknown |
| CVE-2026-123890 | Broadcom VMware vCenter | 2026-11-20 | Unknown |
| CVE-2025-42884 | SAP NetWeaver | 2026-11-20 | Unknown |
| CVE-2026-76466 | Cisco Expressway Series | 2026-11-20 | Unknown |
| CVE-2024-10441 | Synology DiskStation Manager (DSM) | 2026-11-18 | Known |
| CVE-2026-40217 | BerriAI LiteLLM | 2026-11-18 | Unknown |
| CVE-2026-90817 | Vanderbilt University Research Electronic Data Capture (REDCap) | 2026-11-18 | Unknown |

### Avisos de seguridad de los últimos 7 días

**283** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **40** de algo que ya se explota · **10** de día cero · **21** sin parche

**Lo más citado:** CVE-2026-114938 (4 fuentes) · CVE-2026-131914 (4 fuentes, KEV) · CVE-2026-136716 (4 fuentes, KEV) · CVE-2026-123007 (3 fuentes) · CVE-2026-111497 (3 fuentes, KEV) · CVE-2026-123633 (3 fuentes) · CVE-2026-123903 (3 fuentes) · CVE-2026-99362 (3 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-27 | Google Chrome | [Long Term Support Channel Update for ChromeOS](http://chromereleases.googleblog.com/2026/11/long-term-support-channel-update-for_01009121915.html) | explotada |
| 2026-11-27 | BleepingComputer | [Unpatched Cacti zero-day with public PoC gives remote code execution](https://www.bleepingcomputer.com/news/security/unpatched-cacti-zero-day-with-public-poc-gives-remote-code-execution/) | día cero, sin parche |
| 2026-11-27 | Segu-Info | [Explotan vulnerabilidades críticas Zero-Day en VMware vCenter para obtener acceso de administrador y robar dat](http://blog.segu-info.com.ar/2026/11/explotan-una-vulnerabilidad-critica.html) | explotada, día cero, crítica |
| 2026-11-27 | CISA | [CISA Adds Three Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/27/cisa-adds-three-known-exploited-vulnerabilities-catalog) | explotada, crítica |
| 2026-11-27 | BleepingComputer | [Drupal warns of new site takeover flaw exploited in attacks](https://www.bleepingcomputer.com/news/security/drupal-warns-of-new-access-bypass-flaw-exploited-in-attacks/) | explotada, sin parche |
| 2026-11-27 | The Hacker News | [Unpatched Cacti Zero-Day Enables RCE in Just Four HTTP Requests via Guest Access](https://thehackernews.com/2026/11/unpatched-cacti-zero-day-enables-rce-in.html) | día cero, sin parche |
| 2026-11-27 | Siemens ProductCERT | [SSA-898633 V1.1 (Last Update: 2026-11-27): Brotli Vulnerability in Palo Alto Networks PAN-OS on RUGGEDCOM APE1](https://cert-portal.siemens.com/productcert/html/ssa-898633.html) | explotada |
| 2026-11-27 | Siemens ProductCERT | [SSA-443410 V1.2 (Last Update: 2026-11-27): Node2Shell Vulnerability in Industrial Edge Management Applications](https://cert-portal.siemens.com/productcert/html/ssa-443410.html) | explotada |
| 2026-11-26 | SecurityWeek | [Critical Juniper Session Smart Conductor Flaw Exploited in Attacks](https://www.securityweek.com/critical-juniper-session-smart-conductor-flaw-exploited-in-attacks/) | explotada, crítica |
| 2026-11-26 | SecurityWeek | [Mitel MiCollab Zero-Days Exploited in Suspected AI-Assisted Attacks](https://www.securityweek.com/mitel-micollab-zero-days-exploited-in-suspected-ai-assisted-attacks/) | explotada, día cero |
| 2026-11-26 | INCIBE-CERT | [Omisión del control de acceso en Drupal](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/omision-del-control-de-acceso-en-drupal) | explotada, crítica |
| 2026-11-26 | SecurityWeek | [Drupal Installer Patch Left a Gap Attackers Are Already Exploiting](https://www.securityweek.com/drupal-installer-patch-left-a-gap-attackers-are-already-exploiting/) | explotada |
| 2026-11-26 | The Hacker News | [Drupal Warns of New Highly Critical Site Takeover Vulnerability Under Active Exploitation](https://thehackernews.com/2026/11/drupal-warns-of-new-highly-critical.html) | explotada, crítica |
| 2026-11-26 | The Hacker News | [Hackers Exploit 10 Vulnerabilities Across Mitel, Juniper, Vates, and Danfoss Products](https://thehackernews.com/2026/11/hackers-exploit-10-vulnerabilities.html) | explotada |
| 2026-11-26 | CERT-FR · avisos | [Vulnérabilité dans Drupal (26 novembre 2026)](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1623/) | explotada, crítica |
| 2026-11-25 | BleepingComputer | [Palo Alto Networks warns of Fragnesia flaw exploited in PAN-OS attacks](https://www.bleepingcomputer.com/news/security/palo-alto-networks-warns-of-fragnesia-flaw-exploited-in-pan-os-attacks/) | explotada |
| 2026-11-25 | Wordfence (WordPress) | [Wordfence Intelligence Weekly WordPress Vulnerability Report (November 16, 2026 to November 22, 2026)](https://www.wordfence.com/blog/2026/11/wordfence-intelligence-weekly-wordpress-vulnerability-report-november-16-2026-to-november-22-2026/) | sin parche, crítica |
| 2026-11-25 | BleepingComputer | [CISA warns of critical unpatched flaw in Danfoss refrigeration controllers](https://www.bleepingcomputer.com/news/security/cisa-warns-of-critical-unpatched-flaw-in-danfoss-refrigeration-controllers/) | sin parche, crítica |
| 2026-11-25 | The Hacker News | [Hackers Exploit Two GeoServer Flaws as Researchers Warn of Unauthenticated RCE Chains](https://thehackernews.com/2026/11/hackers-exploit-two-geoserver-flaws-as.html) | explotada |
| 2026-11-25 | CISA | [CISA Adds 10 Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/25/cisa-adds-10-known-exploited-vulnerabilities-catalog) | explotada, crítica |
| 2026-11-25 | The Hacker News | [Drupal Fail2Install Exploit Details Emerge as Critical RCE Flaw Faces Active Exploitation](https://thehackernews.com/2026/11/drupal-fail2install-exploit-details.html) | explotada, crítica |
| 2026-11-25 | BleepingComputer | [Hackers now exploit critical Drupal RCE flaw to hijack sites](https://www.bleepingcomputer.com/news/security/hackers-now-exploit-critical-drupal-rce-flaw-to-hijack-sites/) | explotada, sin parche, crítica |
| 2026-11-25 | The Hacker News | [Hackers Exploited CVSS 10.0 Hex.pm RCE Flaw to Compromise 6 Package Registry Servers](https://thehackernews.com/2026/11/hackers-exploited-cvss-100-hexpm-rce.html) | explotada |
| 2026-11-25 | SecurityWeek | [Hackers Exploit Unpatched Flaw in Defunct Idunno AntiCsrf Library](https://www.securityweek.com/hackers-exploit-unpatched-flaw-in-defunct-idunno-anticsrf-library/) | explotada, sin parche |
| 2026-11-25 | INCIBE-CERT | [\[Actualización 26/11/2026\] Múltiples vulnerabilidades en Serv-U de SolarWinds](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-serv-u-de-solarwinds-0) | crítica |

### Vulnerabilidades de los últimos 7 días

**3287** CVE publicados · **4** ya explotados · **91** urgentes · **236** con CVSS ≥ 9 · **486** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **3** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-133469 | Vates | 9.8 | 31.8 % | 2026-11-23 |
| explotada | CVE-2026-132165 | Drupal | 9.8 | 8.4 % | 2026-11-26 |
| explotada | CVE-2026-134624 | N-able | 8.7 | 1.8 % | 2026-11-22 |
| explotada | CVE-2026-136716 | Drupal | 9.8 | 1.2 % | 2026-11-26 |
| urgente | CVE-2026-135789 | D-Link | 9.1 | 3.6 % | 2026-11-24 |
| urgente | CVE-2026-103788 | — | 9.6 | 3.3 % | 2026-11-23 |
| urgente | CVE-2026-134882 | TOTOLINK | 10.0 | 3.2 % | 2026-11-23 |
| urgente | CVE-2026-129514 | — | 10.0 | 3.2 % | 2026-11-24 |
| urgente | CVE-2026-136550 | Tenda | 9.1 | 3.0 % | 2026-11-25 |
| urgente | CVE-2026-97180 | — | 9.4 | 2.9 % | 2026-11-25 |
| urgente | CVE-2026-137721 | — | 10.0 | 2.8 % | 2026-11-27 |
| urgente | CVE-2026-103782 | — | 9.9 | 2.8 % | 2026-11-23 |
| urgente | CVE-2026-135202 | WordPress (plugins) | 9.8 | 2.7 % | 2026-11-24 |
| urgente | CVE-2026-137723 | — | 9.6 | 2.6 % | 2026-11-27 |
| urgente | CVE-2026-135796 | — | 9.9 | 2.5 % | 2026-11-24 |
| urgente | CVE-2026-136823 | D-Link | 10.0 | 2.5 % | 2026-11-25 |
| urgente | CVE-2026-123903 | VMware | 9.8 | 2.4 % | 2026-11-26 |
| urgente | CVE-2026-135792 | — | 10.0 | 2.3 % | 2026-11-24 |
| urgente | CVE-2026-135797 | — | 10.0 | 2.3 % | 2026-11-24 |
| urgente | CVE-2026-137090 | — | 9.8 | 2.3 % | 2026-11-25 |
| urgente | CVE-2026-136549 | Tenda | 10.0 | 2.2 % | 2026-11-25 |
| urgente | CVE-2026-136434 | — | 9.8 | 2.0 % | 2026-11-24 |
| urgente | CVE-2026-135208 | — | 9.8 | 2.0 % | 2026-11-23 |
| urgente | CVE-2026-136404 | — | 9.3 | 2.0 % | 2026-11-24 |
| urgente | CVE-2026-135791 | — | 9.9 | 1.9 % | 2026-11-24 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 432 | 3 / 0 |
| Python (PyPI) | 🔴 paquetes maliciosos | 35 | 0 / 1 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 3 |
| .NET (C#) (NuGet) | 🟢 sin alertas | 0 | 0 / 0 |
| PHP (Packagist) | 🟠 avisos críticos | 0 | 2 / 4 |
| Go (Go modules) | 🟡 avisos altos | 0 | 0 / 2 |
| Rust (crates.io) | 🟡 avisos altos | 0 | 0 / 1 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 19 | 0 / 0 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 1108 | 50 | 4 |
| Software empresarial | 🔴 explotación activa | 236 | 30 | 5 |
| Windows y Microsoft | 🔴 explotación activa | 38 | 15 | 1 |
| Virtualización y nube | 🔴 explotación activa | 62 | 10 | 2 |
| Navegadores | 🔴 explotación activa | 124 | 20 | 1 |
| Servidores y servicios | 🔴 explotación activa | 59 | 2 | 1 |
| Apple (macOS · iOS) | 🔴 explotación activa | 4 | 0 | 1 |
| Red, VPN y firewalls | 🔴 explotación activa | 3 | 0 | 10 |
| Otros | 🔴 explotación activa | 1403 | 80 | 21 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 27 | 14 | 0 |
| Librerías de código abierto | 🟠 riesgo alto | 61 | 8 | 0 |
| Linux | 🟠 riesgo alto | 121 | 4 | 0 |
| IA y agentes (LLM · MCP) | 🟠 riesgo alto | 29 | 2 | 0 |
| Industrial (OT · ICS) | 🟠 riesgo alto | 6 | 1 | 0 |
| Android | 🟢 vigilar | 6 | 0 | 0 |
<!-- CTI:END -->
