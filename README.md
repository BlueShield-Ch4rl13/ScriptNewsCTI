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
**Última actualización:** 2026-11-13 04:45 UTC · **IOCs recolectados:** 1884 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 77 (alta) | alta | `94[.]26[.]106[.]200:9506` | ip:port | Mirai | ThreatFox | 2026-11-12 06:48:37 UTC |
| 72 (alta) | media | `120[.]193[.]9[.]169:22` | ip:port | SSHDoor | ThreatFox | 2026-11-13 02:48:21 UTC |
| 71 (alta) | critica | `45[.]227[.]253[.]132:42643` | ip:port | Cobalt Strike | ThreatFox | 2026-11-13 03:45:42 UTC |
| 71 (alta) | media | `43[.]157[.]55[.]140:80` | ip:port | Unknown malware | ThreatFox | 2026-11-12 14:57:43 UTC |
| 69 (media) | critica | `104[.]251[.]180[.]129:31337` | ip:port | Sliver | ThreatFox | 2026-11-12 05:12:53 UTC |
| 68 (media) | media | `34[.]62[.]31[.]226` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-12 22:29:29 UTC |
| 68 (media) | media | `34[.]78[.]49[.]147` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-12 20:01:55 UTC |
| 68 (media) | media | `34[.]22[.]173[.]23` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-12 10:35:31 UTC |
| 68 (media) | alta | `45[.]141[.]148[.]75:23030` | ip:port | Remcos | ThreatFox | 2026-11-12 09:45:20 UTC |
| 68 (media) | media | `34[.]18[.]223[.]199` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-12 08:55:54 UTC |
| 66 (media) | alta | `141[.]98[.]10[.]172:8080` | ip:port | Aisuru | ThreatFox | 2026-11-12 09:33:27 UTC |
| 64 (media) | media | `20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0` | filehash-sha256 | Coinminer | ThreatFox, OTX | 2026-11-13 01:58:30 UTC |
| 64 (media) | media | `3f64b0146b323c5716043360e84384a5a197a897f46088df93a910470a29e1a0` | filehash-sha256 | Nitol | ThreatFox, OTX | 2026-11-13 01:58:28 UTC |
| 64 (media) | media | `34[.]18[.]174[.]25` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-12 21:14:53 UTC |
| 61 (media) | media | `136[.]85[.]24[.]197` | ipv4 | php.shin\_webshell | ThreatFox | 2026-11-13 03:57:39 UTC |
| 60 (media) | critica | `8[.]163[.]98[.]217:8090` | ip:port | Cobalt Strike | ThreatFox | 2026-11-12 14:05:04 UTC |
| 60 (media) | alta | `035d9999050019ecb044f05b345bdaafc911b021b2abfe6af2f1065a9fdf6e36` | filehash-sha256 | Mirai | ThreatFox | 2026-11-12 12:58:21 UTC |
| 60 (media) | critica | `106[.]12[.]61[.]28:10888` | ip:port | Cobalt Strike | ThreatFox | 2026-11-12 12:05:06 UTC |
| 60 (media) | alta | `141[.]98[.]10[.]157:8080` | ip:port | Aisuru | ThreatFox | 2026-11-12 09:38:38 UTC |
| 60 (media) | media | `4e2698b61750624535ba607d27d1ef1f177057bc13f8901dac4855a84254dd2a` | filehash-sha256 | AMOS | ThreatFox | 2026-11-12 06:48:44 UTC |
| 59 (media) | alta | `644666fdd1ac8d48b2da2e748071618d7b15775123fb9e4415983a20102fc492` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-13 03:58:54 UTC |
| 59 (media) | alta | `fce50aa60ebdf3689d49d05793eb37357e4f7c79a6835ddfc7e8ee1ee2828ebb` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-13 03:58:52 UTC |
| 59 (media) | alta | `2267e9622966d11d5674e8e6c67a6837ffea526ed515c0fc968ea197b652401f` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-13 03:58:51 UTC |
| 59 (media) | alta | `3ec4e0fe5a9a6f1d364db3ad8cb3444c48b0c7101b01a7a1cb4b7f60a8a7b325` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-13 03:58:50 UTC |
| 59 (media) | alta | `858b4b96d1796319b27cf6b482323dccef89db578208dd3cb33f70a45984382d` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-13 03:58:49 UTC |

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

### Avisos de seguridad de los últimos 7 días

**452** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **56** de algo que ya se explota · **16** de día cero · **48** sin parche

**Lo más citado:** CVE-2026-111497 (6 fuentes, KEV) · CVE-2026-119618 (6 fuentes) · CVE-2026-124194 (4 fuentes, KEV) · CVE-2026-125350 (4 fuentes, KEV) · CVE-2026-123158 (4 fuentes, KEV) · CVE-2026-19868 (4 fuentes, KEV) · CVE-2026-20320 (4 fuentes, KEV) · CVE-2026-109618 (3 fuentes, KEV)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-12 | Cisco | [Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20and%20Brotli%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-12 | BleepingComputer | [New N-able "4EverAble2Shell" zero-day exploited hours after PoC released](https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/) | explotada, día cero |
| 2026-11-12 | BleepingComputer | [Apache HTTP Server patches critical HTTP/2 remote code execution flaw](https://www.bleepingcomputer.com/news/security/apache-http-server-patches-critical-http-2-remote-code-execution-flaw/) | crítica |
| 2026-11-12 | CERT-EU | [2026-020: Critical Vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway](https://cert.europa.eu/publications/security-advisories/2026-020/) | crítica |
| 2026-11-12 | The Hacker News | [New SignDrop Zero-Day Exploit Turns Windows CLFS Security Feature Into SYSTEM Access](https://thehackernews.com/2026/11/new-signdrop-zero-day-exploit-turns.html) | explotada, día cero |
| 2026-11-12 | Cisco | [Cisco BroadWorks Out-of-Band Blind XML External Entity Injection Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bworks-xxe-uwUd7CEt?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20BroadWorks%20Out-of-Band%20Blind%20XML%20External%20Entity%20Injection%20Vulnerability%26vs_k=1) | explotada |
| 2026-11-12 | Wordfence (WordPress) | [Wordfence Intelligence Weekly WordPress Vulnerability Report (November 2, 2026 to November 8, 2026)](https://www.wordfence.com/blog/2026/11/wordfence-intelligence-weekly-wordpress-vulnerability-report-november-2-2026-to-november-8-2026/) | sin parche, crítica |
| 2026-11-12 | The Hacker News | [Critical Red Hat Quay Flaw Lets Attackers Read and Overwrite All Private Container Images in a Registry](https://thehackernews.com/2026/11/critical-red-hat-quay-flaw-lets.html) | crítica |
| 2026-11-12 | BleepingComputer | [New Windows SignDrop zero-day gives hackers SYSTEM privileges](https://www.bleepingcomputer.com/news/security/new-windows-signdrop-zero-day-gives-hackers-system-privileges/) | explotada, día cero |
| 2026-11-12 | Microsoft | [CVE-2026-111497 Google: CVE-2026-111497 Buffer overflow vulnerability in the Brotli decoder](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111497) | explotada |
| 2026-11-12 | SecurityWeek | [Apache Patches Critical HTTP Server RCE Found by Anthropic, Google](https://www.securityweek.com/apache-patches-critical-http-server-rce-found-by-anthropic-google/) | crítica |
| 2026-11-12 | Segu-Info | [Falla crítica en el módulo HTTP/2 de Apache (CVE-2026-119618) permite ejecución remota de código sin autentica](http://blog.segu-info.com.ar/2026/11/falla-critica-en-el-modulo-http2-de.html) | sin parche, crítica |
| 2026-11-12 | Wordfence (WordPress) | [PSA: Critical Apache HTTP/2 Vulnerability: What WordPress Site Owners Should Know](https://www.wordfence.com/blog/2026/11/cve-2026-119618-apache-http2/) | crítica |
| 2026-11-12 | CISA | [Siemens Desigo, Gridscale](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-02) | explotada |
| 2026-11-12 | CISA | [Siemens RUGGEDCOM APE1808](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-05) | explotada |
| 2026-11-12 | CISA | [Siemens RUGGEDCOM APE1808](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-04) | explotada |
| 2026-11-12 | CISA | [Siemens Building Automation and Energy Products](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-01) | explotada, sin parche |
| 2026-11-12 | CISA | [Siemens Industrial Edge Management](https://www.cisa.gov/news-events/ics-advisories/icsa-26-316-03) | explotada, sin parche |
| 2026-11-12 | Segu-Info | [Actualizaciones de seguridad de NOVIEMBRE para todas las empresas](http://blog.segu-info.com.ar/2026/11/actualizaciones-de-seguridad-de.html) | explotada, día cero, crítica |
| 2026-11-12 | The Hacker News | [PTC Patches Critical Windchill and FlexPLM Flaw That Could Enable Remote Code Execution](https://thehackernews.com/2026/11/ptc-patches-critical-windchill-and.html) | crítica |
| 2026-11-12 | SecurityWeek | [Hackers Target N-central Zero-Days as N-able Rushes Patches](https://www.securityweek.com/hackers-target-n-central-zero-days-as-n-able-rushes-patches/) | explotada, día cero |
| 2026-11-12 | The Hacker News | [Critical Pre-Auth MongoDB Flaw (CVE-2026-118383) Can Crash Lagging Servers on Failover](https://thehackernews.com/2026/11/critical-pre-auth-mongodb-flaw-cve-2026.html) | crítica |
| 2026-11-12 | SecurityWeek | [Critical Red Hat Quay Vulnerability Could Expose Private Container Images](https://www.securityweek.com/critical-red-hat-quay-vulnerability-could-expose-private-container-images/) | crítica |
| 2026-11-12 | INCIBE-CERT | [Desbordamiento de búfer en EOS de Arista](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/desbordamiento-de-bufer-en-eos-de-arista) | crítica |
| 2026-11-12 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos de Helmholz](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-de-helmholz-3) | explotada |

### Vulnerabilidades de los últimos 7 días

**4898** CVE publicados · **4** ya explotados · **64** urgentes · **333** con CVSS ≥ 9 · **570** paquetes maliciosos en los registros · **1** con exploit en Exploit-DB · **3** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-124194 | Microsoft | 6.5 | 1.6 % | 2026-11-10 |
| explotada | CVE-2026-125350 | Google | 8.8 | 1.0 % | 2026-11-10 |
| explotada | CVE-2026-123218 | IBM | 9.8 | 0.5 % | 2026-11-07 |
| explotada | CVE-2026-19868 | SonicWall | 7.5 | 0.5 % | 2026-11-06 |
| urgente | CVE-2026-12507 | — | 9.1 | 9.4 % | 2026-11-12 |
| urgente | CVE-2026-124580 | — | 9.3 | 2.8 % | 2026-11-09 |
| urgente | CVE-2026-126148 | Fortinet | 9.8 | 2.4 % | 2026-11-11 |
| urgente | CVE-2026-123270 | — | 9.8 | 2.4 % | 2026-11-09 |
| urgente | CVE-2026-118066 | WordPress (plugins) | 9.1 | 2.3 % | 2026-11-07 |
| urgente | CVE-2026-121653 | Ivanti | 9.8 | 2.0 % | 2026-11-10 |
| urgente | CVE-2026-17402 | IBM | 9.9 | 1.9 % | 2026-11-07 |
| urgente | CVE-2026-123488 | — | 9.3 | 1.9 % | 2026-11-06 |
| urgente | CVE-2026-126187 | Código abierto (GitHub) | 9.5 | 1.8 % | 2026-11-10 |
| urgente | CVE-2026-12591 | — | 9.9 | 1.7 % | 2026-11-12 |
| urgente | CVE-2026-122193 | — | 9.3 | 1.6 % | 2026-11-06 |
| urgente | CVE-2026-59105 | Microsoft | 9.3 | 1.4 % | 2026-11-06 |
| urgente | CVE-2026-114630 | WordPress (plugins) | 9.1 | 1.3 % | 2026-11-06 |
| urgente | CVE-2026-121349 | Adobe | 9.6 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-119958 | Microsoft | 9.8 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-113579 | Adobe | 9.9 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-113580 | Adobe | 9.9 | 1.3 % | 2026-11-10 |
| urgente | CVE-2026-121892 | Adobe | 9.9 | 1.2 % | 2026-11-10 |
| urgente | CVE-2026-126065 | Código abierto (GitHub) | 9.8 | 1.2 % | 2026-11-10 |
| urgente | CVE-2026-121887 | Adobe | 9.9 | 1.2 % | 2026-11-10 |
| urgente | CVE-2026-116945 | Microsoft | 9.8 | 1.2 % | 2026-11-10 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 505 | 4 / 14 |
| Python (PyPI) | 🔴 paquetes maliciosos | 53 | 6 / 9 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 2 |
| .NET (C#) (NuGet) | 🟠 avisos críticos | 0 | 2 / 23 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 0 / 0 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 8 / 14 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 4 | 0 / 0 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 8 | 1 / 6 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Software empresarial | 🔴 explotación activa | 556 | 87 | 4 |
| Windows y Microsoft | 🔴 explotación activa | 1144 | 31 | 1 |
| Aplicaciones web y CMS | 🔴 explotación activa | 823 | 61 | 3 |
| Red, VPN y firewalls | 🔴 explotación activa | 160 | 32 | 11 |
| Navegadores | 🔴 explotación activa | 199 | 15 | 1 |
| Virtualización y nube | 🔴 explotación activa | 30 | 3 | 1 |
| Linux | 🔴 explotación activa | 141 | 6 | 1 |
| Servidores y servicios | 🔴 explotación activa | 126 | 0 | 5 |
| Apple (macOS · iOS) | 🔴 explotación activa | 13 | 1 | 1 |
| Industrial (OT · ICS) | 🔴 explotación activa | 6 | 1 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Otros | 🔴 explotación activa | 1350 | 67 | 7 |
| Librerías de código abierto | 🟠 riesgo alto | 300 | 25 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 34 | 4 | 0 |
| Android | 🟢 vigilar | 10 | 0 | 0 |
| IA y agentes (LLM · MCP) | 🟢 vigilar | 6 | 0 | 0 |
<!-- CTI:END -->
