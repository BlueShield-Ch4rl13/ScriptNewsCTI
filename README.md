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
**Última actualización:** 2026-11-25 16:50 UTC · **IOCs recolectados:** 2117 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 74 (alta) | media | `aa7c5b35fe6f11638419c613e6c8242c33db363606bca397f286c04ba279f2e1` | filehash-sha256 | WannaCryptor | ThreatFox | 2026-11-25 06:23:58 UTC |
| 74 (alta) | alta | `102[.]220[.]163[.]98:777` | ip:port | DCRat | ThreatFox | 2026-11-25 03:05:09 UTC |
| 73 (alta) | media | `202[.]170[.]75[.]111:56001` | ip:port | PureRAT | ThreatFox | 2026-11-24 19:44:11 UTC |
| 71 (alta) | media | `176[.]65[.]132[.]19:8787` | ip:port | Unknown malware | ThreatFox | 2026-11-25 00:24:14 UTC |
| 67 (media) | media | `e522ad3c93901305749d60fe60e07953658827734c5a5329909c4d7832204de0` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-25 03:16:37 UTC |
| 66 (media) | media | `67e3e110e752e10863cb6baa0942e8db2fb16934b0e3511decbd18aaedc72c68` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-25 03:16:37 UTC |
| 64 (media) | media | `42b15b3be8f3b98bdee095f3a208bfe0a29cece161125aa2635bb00472dc2f69` | filehash-sha256 | SNOWLIGHT | ThreatFox | 2026-11-25 03:00:38 UTC |
| 63 (media) | alta | `fa975f82f37e597184b7ffee1273ede6141bd04d8c99fb1265db9681760486e0` | filehash-sha256 | Mirai | ThreatFox | 2026-11-25 03:00:40 UTC |
| 63 (media) | alta | `448369ba26cc8fb4cb3930cfee0ebf6adc0195d611cac139d99aac26660f9589` | filehash-sha256 | Mirai | ThreatFox | 2026-11-25 03:00:39 UTC |
| 62 (media) | alta | `95[.]153[.]32[.]186:62411` | ip:port | PureLogs Stealer | ThreatFox | 2026-11-25 13:24:24 UTC |
| 62 (media) | alta | `dee6b58c120562685044d1108e963c39cfd9cecec71049299a0fe68d693674e8` | filehash-sha256 | Mirai | ThreatFox | 2026-11-25 03:00:44 UTC |
| 62 (media) | alta | `fcbf362c7f4909010e496a27f9383303aa6384ab3a06ac13533d96b66178c0a8` | filehash-sha256 | Mirai | ThreatFox | 2026-11-25 03:00:43 UTC |
| 62 (media) | alta | `a81c994cfc2d00af1a6c0bc6791124bdc2719283e61d9314ccea97fd2bb3b685` | filehash-sha256 | Mirai | ThreatFox | 2026-11-25 03:00:41 UTC |
| 61 (media) | alta | `91[.]240[.]165[.]44:48222` | ip:port | Mirai | ThreatFox | 2026-11-25 16:10:28 UTC |
| 61 (media) | media | `hxxp://182[.]117[.]155[.]67:50821/bin[.]sh` | url | Mozi | ThreatFox, URLhaus | 2026-11-25 12:18:37 UTC |
| 61 (media) | media | `hxxp://182[.]117[.]155[.]67:50821/i` | url | Mozi | ThreatFox, URLhaus | 2026-11-25 12:18:33 UTC |
| 61 (media) | media | `45[.]133[.]73[.]7:8787` | ip:port | Unknown malware | ThreatFox | 2026-11-25 00:21:30 UTC |
| 61 (media) | alta | `9c3528ea42fe31a9979a1517e5898249e0e73d093354b63d81320dab61b0b924` | filehash-sha256 | Unknown Loader | ThreatFox | 2026-11-24 19:00:34 UTC |
| 58 (media) | alta | `195[.]3[.]222[.]3:80` | ip:port | Stealc | ThreatFox | 2026-11-25 16:10:35 UTC |
| 57 (media) | media | `195[.]177[.]94[.]18:8787` | ip:port | Unknown malware | ThreatFox | 2026-11-25 16:22:39 UTC |
| 57 (media) | alta | `ss[.]asianwins[.]com` | domain | Vidar | ThreatFox | 2026-11-25 03:05:34 UTC |
| 57 (media) | alta | `46[.]246[.]12[.]7:8090` | ip:port | DCRat | ThreatFox | 2026-11-25 03:05:09 UTC |
| 57 (media) | alta | `gue[.]asdselot[.]org` | domain | Vidar | ThreatFox | 2026-11-25 02:25:34 UTC |
| 57 (media) | alta | `m9y[.]asianwins[.]com` | domain | Vidar | ThreatFox | 2026-11-24 19:05:34 UTC |
| 56 (media) | media | `425d5b3fee2c9662dfac980de9d3d9e750b32ae095f44f0a65af9f7f1172204b` | filehash-sha256 | Unknown malware | ThreatFox | 2026-11-25 16:35:13 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-103406 | Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router | 2026-11-25 | Unknown |
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
| CVE-2026-90436 | Apache Axis | 2026-11-18 | Unknown |
| CVE-2026-115731 | Perforce Puppet Enterprise | 2026-11-17 | Unknown |
| CVE-2026-114713 | UnrealIRCd UnrealIRCd | 2026-11-13 | Unknown |
| CVE-2026-123039 | Check Point Multiple Products | 2026-11-13 | Unknown |

### Avisos de seguridad de los últimos 7 días

**395** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **40** de algo que ya se explota · **13** de día cero · **20** sin parche

**Lo más citado:** CVE-2026-123007 (9 fuentes) · CVE-2026-114938 (7 fuentes) · CVE-2026-123633 (7 fuentes) · CVE-2026-126714 (5 fuentes) · CVE-2026-113425 (5 fuentes) · CVE-2026-115560 (5 fuentes) · CVE-2026-121810 (5 fuentes) · CVE-2026-123634 (5 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-11-25 | BleepingComputer | [CISA warns of critical unpatched flaw in Danfoss refrigeration controllers](https://www.bleepingcomputer.com/news/security/cisa-warns-of-critical-unpatched-flaw-in-danfoss-refrigeration-controllers/) | sin parche, crítica |
| 2026-11-25 | The Hacker News | [Hackers Exploit Two GeoServer Flaws as Researchers Warn of Unauthenticated RCE Chains](https://thehackernews.com/2026/11/hackers-exploit-two-geoserver-flaws-as.html) | explotada |
| 2026-11-25 | The Hacker News | [Drupal Fail2Install Exploit Details Emerge as Critical RCE Flaw Faces Active Exploitation](https://thehackernews.com/2026/11/drupal-fail2install-exploit-details.html) | explotada, crítica |
| 2026-11-25 | BleepingComputer | [Hackers now exploit critical Drupal RCE flaw to hijack sites](https://www.bleepingcomputer.com/news/security/hackers-now-exploit-critical-drupal-rce-flaw-to-hijack-sites/) | explotada, sin parche, crítica |
| 2026-11-25 | The Hacker News | [Hackers Exploited CVSS 10.0 Hex.pm RCE Flaw to Compromise 6 Package Registry Servers](https://thehackernews.com/2026/11/hackers-exploited-cvss-100-hexpm-rce.html) | explotada |
| 2026-11-25 | SecurityWeek | [Hackers Exploit Unpatched Flaw in Defunct Idunno AntiCsrf Library](https://www.securityweek.com/hackers-exploit-unpatched-flaw-in-defunct-idunno-anticsrf-library/) | explotada, sin parche, crítica |
| 2026-11-25 | INCIBE-CERT | [Múltiples vulnerabilidades en Serv-U de SolarWinds](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-serv-u-de-solarwinds-0) | crítica |
| 2026-11-25 | SecurityWeek | [Drupal Flaw Found by Anthropic Scanner Exploited in Attacks](https://www.securityweek.com/drupal-flaw-found-by-anthropic-scanner-exploited-in-attacks/) | explotada |
| 2026-11-25 | CERT-FR · avisos | [Vulnérabilité dans Palo Alto Networks PAN-OS (25 novembre 2026)](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1621/) | explotada |
| 2026-11-24 | Palo Alto Networks | [CVE-2026-123633 Portfolio Status: Impact of NGINX Vulnerabilities (CVE-2026-123633, CVE-2026-123007) on Palo A](https://security.paloaltonetworks.com/CVE-2026-123633) | crítica |
| 2026-11-24 | Cisco | [Vulnerabilities in Node.js and Brotli Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20and%20Brotli%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-11-24 | Cisco | [Vulnerability in PHP Affecting Cisco Products: November 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-phpaftershell-nov-2026-kT9pL4Xe?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerability%20in%20PHP%20Affecting%20Cisco%20Products:%20November%202026%26vs_k=1) | crítica |
| 2026-11-24 | SecurityWeek | [VMware Updates Patch Critical ESX, vCenter Vulnerabilities](https://www.securityweek.com/vmware-updates-patch-critical-esx-vcenter-vulnerabilities/) | crítica |
| 2026-11-24 | Microsoft | [CVE-2026-112732 Microsoft Office Visio Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-112732) | crítica |
| 2026-11-24 | The Hacker News | [VMware vCenter Hit by Another Critical 9.8-Rated Auth Bypass Flaw After Zero-Day Exploitation](https://thehackernews.com/2026/11/vmware-vcenter-hit-by-another-critical.html) | explotada, día cero, crítica |
| 2026-11-24 | Segu-Info | [Explotan una vulnerabilidad crítica en biblioteca Anti-CSRF de ASP.NET, permite RCE sin autenticación](http://blog.segu-info.com.ar/2026/11/explotan-una-vulnerabilidad-critica-en.html) | explotada, crítica |
| 2026-11-24 | CISA | [CISA Adds Three Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/11/24/cisa-adds-three-known-exploited-vulnerabilities-catalog) | explotada, crítica |
| 2026-11-24 | CISA | [Danfoss AK-SM 8xxA Series](https://www.cisa.gov/news-events/ics-advisories/icsa-26-328-03) | crítica |
| 2026-11-24 | CISA | [AutomationDirect C-More EA9 Programming Software](https://www.cisa.gov/news-events/ics-advisories/icsa-26-328-01) | día cero |
| 2026-11-24 | INCIBE-CERT | [Múltiples vulnerabilidades en productos VMware Tanzu de Broadcom](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-vmware-tanzu-de-broadcom) | explotada, crítica |
| 2026-11-24 | INCIBE-CERT | [Condición de carrera en la gestión de sesiones PHP en productos de Cisco](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/condicion-de-carrera-en-la-gestion-de-sesiones-php-en-productos-de-cisco) | crítica |
| 2026-11-24 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos de Wiesemann &amp; Theis](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-de-wiesemann-theis) | explotada |
| 2026-11-24 | INCIBE-CERT · industrial | [Falta de autenticación en cámaras industriales de ifm](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/falta-de-autenticacion-en-camaras-industriales-de-ifm) | crítica |
| 2026-11-24 | The Hacker News | [Hackers Exploit N-able MailAssure Flaw While AI Agents Exploit MONAI Label Zero-Day](https://thehackernews.com/2026/11/hackers-exploit-n-able-mailassure-flaw.html) | explotada, día cero |
| 2026-11-24 | Zero Day Initiative | [ZDI-26-1129: (Pwn2Own) Oracle Autonomous AI Database APEX Password Change External Control of Critical State V](http://www.zerodayinitiative.com/advisories/ZDI-26-1129/) | crítica |

### Vulnerabilidades de los últimos 7 días

**4269** CVE publicados · **4** ya explotados · **94** urgentes · **313** con CVSS ≥ 9 · **653** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **2** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-133968 | Project MONAI | 9.8 | 27.2 % | 2026-11-20 |
| explotada | CVE-2026-123890 | Broadcom | 9.8 | 5.0 % | 2026-11-19 |
| explotada | CVE-2026-131914 | Idunno | 9.8 | 4.3 % | 2026-11-19 |
| explotada | CVE-2026-134624 | N-able | 8.7 | 1.8 % | 2026-11-22 |
| urgente | CVE-2026-115560 | — | 9.2 | 86.6 % | 2026-11-19 |
| urgente | CVE-2026-126714 | — | 9.2 | 33.8 % | 2026-11-19 |
| urgente | CVE-2026-129289 | — | 9.2 | 24.8 % | 2026-11-19 |
| urgente | CVE-2026-129474 | — | 9.2 | 21.2 % | 2026-11-19 |
| urgente | CVE-2026-129538 | — | 6.9 | 12.8 % | 2026-11-19 |
| urgente | CVE-2026-129496 | — | 9.2 | 11.1 % | 2026-11-19 |
| urgente | CVE-2026-127027 | — | 9.2 | 7.6 % | 2026-11-20 |
| urgente | CVE-2026-129481 | — | 9.2 | 6.4 % | 2026-11-19 |
| urgente | CVE-2026-133493 | D-Link | 9.3 | 4.2 % | 2026-11-20 |
| urgente | CVE-2026-114516 | Código abierto (GitHub) | 9.8 | 4.1 % | 2026-11-19 |
| urgente | CVE-2026-132622 | — | 9.4 | 3.7 % | 2026-11-19 |
| urgente | CVE-2026-135789 | D-Link | 9.1 | 3.6 % | 2026-11-24 |
| urgente | CVE-2026-103788 | — | 9.6 | 3.3 % | 2026-11-23 |
| urgente | CVE-2026-134882 | TOTOLINK | 10.0 | 3.2 % | 2026-11-23 |
| urgente | CVE-2026-73969 | Código abierto (GitHub) | 9.8 | 3.0 % | 2026-11-18 |
| urgente | CVE-2026-136550 | Tenda | 9.1 | 3.0 % | 2026-11-25 |
| urgente | CVE-2026-135202 | WordPress (plugins) | 9.8 | 2.7 % | 2026-11-24 |
| urgente | CVE-2026-65817 | Microsoft | 9.6 | 2.7 % | 2026-11-23 |
| urgente | CVE-2026-133680 | D-Link | 9.9 | 2.6 % | 2026-11-20 |
| urgente | CVE-2026-133323 | — | 10.0 | 2.5 % | 2026-11-19 |
| urgente | CVE-2026-135796 | — | 9.9 | 2.5 % | 2026-11-24 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 614 | 5 / 12 |
| Python (PyPI) | 🔴 paquetes maliciosos | 31 | 3 / 23 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 6 |
| .NET (C#) (NuGet) | 🟠 avisos críticos | 0 | 3 / 3 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 3 / 9 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 4 / 20 |
| Rust (crates.io) | 🔴 paquetes maliciosos | 1 | 1 / 6 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 7 | 1 / 0 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Windows y Microsoft | 🔴 explotación activa | 41 | 15 | 1 |
| Software empresarial | 🔴 explotación activa | 235 | 33 | 6 |
| Aplicaciones web y CMS | 🔴 explotación activa | 991 | 45 | 3 |
| Linux | 🔴 explotación activa | 555 | 14 | 1 |
| Navegadores | 🔴 explotación activa | 126 | 19 | 1 |
| Virtualización y nube | 🔴 explotación activa | 45 | 4 | 2 |
| Red, VPN y firewalls | 🔴 explotación activa | 178 | 8 | 10 |
| Servidores y servicios | 🔴 explotación activa | 52 | 2 | 1 |
| Apple (macOS · iOS) | 🔴 explotación activa | 20 | 3 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Otros | 🔴 explotación activa | 1682 | 119 | 12 |
| Librerías de código abierto | 🟠 riesgo alto | 289 | 38 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 26 | 11 | 0 |
| IA y agentes (LLM · MCP) | 🟠 riesgo alto | 22 | 2 | 0 |
| Android | 🟢 vigilar | 5 | 0 | 0 |
| Industrial (OT · ICS) | 🟢 vigilar | 2 | 0 | 0 |
<!-- CTI:END -->
