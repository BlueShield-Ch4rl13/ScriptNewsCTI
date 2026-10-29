# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Plataforma ligera de **Cyber Threat Intelligence** que se actualiza sola cada 3 horas mediante GitHub Actions. Responde a cuatro preguntas:

- **¿Qué fallos de seguridad están saliendo?** Los avisos de los últimos 7 días de **26 fuentes**: fabricantes (Microsoft, Cisco, Fortinet, Palo Alto, Ivanti, Chrome, Siemens…), CERT y gobiernos (**INCIBE-CERT**, CISA, CERT-EU, CERT-FR, CERT/CC), exploits e investigación (Zero Day Initiative, Exploit-DB, Project Zero, Wordfence) y noticias de vulnerabilidades (Una al Día, Segu-Info, The Hacker News…). Cada aviso se cruza con CISA KEV y EPSS y se marca si ya se explota, si es de día cero o si sale sin parche.
- **¿Qué CVE nuevos importan?** Los de la última semana (NVD), ordenados por **explotación real** y no solo por CVSS: primero lo que ya se explota (CISA KEV, SSVC de CISA), después lo que más probablemente se explotará (FIRST EPSS, o un exploit publicado en Exploit-DB) y por último la gravedad. Cada CVE dice si tiene exploit público, si lo usa el ransomware, si se explotó desde el primer día y qué avisos lo citan.
- **¿Está en riesgo mi sistema?** Por tipo de sistema (Windows, Linux, Apple, Android, navegadores, red y VPN, routers e IoT, virtualización y nube, IA y agentes, industrial…): CVE nuevos, críticos y explotación activa en los últimos 30 días.
- **¿Está comprometido mi lenguaje?** Por lenguaje (JavaScript, Python, Java, .NET, PHP, Go, Rust, Ruby…): si **el propio lenguaje** (intérprete o runtime) tiene CVE explotados, y cuántos **paquetes maliciosos** y avisos graves han aparecido en su registro (npm, PyPI, Maven…).

Además recolecta IOCs de feeds públicos, los **fusiona entre fuentes**, los enriquece (GeoIP, VirusTotal, AbuseIPDB) y calcula un **score de confianza** y una **gravedad** por indicador. Todo se publica en un dashboard estático, en este README y en `data/` (JSON + CSV), y sale también hacia otras herramientas: **feed Atom** de los avisos importantes, **feed de MISP** con los IOCs, **alertas** a un webhook (n8n → Telegram) y un **histórico diario** con gráficas de tendencia. En el panel, cada visitante puede guardar su **lista de vigilancia** (productos y fabricantes) y ver qué avisos y CVE de la semana la citan.

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
**Última actualización:** 2026-10-29 23:13 UTC · **IOCs recolectados:** 2510 · **CVEs KEV recientes:** 19

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 80 (alta) | media | `85[.]137[.]54[.]178:18082` | ip:port | Unknown malware | ThreatFox | 2026-10-29 14:32:44 UTC |
| 78 (alta) | media | `80[.]87[.]206[.]86:443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 14:32:44 UTC |
| 76 (alta) | media | `176[.]123[.]7[.]7:443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 14:32:44 UTC |
| 75 (alta) | media | `160[.]119[.]71[.]27:80` | ip:port | Unknown malware | ThreatFox | 2026-10-29 14:48:12 UTC |
| 71 (alta) | media | `146[.]190[.]103[.]76:443` | ip:port | Jackskid | ThreatFox | 2026-10-29 06:33:19 UTC |
| 68 (media) | alta | `157[.]66[.]225[.]224:7707` | ip:port | AsyncRAT | ThreatFox | 2026-10-29 05:19:21 UTC |
| 66 (media) | alta | `159[.]203[.]28[.]151:8002` | ip:port | Aisuru | ThreatFox | 2026-10-29 16:54:41 UTC |
| 62 (media) | media | `104[.]248[.]206[.]134:36275` | ip:port | Drifter | ThreatFox | 2026-10-29 16:51:42 UTC |
| 61 (media) | media | `46[.]101[.]249[.]247:36275` | ip:port | Drifter | ThreatFox | 2026-10-29 13:48:46 UTC |
| 59 (media) | media | `130[.]254[.]45[.]8:443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 17:28:19 UTC |
| 59 (media) | media | `138[.]68[.]134[.]9:36275` | ip:port | Drifter | ThreatFox | 2026-10-29 13:48:45 UTC |
| 58 (media) | media | `157[.]230[.]122[.]72:32505` | ip:port | Drifter | ThreatFox | 2026-10-29 16:51:42 UTC |
| 58 (media) | media | `38[.]127[.]244[.]12:18081` | ip:port | Unknown malware | ThreatFox | 2026-10-29 14:32:44 UTC |
| 58 (media) | media | `103[.]39[.]79[.]102:8443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 05:05:06 UTC |
| 57 (media) | media | `156[.]246[.]90[.]214:443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 17:28:20 UTC |
| 57 (media) | media | `178[.]83[.]206[.]213:443` | ip:port | Unknown malware | ThreatFox | 2026-10-29 17:28:20 UTC |
| 57 (media) | media | `135[.]136[.]191[.]231:2222` | ip:port | Unknown malware | ThreatFox | 2026-10-29 17:28:19 UTC |
| 57 (media) | media | `152[.]42[.]135[.]240:34532` | ip:port | Drifter | ThreatFox | 2026-10-29 13:48:45 UTC |
| 57 (media) | media | `8[.]138[.]27[.]20:8084` | ip:port | VShell | ThreatFox | 2026-10-29 12:05:04 UTC |
| 57 (media) | media | `119[.]42[.]148[.]189:2333` | ip:port | VShell | ThreatFox | 2026-10-29 05:05:07 UTC |
| 56 (media) | alta | `hxxps://c[.]bb69[.]org/m/` | url | Vidar | ThreatFox | 2026-10-29 23:00:49 UTC |
| 56 (media) | alta | `hxxps://c[.]bb69[.]org/o/` | url | Vidar | ThreatFox | 2026-10-29 22:30:48 UTC |
| 56 (media) | alta | `hxxps://fastly[.]jsdelivr[.]net/gh/sdedyk172/ad8f6908-5019-42ff-a88e-b8279bfaed84/9cc8ac42-ee34-4250-bfee-d893438a3b3b` | url | ClearFake | ThreatFox | 2026-10-29 12:08:30 UTC |
| 56 (media) | media | `hxxp://45[.]225[.]135[.]233/2/config[.]json` | url | XMRIG | ThreatFox | 2026-10-29 06:11:51 UTC |
| 56 (media) | media | `89[.]32[.]41[.]114:23789` | ip:port | Potassium | ThreatFox | 2026-10-29 03:49:51 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-102764 | BeyondTrust Remote Support | 2026-10-16 | Unknown |
| CVE-2025-61624 | Fortinet Multiple Products | 2026-10-16 | Unknown |
| CVE-2026-21589 | Atlassian Multiple Products | 2026-10-15 | Unknown |

### Avisos de seguridad de los últimos 7 días

**294** avisos de 26/26 fuentes (fabricantes, CERT, exploits y noticias) · **66** de algo que ya se explota · **7** de día cero · **34** sin parche

**Lo más citado:** CVE-2026-109618 (9 fuentes, KEV) · CVE-2026-111497 (9 fuentes, KEV) · CVE-2026-109619 (8 fuentes, KEV) · CVE-2026-76418 (5 fuentes, KEV) · CVE-2026-105482 (4 fuentes) · CVE-2026-105483 (4 fuentes) · CVE-2026-106069 (4 fuentes) · CVE-2026-115560 (2 fuentes)

| Fecha | Fuente | Aviso | Señales |
|---|---|---|---|
| 2026-10-29 | Wordfence (WordPress) | [WordPress 7.1.4 Patches Unauthenticated Upgrade-Window RCE; Exploitation Attempts Detected After Release](https://www.wordfence.com/blog/2026/10/wordpress-7-1-4-security-release-rce/) | explotada, sin parche |
| 2026-10-29 | Cisco | [Vulnerabilities in Node.js Affecting Cisco Products: October 2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Vulnerabilities%20in%20Node.js%20Affecting%20Cisco%20Products:%20October%202026%26vs_k=1) | explotada |
| 2026-10-29 | The Hacker News | [ThreatsDay: Critical Firewall Flaws, Banking Trojans Rented, Weaponized PDF, Token Theft + 26 More Stories](https://thehackernews.com/2026/10/threatsday-critical-firewall-flaws.html) | crítica |
| 2026-10-29 | BleepingComputer | [Hackers exploit Cisco SD-WAN flaw to deploy custom KeyDrift malware](https://www.bleepingcomputer.com/news/security/hackers-exploit-cisco-sd-wan-flaw-to-deploy-custom-keydrift-malware/) | explotada |
| 2026-10-29 | Ubuntu | [USN-8958-1: .NET vulnerabilities](https://ubuntu.com/security/notices/USN-8958-1) | explotada |
| 2026-10-29 | Wordfence (WordPress) | [Wordfence Intelligence Weekly WordPress Vulnerability Report (October 19, 2026 to October 25, 2026)](https://www.wordfence.com/blog/2026/10/wordfence-intelligence-weekly-wordpress-vulnerability-report-october-19-2026-to-october-25-2026/) | sin parche, crítica |
| 2026-10-29 | SecurityWeek | [Adobe, Veeam, Juniper Networks Patch Critical Vulnerabilities](https://www.securityweek.com/adobe-veeam-juniper-networks-patch-critical-vulnerabilities/) | crítica |
| 2026-10-29 | CISA | [CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog) | explotada |
| 2026-10-29 | BleepingComputer | [New Cisco firewall zero-day exploited to crash SSL VPN devices](https://www.bleepingcomputer.com/news/security/cisco-warns-of-firewall-zero-day-exploited-to-crash-ssl-vpn-devices/) | explotada, día cero |
| 2026-10-29 | The Hacker News | [Cisco Patches Actively Exploited ASA and FTD VPN Flaw That Can Crash Firewalls](https://thehackernews.com/2026/10/cisco-patches-actively-exploited-asa.html) | explotada |
| 2026-10-29 | SecurityWeek | [Cisco SD-WAN Zero-Day Exploitation Tied to Volt Typhoon’s ‘Silent Train’ Network](https://www.securityweek.com/cisco-sd-wan-zero-day-exploitation-tied-to-volt-typhoons-silent-train-network/) | explotada, día cero |
| 2026-10-29 | SecurityWeek | [Attackers Exploit Second Cisco Firewall VPN Zero-Day Since August](https://www.securityweek.com/attackers-exploit-second-cisco-firewall-vpn-zero-day-since-august/) | explotada, día cero |
| 2026-10-29 | The Hacker News | [Attacker Tried to Exploit Alpine Linux’s GitLab via CVSS 10.0 Flaw Its Ruby Left Open](https://thehackernews.com/2026/10/attacker-tried-to-exploit-alpine-linuxs.html) | explotada |
| 2026-10-29 | INCIBE-CERT | [Escritura fuera de límites en PHP para Windows](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/escritura-fuera-de-limites-en-php-para-windows) | explotada |
| 2026-10-29 | INCIBE-CERT | [Múltiples vulnerabilidades en OpenScape Endpoint Management de Mitel](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-openscape-endpoint-management-de-mitel) | explotada |
| 2026-10-29 | INCIBE-CERT | [Múltiples vulnerabilidades en productos de Cisco](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-productos-de-cisco-20) | explotada |
| 2026-10-29 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en productos de Schneider Electric](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-productos-de-schneider-14) | explotada |
| 2026-10-29 | INCIBE-CERT · industrial | [Múltiples vulnerabilidades en OCTO Image Server de Mettler Toledo](https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/multiples-vulnerabilidades-en-octo-image-server-de-mettler-toledo) | explotada |
| 2026-10-29 | The Hacker News | [Hackers Exploited Cisco SD-WAN Flaw to Plant Malware Built to Steal Encryption Keys](https://thehackernews.com/2026/10/hackers-exploited-cisco-sd-wan-flaw-to.html) | explotada |
| 2026-10-29 | The Hacker News | [China-Linked Hackers Exploited VMware ESX Zero-Day to Reduce Audit Trail Visibility](https://thehackernews.com/2026/10/china-linked-hackers-exploited-vmware.html) | explotada, día cero |
| 2026-10-29 | The Hacker News | [Attackers Exploit PHP2Shell Flaws in Internet-Exposed Palo Alto Networks Management Interfaces](https://thehackernews.com/2026/10/attackers-exploit-php2shell-flaws-in.html) | explotada |
| 2026-10-29 | Palo Alto Networks | [CVE-2026-111497 Portfolio Status: Impact of Brotli Vulnerability (CVE-2026-111497) on Palo Alto Networks Produ](https://security.paloaltonetworks.com/CVE-2026-111497) | explotada, crítica |
| 2026-10-29 | Palo Alto Networks | [CVE-2026-109618 Impact of Critical Vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619) on Palo Alto Netw](https://security.paloaltonetworks.com/CVE-2026-109618) | explotada, crítica |
| 2026-10-29 | Zero Day Initiative | [ZDI-26-846: MLflow Webhook Server-Side Request Forgery Vulnerability](http://www.zerodayinitiative.com/advisories/ZDI-26-846/) | explotada |
| 2026-10-29 | CERT-FR · avisos | [Vulnérabilité dans les produits Cisco (29 octobre 2026)](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1412/) | explotada |

### Vulnerabilidades de los últimos 7 días

**3246** CVE publicados · **1** ya explotados · **19** urgentes · **241** con CVSS ≥ 9 · **334** paquetes maliciosos en los registros · **0** con exploit en Exploit-DB · **1** explotados desde el primer día

Prioridad: *explotada* (CISA KEV o SSVC «active») > *urgente* (EPSS ≥ 10 %, o CVSS ≥ 9 con EPSS ≥ 1 % o prueba de concepto) > *alta* (CVSS ≥ 7, percentil EPSS ≥ 90 o PoC). Un exploit de Exploit-DB cuenta como prueba de concepto.

| Prioridad | CVE | Fabricante | CVSS | EPSS | Publicado |
|---|---|---|---|---|---|
| explotada | CVE-2026-76418 | Cisco | 8.6 | 0.6 % | 2026-10-28 |
| urgente | CVE-2026-116505 | TOTOLINK | 9.1 | 2.7 % | 2026-10-26 |
| urgente | CVE-2026-116485 | — | 9.8 | 2.3 % | 2026-10-26 |
| urgente | CVE-2026-116506 | TOTOLINK | 9.9 | 1.9 % | 2026-10-26 |
| urgente | CVE-2026-115995 | Unitree | 9.4 | 1.4 % | 2026-10-24 |
| urgente | CVE-2026-112352 | — | 9.1 | 1.3 % | 2026-10-27 |
| urgente | CVE-2026-104353 | Adobe | 9.9 | 1.3 % | 2026-10-27 |
| urgente | CVE-2026-110879 | — | 9.8 | 1.2 % | 2026-10-28 |
| urgente | CVE-2026-53921 | Código abierto (GitHub) | 9.8 | 1.1 % | 2026-10-23 |
| urgente | CVE-2026-82119 | — | 9.8 | 1.0 % | 2026-10-27 |
| urgente | CVE-2026-112346 | — | 9.8 | 1.0 % | 2026-10-26 |
| urgente | CVE-2026-107092 | Nexopos | 9.8 | 0.9 % | 2026-10-26 |
| urgente | CVE-2026-63190 | Código abierto (GitHub) | 9.4 | 0.5 % | 2026-10-28 |
| urgente | CVE-2026-57116 | Código abierto (GitHub) | 9.8 | 0.4 % | 2026-10-23 |
| urgente | CVE-2026-31158 | — | 9.8 | 0.4 % | 2026-10-26 |
| urgente | CVE-2026-116111 | 2K | 9.6 | 0.3 % | 2026-10-26 |
| urgente | CVE-2026-54630 | Código abierto (GitHub) | 9.6 | 0.2 % | 2026-10-23 |
| urgente | CVE-2026-107058 | — | 9.8 | — | 2026-10-29 |
| urgente | CVE-2026-107015 | — | 9.1 | — | 2026-10-29 |
| urgente | CVE-2026-107032 | — | 9.1 | — | 2026-10-29 |
| alta | CVE-2026-86379 | — | 7.2 | 2.8 % | 2026-10-28 |
| alta | CVE-2026-112351 | — | 8.8 | 2.7 % | 2026-10-27 |
| alta | CVE-2026-86394 | — | 7.2 | 2.2 % | 2026-10-28 |
| alta | CVE-2026-86395 | — | 7.2 | 2.2 % | 2026-10-28 |
| alta | CVE-2026-86399 | — | 7.2 | 2.2 % | 2026-10-28 |

### Lenguajes (registros de paquetes, últimos 7 días)

| Lenguaje | Estado | Paquetes maliciosos | Avisos críticos / altos |
|---|---|---|---|
| JavaScript / TypeScript (npm) | 🔴 paquetes maliciosos | 244 | 7 / 57 |
| Python (PyPI) | 🔴 paquetes maliciosos | 89 | 9 / 59 |
| Java / Kotlin (Maven) | 🟡 avisos altos | 0 | 0 / 5 |
| .NET (C#) (NuGet) | 🟡 avisos altos | 0 | 0 / 1 |
| PHP (Packagist) | 🔴 el lenguaje se explota | 0 | 1 / 7 |
| Go (Go modules) | 🟠 avisos críticos | 0 | 1 / 13 |
| Rust (crates.io) | 🟠 avisos críticos | 0 | 3 / 5 |
| Ruby (RubyGems) | 🔴 paquetes maliciosos | 1 | 0 / 1 |
| Erlang / Elixir (Hex) | 🟢 sin alertas | 0 | 0 / 0 |
| Dart / Flutter (pub.dev) | 🟢 sin alertas | 0 | 0 / 0 |
| Swift (SwiftPM) | 🟢 sin alertas | 0 | 0 / 0 |
| GitHub Actions (Marketplace) | 🟢 sin alertas | 0 | 0 / 0 |

### Sistemas

| Sistema | Estado | CVE nuevos | CVSS ≥ 9 | En KEV (30 días) |
|---|---|---|---|---|
| Aplicaciones web y CMS | 🔴 explotación activa | 695 | 75 | 2 |
| Software empresarial | 🔴 explotación activa | 99 | 17 | 4 |
| Red, VPN y firewalls | 🔴 explotación activa | 29 | 5 | 9 |
| Linux | 🔴 explotación activa | 379 | 4 | 1 |
| Apple (macOS · iOS) | 🔴 explotación activa | 335 | 0 | 1 |
| Windows y Microsoft | 🔴 explotación activa | 76 | 8 | 1 |
| Virtualización y nube | 🔴 explotación activa | 21 | 3 | 1 |
| Servidores y servicios | 🔴 explotación activa | 2 | 0 | 4 |
| Industrial (OT · ICS) | 🔴 explotación activa | 2 | 0 | 1 |
| Lenguajes y entornos de ejecución | 🔴 explotación activa | 0 | 0 | 2 |
| Otros | 🔴 explotación activa | 959 | 85 | 10 |
| Librerías de código abierto | 🟠 riesgo alto | 349 | 24 | 0 |
| Routers domésticos, IoT y cámaras | 🟠 riesgo alto | 26 | 5 | 0 |
| Navegadores | 🟠 riesgo alto | 232 | 12 | 0 |
| IA y agentes (LLM · MCP) | 🟠 riesgo alto | 31 | 2 | 0 |
| Android | 🟠 riesgo alto | 11 | 1 | 0 |
<!-- CTI:END -->
