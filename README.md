# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Plataforma ligera de **Cyber Threat Intelligence** que se actualiza sola cada 6 horas mediante GitHub Actions. Recolecta IOCs de feeds públicos, los **fusiona entre fuentes**, los enriquece (GeoIP, VirusTotal, AbuseIPDB), calcula un **score de confianza** y una **gravedad** por indicador, y publica los resultados en un dashboard estático, en este README y en `data/` (JSON + CSV).

🌐 **Dashboard en vivo:** https://cti.carlosvillalbalagos.com

> ⚠️ Uso exclusivamente defensivo (TLP:CLEAR). Los IOCs se muestran defangueados.

## Fuentes

| Feed | Datos | API key |
|---|---|---|
| ThreatFox (abuse.ch) | IOCs de malware (IP, dominios, URLs, hashes) | Gratuita, obligatoria |
| URLhaus (abuse.ch) | URLs de distribución de malware | Gratuita, obligatoria |
| AlienVault OTX | Indicadores de pulses suscritos | Gratuita, opcional |
| CISA KEV | CVEs explotados activamente | No requiere |
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
GitHub Actions (cron 6h) <── main.py ──> data/*.json|csv + README + dashboard
```

El frontend no realiza ninguna llamada externa: todo el enriquecimiento ocurre en el backend del pipeline y el dashboard solo lee `data/iocs_latest.json`.

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
- **AbuseIPDB** (1.000 checks/día): 150 IPs por ejecución.
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
5. Listo: el cron lo ejecutará cada 6 h (hora UTC) y el bot hará commit de los cambios.

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
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
├── tests/                             # pruebas de fusión, edad, gravedad y depuración
└── data/                              # iocs_latest.json / .csv (el estado va en la caché de Actions)
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-10-24 15:52 UTC · **IOCs recolectados:** 1131 · **CVEs KEV recientes:** 17

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | alta | `176[.]65[.]132[.]7:53` | ip:port | Mirai | ThreatFox | 2026-10-24 11:01:24 UTC |
| 76 (alta) | media | `130[.]12[.]180[.]51:2137` | ip:port | RedTail | ThreatFox | 2026-10-23 16:11:43 UTC |
| 75 (alta) | critica | `92[.]249[.]61[.]190:443` | ip:port | AdaptixC2 | ThreatFox | 2026-10-24 01:05:05 UTC |
| 71 (alta) | media | `176[.]65[.]139[.]201:443` | ip:port | Unknown malware | ThreatFox | 2026-10-24 14:25:37 UTC |
| 71 (alta) | media | `176[.]65[.]139[.]210:9111` | ip:port | Unknown malware | ThreatFox | 2026-10-24 09:59:47 UTC |
| 68 (media) | media | `8[.]229[.]222[.]124` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-24 14:08:44 UTC |
| 68 (media) | media | `35[.]247[.]234[.]209` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-24 12:17:35 UTC |
| 68 (media) | alta | `008391c2f5053f8d6ae93687ff3e646ea3781eb7fceb90dff27662639a7833d1` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:23 UTC |
| 68 (media) | alta | `963a9d98e301b4c546ecf84a34569622a3587b4ca81be30a074c703cdaddccec` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:23 UTC |
| 68 (media) | alta | `30565cd88df5581d1ecb807c7893702baf9489149bc255e72138819a4858c50e` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:22 UTC |
| 68 (media) | alta | `384f6102f832c8275043e227cd628da323968fe0cb7b9bce68be4568f55dfea7` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:22 UTC |
| 68 (media) | alta | `e43dc4bc7e0f09e409ab641af90e41ed761d61d548a42abafe1d9cb90f4e9fd5` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:22 UTC |
| 68 (media) | alta | `dd9f2de148a4e974260ad1441e52d2206a9094189774caec8de819c5e203fad5` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:21 UTC |
| 68 (media) | alta | `f4d9d45b6bfb977488816e89020c7db4b8c31a6e0c55931946e510d497e466c2` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:20 UTC |
| 68 (media) | alta | `e10e3b26f909615328ede9691d24bb8df37fa5cc5569905d3e314483e90d0b6d` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:20 UTC |
| 68 (media) | alta | `8b6c459d683d473363105270cfbf29d0f5eff90c54e3c797dc64cb7cc92004f1` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:19 UTC |
| 68 (media) | alta | `8a0c2c6c2fca4e2b6bbf0d8f60b4d6dc1f7812d12caffca203abe755c6a78ff2` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:19 UTC |
| 68 (media) | alta | `fb00431d5355efeebfd795b39b770a8b1368fea5500f765101d72b876348fd0d` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:17 UTC |
| 68 (media) | alta | `55d54c40098e920a1e8ab3bb45a61dffea9ad1c22d2451090ee90beff366aff9` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:17 UTC |
| 68 (media) | media | `34[.]79[.]59[.]9` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-24 10:56:28 UTC |
| 68 (media) | media | `34[.]174[.]99[.]7` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-24 04:23:33 UTC |
| 68 (media) | media | `34[.]97[.]57[.]138` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-24 04:01:41 UTC |
| 68 (media) | media | `89[.]32[.]41[.]43:38429` | ip:port | Potassium | ThreatFox | 2026-10-23 23:37:37 UTC |
| 68 (media) | media | `b8ddba517ded94631018d0b877d23fcdc94ea4a2244bb9e3c7795433fd11604a` | filehash-sha256 | SmartLoader | ThreatFox | 2026-10-23 20:55:03 UTC |
| 67 (media) | alta | `e7d3b33ad533a7214a730c74b1b55bbf867ec0ef59bedd295aabb3761f1129b0` | filehash-sha256 | Mirai | ThreatFox | 2026-10-24 11:01:17 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2026-105134 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-76519 | Cisco Secure Email Gateway | 2026-10-14 | Unknown |
| CVE-2026-105133 | Ahsay AhsayCBS | 2026-10-14 | Unknown |
| CVE-2026-0322 | Palo Alto Networks PAN-OS | 2026-10-14 | Unknown |
| CVE-2026-104935 | Ivanti Connect Secure | 2026-10-13 | Unknown |
| CVE-2026-96951 | Microsoft Windows | 2026-10-13 | Unknown |
<!-- CTI:END -->
