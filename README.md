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
**Última actualización:** 2026-10-23 04:24 UTC · **IOCs recolectados:** 2279 · **CVEs KEV recientes:** 15

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 71 (alta) | alta | `85[.]215[.]73[.]250:8080` | ip:port | Mirai | ThreatFox | 2026-10-23 02:06:31 UTC |
| 71 (alta) | media | `89[.]32[.]41[.]49:15987` | ip:port | Potassium | ThreatFox | 2026-10-22 12:02:52 UTC |
| 69 (media) | alta | `a8f5152e9c6da80bff86401c3deb3fb0fc842ebfe4d24b45f48b8f097e377a57` | filehash-sha256 | Unknown Stealer | ThreatFox | 2026-10-22 21:54:51 UTC |
| 68 (media) | media | `34[.]156[.]68[.]110` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-23 03:22:03 UTC |
| 68 (media) | media | `35[.]222[.]239[.]11` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 20:36:05 UTC |
| 68 (media) | media | `35[.]205[.]69[.]67` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 19:25:57 UTC |
| 68 (media) | media | `34[.]97[.]50[.]241` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 13:57:35 UTC |
| 68 (media) | media | `89[.]32[.]41[.]43:27651` | ip:port | Potassium | ThreatFox | 2026-10-22 13:08:20 UTC |
| 68 (media) | media | `34[.]176[.]60[.]3` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 12:56:25 UTC |
| 68 (media) | media | `34[.]12[.]92[.]249` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 12:14:37 UTC |
| 68 (media) | media | `34[.]154[.]182[.]48` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 09:17:54 UTC |
| 66 (media) | media | `144[.]172[.]103[.]188:44831` | ip:port | Unknown malware | ThreatFox | 2026-10-22 15:43:03 UTC |
| 66 (media) | media | `34[.]30[.]171[.]26` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 10:08:04 UTC |
| 65 (media) | media | `217[.]156[.]122[.]208:56003` | ip:port | PureRAT | ThreatFox | 2026-10-22 19:44:40 UTC |
| 65 (media) | media | `35[.]240[.]91[.]34` | ipv4 | php.shin_webshell | ThreatFox | 2026-10-22 10:19:28 UTC |
| 62 (media) | alta | `b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:55:06 UTC |
| 62 (media) | alta | `217[.]60[.]242[.]28:80` | ip:port | Mirai | ThreatFox | 2026-10-22 09:45:07 UTC |
| 61 (media) | alta | `65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:55:04 UTC |
| 61 (media) | alta | `35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:55:00 UTC |
| 61 (media) | media | `209[.]200[.]246[.]18:40517` | ip:port | Unknown malware | ThreatFox | 2026-10-22 15:42:56 UTC |
| 60 (media) | alta | `d9a4f09acbe5baf37d129ddc8a22c25a2fb42c3437667ad676ea3a08e4d0371c` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:55:05 UTC |
| 60 (media) | alta | `a4e00dc0d18a48b71be811a3bd0493f59033a9621815a1a9444ba22c211f7a21` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:54:58 UTC |
| 60 (media) | alta | `0d1f3ea519338a5254c15e409176e54f7f0820bc3da8259eb91cf2306d6df79a` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:54:56 UTC |
| 60 (media) | alta | `7e94feb9c18ef4bec822a5919dc9db603656cf42532742b91be0db25eb4d4f80` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:54:55 UTC |
| 60 (media) | alta | `a1347741490358dfdcf8933b7b38e845f4778244c064ac61548dcf21fa113860` | filehash-sha256 | Mirai | ThreatFox | 2026-10-23 03:54:54 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
