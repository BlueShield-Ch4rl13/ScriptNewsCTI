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
                            estado histórico (data/ioc_state.json)
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


Niveles: **alta** ≥70 · **media** 40–69 · **baja** <40.

## Gravedad

Dimensión independiente del score: el score mide *cuánto fiarse del indicador*; la gravedad, *el impacto de la amenaza si es real*. Un IOC puede ser score bajo + gravedad crítica (mención única y antigua de LockBit) o score alto + gravedad media (URL de payload confirmadísima).

| Gravedad | Criterio |
|---|---|
| **crítica** | ransomware (LockBit, Akira, RansomHub…) y frameworks C2 (Cobalt Strike, Sliver, Havoc, AdaptixC2…) |
| **alta** | RATs, stealers, loaders y botnets — familias conocidas o categoría genérica en el nombre («X Stealer», «Unknown RAT»…) |
| **media** | resto de amenazas identificadas, o desconocidas con ratio de detecciones VT ≥ 0,3 |
| **baja** | sin familia identificada ni señal externa |

Las listas viven en `SEV_CRITICA` / `SEV_ALTA` / `SEV_ALTA_GENERICAS` de `enrich.py` y se amplían según aparecen familias nuevas en los feeds.

## Enriquecimiento externo y límites

- **GeoIP**: base [DB-IP Country Lite](https://db-ip.com) (CC BY 4.0), sin registro ni clave. Se descarga bajo demanda (~10 MB) al directorio temporal del runner y los lookups son offline: sin límites, cubre todas las IPs.
- **VirusTotal** (4 req/min · 500/día en plan gratuito): 40 lookups por ejecución con pausa de 15,5 s.
- **AbuseIPDB** (1.000 checks/día): 150 IPs por ejecución.
- Los resultados se **cachean 7 días** en `data/ioc_state.json` y siempre se prioriza lo nuevo. Sin claves, el pipeline sigue funcionando con fusión + confianza del feed + frescura + gravedad + GeoIP.

Ajustable vía variables de entorno en el workflow: `VT_BUDGET`, `ABUSEIPDB_BUDGET`, `CTI_RECHECK_DAYS`, `CTI_RETENTION_DAYS`, `CTI_MAX_STATE`.

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
pip install -r requirements.txt
export ABUSECH_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"          # opcional
export VT_API_KEY="tu_clave"           # opcional
export ABUSEIPDB_API_KEY="tu_clave"    # opcional
python main.py
```

## Estructura

```
├── .github/workflows/cti-update.yml   # cron + auto-commit (concurrency + rebase anti-carreras)
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── enrich.py                          # fusión, estado histórico, GeoIP, reputación, score y gravedad
├── utils.py                           # defang, export JSON/CSV, README autogenerado
├── index.html + assets/               # dashboard estático (Cloudflare Pages)
└── data/                              # iocs_latest.json / .csv + ioc_state.json (estado)
```
---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-10-06 00:06 UTC · **IOCs recolectados:** 2214 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 72 (alta) | alta | `107[.]172[.]132[.]240:1312` | ip:port | Mirai | ThreatFox | 2026-10-05 09:27:09 UTC |
| 71 (alta) | alta | `2af2d82ac1b143dc3858f394d64142b313190a8a8bf3ab5c4398c8746a700ec5` | sha256_hash | Overlord RAT | ThreatFox | 2026-10-05 13:46:42 UTC |
| 71 (alta) | alta | `176[.]65[.]139[.]235:313` | ip:port | Mirai | ThreatFox | 2026-10-05 12:09:37 UTC |
| 71 (alta) | alta | `94[.]154[.]43[.]30:695` | ip:port | Mirai | ThreatFox | 2026-10-05 06:15:17 UTC |
| 70 (alta) | alta | `700982a7340b326fd1fb402dfab1d7991eb9ff85ba06437457f182ae9f041a88` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:05 UTC |
| 70 (alta) | alta | `e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:04 UTC |
| 70 (alta) | alta | `2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:03 UTC |
| 70 (alta) | alta | `2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:02 UTC |
| 70 (alta) | alta | `daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:01 UTC |
| 69 (media) | alta | `b3ee99af1e9dc43036a5832b6aa4fbf6ac995bcea2d6fce9e933b2ee74550411` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:02 UTC |
| 69 (media) | alta | `7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:46:56 UTC |
| 69 (media) | alta | `273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:00 UTC |
| 69 (media) | alta | `90c6e31dbd3d092caef01ed472ef25717a4e8bf40d0ac842b7163ef9286860fe` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:34 UTC |
| 69 (media) | alta | `bf1702f8d7b7a938d05f5e776ba28d60e2421f4b74cb671fb510028f8a80fb5f` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:33 UTC |
| 69 (media) | alta | `5aefe115dc06827f878068f6f30470ddcc2aa53b5ad441224ba00b75169a9892` | sha256_hash | Mirai | ThreatFox | 2026-10-05 06:15:46 UTC |
| 68 (media) | alta | `bacd686528120d6216a3354cb4e3aebc16c6eb4e3795bd514d63d748a6098df5` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:04 UTC |
| 68 (media) | alta | `3acb3901111c81c4204026c3fea5dfd7d3e78c019fd35422f98e42db058ba98d` | sha256_hash | Mirai | ThreatFox | 2026-10-05 23:47:01 UTC |
| 68 (media) | alta | `e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:06 UTC |
| 68 (media) | alta | `a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:47:05 UTC |
| 68 (media) | alta | `7649fa641422a292db1a245106f9bca00180c05a6e959c4aa1301d44e51fb499` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:44 UTC |
| 68 (media) | alta | `b46644ea431174016fac2b1e03e241ec72188f6fecd3a15bf709fd1282e1a64d` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:43 UTC |
| 68 (media) | alta | `003987d241c631fa85c008638c51f0b402b864fd41b1cff2d05803ac8df41d16` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:40 UTC |
| 68 (media) | alta | `cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:36 UTC |
| 68 (media) | alta | `f7ad68eccd67f1c2785c24cd627a5da4463aa2f319a5540cbe58afad7a5a3dd5` | sha256_hash | Mirai | ThreatFox | 2026-10-05 13:46:31 UTC |
| 68 (media) | alta | `dc22c37cc0ae4a88717cdcd54df18a42e09f85c682189f58e77ddd722b5ee3ee` | sha256_hash | Mirai | ThreatFox | 2026-10-05 06:15:48 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-88779 | Citrix NetScaler | 2026-10-04 | Unknown |
| CVE-2026-102490 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-102489 | Zammad GmbH Zammad | 2026-10-02 | Unknown |
| CVE-2026-104286 | Fortinet FortiMail | 2026-10-01 | Unknown |
| CVE-2026-76504 | Cisco Catalyst SD-WAN Manager | 2026-09-30 | Unknown |
| CVE-2026-86950 | Apple Multiple Products | 2026-09-29 | Unknown |
| CVE-2026-88772 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-88771 | Citrix NetScaler | 2026-09-27 | Unknown |
| CVE-2026-67279 | MikroTik RouterOS | 2026-09-25 | Unknown |
| CVE-2026-65660 | Microsoft SharePoint | 2026-09-25 | Unknown |
| CVE-2026-87902 | WordPress Core | 2026-09-25 | Unknown |
| CVE-2026-5430 | WSO2 Multiple Products | 2026-09-24 | Unknown |
| CVE-2026-71362 | Adobe Commerce and Magento  | 2026-09-24 | Unknown |
| CVE-2026-93952 | Arista VeloCloud Orchestrator | 2026-09-22 | Unknown |
| CVE-2026-94127 | F5 BIG-IP APM | 2026-09-22 | Unknown |
| CVE-2026-93616 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-85102 | Check Point Multiple Products | 2026-09-22 | Unknown |
| CVE-2026-7273 | Zyxel GS1900 Series Switches | 2026-09-21 | Unknown |
<!-- CTI:END -->
