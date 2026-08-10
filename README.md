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
**Última actualización:** 2026-08-10 13:31 UTC · **IOCs recolectados:** 682 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 80 (alta) | media | `130[.]12[.]180[.]51:43782` | ip:port | RedTail | ThreatFox | 2026-08-10 06:17:50 UTC |
| 76 (alta) | alta | `161[.]35[.]48[.]40:12345` | ip:port | Aisuru | ThreatFox | 2026-08-10 12:49:42 UTC |
| 76 (alta) | alta | `161[.]35[.]48[.]40:9034` | ip:port | Aisuru | ThreatFox | 2026-08-10 06:18:08 UTC |
| 71 (alta) | critica | `1441b32780ec0e76d09af693f62819c2d1ae8125` | sha1_hash | Havoc | ThreatFox | 2026-08-10 11:49:10 UTC |
| 71 (alta) | critica | `33d103a950e97fb4c0f28d8cff985ba6` | md5_hash | Havoc | ThreatFox | 2026-08-10 11:49:10 UTC |
| 71 (alta) | critica | `904bb06ad9ad3c8e4aa980b96cbecad85c14bd994af013d77121723c85a5e1a9` | sha256_hash | Havoc | ThreatFox | 2026-08-10 11:49:09 UTC |
| 70 (alta) | alta | `c829ecdfad04daba449fb93106f176c5fd065f3642b70cc46ab4285246a3057d` | sha256_hash | Creal Stealer | ThreatFox | 2026-08-10 11:49:06 UTC |
| 70 (alta) | alta | `40bb4c848b9e8843d48884ded074af0dc183778d` | sha1_hash | Creal Stealer | ThreatFox | 2026-08-10 11:49:06 UTC |
| 68 (media) | alta | `2a167fbe58a9d874dda8798e9b0d773d9316a217256a7e3f1d0c5e3e26f9f03a` | sha256_hash | PureRAT | ThreatFox | 2026-08-10 11:49:07 UTC |
| 68 (media) | alta | `666974fd5ab2ab200c8c87e1945708c9e4f2e76e` | sha1_hash | PureRAT | ThreatFox | 2026-08-10 11:49:07 UTC |
| 68 (media) | alta | `325dd213f9a6f78e41cad30c49e0a178` | md5_hash | PureRAT | ThreatFox | 2026-08-10 11:49:07 UTC |
| 67 (media) | alta | `0e260f328a81040da84f79bb21d54953` | md5_hash | PureRAT | ThreatFox | 2026-08-10 11:49:09 UTC |
| 67 (media) | alta | `965974f7bb6bd5c71da7d0ae843ea3f84229b74c` | sha1_hash | PureRAT | ThreatFox | 2026-08-10 11:49:08 UTC |
| 67 (media) | alta | `da9442ac1174544216a00fb1792f7ee019cb708e47cd5948a9632e24285b36cb` | sha256_hash | PureRAT | ThreatFox | 2026-08-10 11:49:07 UTC |
| 66 (media) | alta | `180[.]93[.]116[.]41:56999` | ip:port | Mirai | ThreatFox | 2026-08-10 06:18:01 UTC |
| 64 (media) | media | `de71cf8817c3e91c8a00c22198bb36d6655f00e32741098ae5d81ec09ea69918` | sha256_hash | Kuiper | ThreatFox | 2026-08-10 11:49:11 UTC |
| 64 (media) | media | `5df985e256e32dd57aaac1bad79672fbb44788ea` | sha1_hash | Kuiper | ThreatFox | 2026-08-10 11:49:11 UTC |
| 64 (media) | media | `662d653f550544643f67c3891ff2cf2c` | md5_hash | Kuiper | ThreatFox | 2026-08-10 11:49:11 UTC |
| 64 (media) | media | `158[.]94[.]211[.]92:80` | ip:port | Unknown malware | ThreatFox | 2026-08-10 07:33:28 UTC |
| 61 (media) | media | `hxxps://id-verif-code[.]info/api[.]php` | url | Unknown malware | ThreatFox | 2026-08-10 07:33:29 UTC |
| 61 (media) | media | `hxxp://178[.]16[.]54[.]109/bolodo` | url | Phorpiex | ThreatFox | 2026-08-10 06:18:00 UTC |
| 60 (media) | alta | `91[.]92[.]42[.]22:443` | ip:port | PureRAT | ThreatFox | 2026-08-10 09:46:52 UTC |
| 58 (media) | media | `178[.]62[.]229[.]223:25001` | ip:port | Kimwolf | ThreatFox | 2026-08-10 10:23:25 UTC |
| 58 (media) | media | `hxxps://atomento10[.]icu/t[.]js` | url | Unknown malware | ThreatFox | 2026-08-10 07:33:24 UTC |
| 58 (media) | media | `hxxps://frontalback91[.]icu/t[.]js` | url | Unknown malware | ThreatFox | 2026-08-10 07:33:24 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-8037 | Progress LoadMaster | 2026-08-07 | Unknown |
| CVE-2026-63077 | JetBrains TeamCity | 2026-08-05 | Unknown |
| CVE-2026-18556 | N-able N-central | 2026-08-04 | Unknown |
| CVE-2026-34486 | Apache Tomcat | 2026-08-04 | Unknown |
| CVE-2026-9198 | IBM Langflow | 2026-08-04 | Unknown |
| CVE-2026-18577 | N-able N-central | 2026-08-03 | Unknown |
| CVE-2026-20316 | Cisco Secure Firewall Management Center (FMC) | 2026-07-29 | Unknown |
| CVE-2025-68686 | Fortinet FortiOS | 2026-07-27 | Unknown |
| CVE-2026-16812 | Arista VeloCloud Orchestrator | 2026-07-27 | Unknown |
<!-- CTI:END -->
