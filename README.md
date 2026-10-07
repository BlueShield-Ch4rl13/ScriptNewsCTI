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
**Última actualización:** 2026-10-07 13:13 UTC · **IOCs recolectados:** 1797 · **CVEs KEV recientes:** 13

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 76 (alta) | media | `89[.]32[.]41[.]19:7193` | ip:port | Potassium | ThreatFox | 2026-10-06 21:19:56 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:42061` | ip:port | Potassium | ThreatFox | 2026-10-07 06:28:53 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:38429` | ip:port | Potassium | ThreatFox | 2026-10-07 03:26:54 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:27651` | ip:port | Potassium | ThreatFox | 2026-10-07 02:29:02 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:23789` | ip:port | Potassium | ThreatFox | 2026-10-07 00:24:39 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:49376` | ip:port | Potassium | ThreatFox | 2026-10-06 23:21:55 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]19:15987` | ip:port | Potassium | ThreatFox | 2026-10-06 16:57:12 UTC |
| 75 (alta) | media | `89[.]32[.]41[.]49:7193` | ip:port | Potassium | ThreatFox | 2026-10-06 16:03:36 UTC |
| 74 (alta) | media | `89[.]32[.]41[.]43:23789` | ip:port | Potassium | ThreatFox | 2026-10-07 08:33:30 UTC |
| 74 (alta) | media | `89[.]32[.]41[.]43:7193` | ip:port | Potassium | ThreatFox | 2026-10-07 07:22:50 UTC |
| 72 (alta) | alta | `139[.]162[.]5[.]254:3778` | ip:port | Mirai | ThreatFox | 2026-10-06 14:30:45 UTC |
| 64 (media) | media | `89[.]32[.]41[.]128:27651` | ip:port | Potassium | ThreatFox | 2026-10-07 06:28:52 UTC |
| 64 (media) | media | `89[.]32[.]41[.]128:7193` | ip:port | Potassium | ThreatFox | 2026-10-07 03:45:22 UTC |
| 64 (media) | critica | `45[.]227[.]253[.]132:8080` | ip:port | Cobalt Strike | ThreatFox | 2026-10-06 15:05:05 UTC |
| 64 (media) | critica | `45[.]227[.]253[.]132:443` | ip:port | Cobalt Strike | ThreatFox | 2026-10-06 15:05:04 UTC |
| 64 (media) | critica | `45[.]227[.]253[.]132:80` | ip:port | Cobalt Strike | ThreatFox | 2026-10-06 15:05:04 UTC |
| 60 (media) | media | `91[.]92[.]242[.]19:7193` | ip:port | Potassium | ThreatFox | 2026-10-06 15:17:46 UTC |
| 60 (media) | critica | `45[.]227[.]253[.]132:32775` | ip:port | Cobalt Strike | ThreatFox | 2026-10-06 13:45:58 UTC |
| 59 (media) | media | `6111a10b82cc1bf6bac1082bc8ffa36e9f3123f0feb811aac281278a7fe63e13` | sha256_hash | AMOS | ThreatFox | 2026-10-07 11:44:51 UTC |
| 59 (media) | media | `49f19199c38499498aa4dead3e19102c6679192fe282e72ec024b19191d8ae63` | sha256_hash | AMOS | ThreatFox | 2026-10-07 11:08:02 UTC |
| 59 (media) | media | `ext-checkedin[.]vercel[.]app` | domain | ContagiousDrop | ThreatFox | 2026-10-07 10:38:35 UTC |
| 59 (media) | media | `tailwind-version-4[.]vercel[.]app` | domain | ContagiousDrop | ThreatFox | 2026-10-07 10:38:34 UTC |
| 59 (media) | media | `thopywork[.]vercel[.]app` | domain | ContagiousDrop | ThreatFox | 2026-10-07 10:38:34 UTC |
| 59 (media) | media | `vscode-bootstrapper[.]vercel[.]app` | domain | ContagiousDrop | ThreatFox | 2026-10-07 10:38:33 UTC |
| 59 (media) | media | `vscode-config-setting[.]vercel[.]app` | domain | ContagiousDrop | ThreatFox | 2026-10-07 10:38:33 UTC |

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
<!-- CTI:END -->
