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
**Última actualización:** 2026-10-02 12:24 UTC · **IOCs recolectados:** 1770 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 70 (alta) | alta | `dc17c133c5d7087e6fa11a41cbaabf7cd870b2cf982f02b2df398eb78e408229` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:57 UTC |
| 70 (alta) | media | `771ec7047ca7242266491a67a07b1ad4fe18dcbc6ed4b92c26905090183a196f` | sha256_hash | VShell | ThreatFox | 2026-10-01 12:45:56 UTC |
| 69 (media) | alta | `64ecb45d56f1126d982609f4c9679e3a7db4fea47b90726e28aed6c1555e9331` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:55 UTC |
| 69 (media) | alta | `14adbc5ababc074a0a890804138c8ac4c9be11a70a38456bc11ab625c2194622` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:53 UTC |
| 69 (media) | alta | `7ba88a03067c548f642bb8971f81e266e34281a6b4b42784e5d88f91892daaaa` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:08 UTC |
| 69 (media) | media | `dedad5b693e337a6d6480398e551ad9296a74da18707a5179c9fa2d88fe4bd50` | sha256_hash | VShell | ThreatFox | 2026-10-01 12:45:57 UTC |
| 68 (media) | alta | `dc45540bdad7a5ffc99dbe071dd8803aebb8b85c59b14871e33e58f9096d235d` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:58 UTC |
| 68 (media) | alta | `448bb7bd702777e61ee298cc5b366813dccb872748afdf7f8d462ccd80030f85` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:56 UTC |
| 68 (media) | alta | `f88d65205dbfa7cc6a2570d8dd717159c4c541ad5375d387a0536329f1f9a855` | sha256_hash | Mirai | ThreatFox | 2026-10-02 03:45:48 UTC |
| 68 (media) | alta | `b9a5981e8cc88e30b5a2cc19fdfaddc7292c920c0d780e09dd338b95362e586a` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:09 UTC |
| 68 (media) | alta | `0f4825a816b143a681601528b75aca2092b26026c78141c842b05354e96d8a86` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:07 UTC |
| 68 (media) | alta | `5a21c34ff54ab1a92246b9cfba815ed187fe636b9350d41e26c5e4aa8f4bf891` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:04 UTC |
| 68 (media) | alta | `3ef94abf1e178ac49ddcccd474eb883e248237f2854e220de69216fb3d196a13` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:02 UTC |
| 68 (media) | alta | `cc6f394e7ab43785247b4614076cbcac9a1d47839569de8a81be2ad1bafff7ae` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:45:58 UTC |
| 67 (media) | alta | `9514a4a4a35e00d4b4fc5d137dd09abce68788b36547ae7124f3ce55ac26c0d6` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 10:45:59 UTC |
| 67 (media) | alta | `0cbe5a49a0f02bac48140c58a127624924372679aeef0daa4a2fe61dd35b9893` | sha256_hash | Mirai | ThreatFox | 2026-10-02 04:45:56 UTC |
| 67 (media) | alta | `1c77488c6575124f424f079997b7b4d75c57703ecf80e2adc1820f9efdb223d2` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:46:06 UTC |
| 67 (media) | alta | `4a41ed2bc8172520e42d9fc6221974331cf54974265e171afa727a07068361a8` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-01 12:46:03 UTC |
| 67 (media) | alta | `d297569fc63ec7336886f5e5e9c451c4560bc888d116a9db7706ff90ff44f77d` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-01 12:46:01 UTC |
| 67 (media) | alta | `61c14afa6a0e10bc6bde13bcc16b14ee0be3eaa843306f8096438a2303496e8a` | sha256_hash | Mirai | ThreatFox | 2026-10-01 12:45:59 UTC |
| 65 (media) | alta | `148649970ff9237136b4456bf729afe4c8986a6e705f99752d2a8081dc05c27b` | sha256_hash | Unknown Loader | ThreatFox | 2026-10-02 11:45:54 UTC |
| 65 (media) | critica | `158[.]94[.]210[.]16:2853` | ip:port | Havoc | ThreatFox | 2026-10-02 09:43:42 UTC |
| 64 (media) | alta | `160[.]119[.]76[.]118:443` | ip:port | PureRAT | ThreatFox | 2026-10-01 19:43:44 UTC |
| 62 (media) | critica | `153[.]80[.]242[.]105:3478` | ip:port | Cobalt Strike | ThreatFox | 2026-10-02 08:05:05 UTC |
| 62 (media) | critica | `153[.]80[.]242[.]105:5349` | ip:port | Cobalt Strike | ThreatFox | 2026-10-02 08:05:05 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
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
| CVE-2025-39964 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2026-53266 | Linux Kernel | 2026-09-18 | Unknown |
| CVE-2025-39682 | Linux Kernel | 2026-09-18 | Unknown |
<!-- CTI:END -->
