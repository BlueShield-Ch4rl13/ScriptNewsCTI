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
| Frescura | ×1,0 ≤7 días · ×0,85 ≤30 · ×0,6 ≤90 · ×0,3 resto |

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

## Troubleshooting

- **El workflow no commitea**: revisa *Settings → Actions → General → Workflow permissions* y marca *Read and write permissions*.
- **ThreatFox/URLhaus devuelven 401/403**: falta o es inválida la `ABUSECH_API_KEY`.
- **Score o gravedad en «—» en la web**: los datos publicados los generó una versión antigua del pipeline; comprueba que `main.py` importa `enrich` y relanza *CTI Update*.
- **Reputación en «—»**: faltan `VT_API_KEY` / `ABUSEIPDB_API_KEY`; el log del run lo confirma (`VirusTotal omitido: falta VT_API_KEY`).
- **El run tarda ~10 minutos**: normal con VirusTotal activo (rate limit del plan gratuito) — no lo canceles.
- **Push rechazado (`fetch first`)**: usa la versión actual del workflow, que serializa ejecuciones y rebasa antes de publicar.
- **El cron deja de ejecutarse**: GitHub pausa los schedules tras 60 días sin actividad; los commits del bot cuentan como actividad, así que con que funcione no se pausará.

---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-07-24 14:06 UTC · **IOCs recolectados:** 1043 · **CVEs KEV recientes:** 18

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| 71 (alta) | alta | `5cc694a33b659fb6c6e18633daea040c` | md5_hash | Vidar | ThreatFox | 2026-07-24 01:06:37 UTC |
| 71 (alta) | alta | `c118f7037676c76b39d05c16c337158c0d714decee91af1c44f41c899233b265` | sha256_hash | Vidar | ThreatFox | 2026-07-24 01:06:36 UTC |
| 71 (alta) | alta | `c2b2ecfe88e5555a73cd3d893d369b1640b626bd` | sha1_hash | Vidar | ThreatFox | 2026-07-24 01:06:36 UTC |
| 68 (media) | alta | `5a43ccbb36c23176b99cb7727d338f43319f353f` | sha1_hash | Vidar | ThreatFox | 2026-07-24 01:06:39 UTC |
| 68 (media) | alta | `e006cb0220146177e684c11e8548ab39` | md5_hash | Vidar | ThreatFox | 2026-07-24 01:06:39 UTC |
| 68 (media) | alta | `3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c` | sha256_hash | Vidar | ThreatFox | 2026-07-24 01:06:38 UTC |
| 67 (media) | media | `18b3741afc2712dafb56505b1c1822372b35cc0b` | sha1_hash | Kuiper | ThreatFox | 2026-07-24 01:06:42 UTC |
| 67 (media) | media | `a20052c78501ce91feba8ce56a3aa665` | md5_hash | Kuiper | ThreatFox | 2026-07-24 01:06:42 UTC |
| 67 (media) | media | `366e52b6d95d9478a73ffcd659a1807bdea901a0737b7b2532fe11145be03925` | sha256_hash | Kuiper | ThreatFox | 2026-07-24 01:06:41 UTC |
| 67 (media) | alta | `afc61229018541efa19cd9affa1aeb72` | md5_hash | ValleyRAT | ThreatFox | 2026-07-24 01:06:38 UTC |
| 67 (media) | alta | `98f5e6cc01bd74709e63639e75a6e4d68b6c5fb9654ae97490155792888bebdd` | sha256_hash | ValleyRAT | ThreatFox | 2026-07-24 01:06:37 UTC |
| 67 (media) | alta | `b6cbc4017ed864b21917e3604c6e5f57d2e9ed0a` | sha1_hash | ValleyRAT | ThreatFox | 2026-07-24 01:06:37 UTC |
| 66 (media) | media | `56091719eeba4881f3db1f837feaa9d47a5a275bff6218186d97614e252e6d21` | sha256_hash | Kuiper | ThreatFox | 2026-07-24 01:06:40 UTC |
| 66 (media) | media | `432375fba1147d8880a98b149fe7f8f2e4f78d1a` | sha1_hash | Kuiper | ThreatFox | 2026-07-24 01:06:40 UTC |
| 66 (media) | media | `9f3955f8be35326246e2551754bd6d5e` | md5_hash | Kuiper | ThreatFox | 2026-07-24 01:06:40 UTC |
| 65 (media) | media | `ce629f8ad9428474bab4b95774102a13b096f516` | sha1_hash | Coinminer | ThreatFox | 2026-07-24 01:06:41 UTC |
| 65 (media) | media | `9f95d8290bd17c8319a2f3b47db6bd75` | md5_hash | Coinminer | ThreatFox | 2026-07-24 01:06:41 UTC |
| 65 (media) | media | `694a3bab92e60e6760649fd40e97c04ff03faded2073e7a0c2e061229bf7820a` | sha256_hash | Coinminer | ThreatFox | 2026-07-24 01:06:40 UTC |
| 59 (media) | critica | `8[.]134[.]70[.]73:8082` | ip:port | Cobalt Strike | ThreatFox | 2026-07-23 18:05:05 UTC |
| 58 (media) | media | `221[.]132[.]16[.]23:8000` | ip:port | Unknown malware | ThreatFox | 2026-07-24 13:05:11 UTC |
| 58 (media) | critica | `8[.]140[.]239[.]162:3000` | ip:port | Cobalt Strike | ThreatFox | 2026-07-24 13:05:05 UTC |
| 58 (media) | media | `47[.]108[.]140[.]10:20884` | ip:port | Unknown malware | ThreatFox | 2026-07-23 18:05:06 UTC |
| 57 (media) | critica | `8[.]137[.]170[.]3:22` | ip:port | Cobalt Strike | ThreatFox | 2026-07-24 02:05:08 UTC |
| 57 (media) | critica | `8[.]137[.]170[.]3:8443` | ip:port | Cobalt Strike | ThreatFox | 2026-07-24 02:05:08 UTC |
| 57 (media) | critica | `8[.]137[.]170[.]3:8080` | ip:port | Cobalt Strike | ThreatFox | 2026-07-24 02:05:07 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-16232 | Check Point SmartConsole | 2026-07-22 | Unknown |
| CVE-2026-50522 | Microsoft SharePoint | 2026-07-22 | Unknown |
| CVE-2026-60137 | WordPress Core | 2026-07-21 | Unknown |
| CVE-2026-63030 | WordPress Core | 2026-07-21 | Unknown |
| CVE-2026-0770 | Langflow Langflow | 2026-07-21 | Unknown |
| CVE-2021-27137 | DD-WRT DD-WRT | 2026-07-21 | Unknown |
| CVE-2026-58644 | Microsoft SharePoint | 2026-07-16 | Unknown |
| CVE-2026-25089 | Fortinet FortiSandbox | 2026-07-16 | Unknown |
| CVE-2026-39808 | Fortinet FortiSandbox | 2026-07-16 | Unknown |
| CVE-2026-46817 | Oracle E-Business Suite | 2026-07-15 | Unknown |
| CVE-2023-4346 | KNX Association KNX Protocol Connection Authorization Option 1 | 2026-07-15 | Unknown |
| CVE-2026-56155 | Microsoft Active Directory Federation Services | 2026-07-14 | Unknown |
| CVE-2026-56164 | Microsoft SharePoint Server | 2026-07-14 | Unknown |
| CVE-2026-15409 | SonicWall SMA1000 Appliances | 2026-07-14 | Unknown |
| CVE-2026-15410 | SonicWall SMA1000 Appliances | 2026-07-14 | Unknown |
| CVE-2008-4128 | Cisco IOS | 2026-07-13 | Unknown |
| CVE-2026-56291 | Balbooa Forms | 2026-07-10 | Unknown |
| CVE-2026-48939 | iCagenda iCagenda | 2026-07-10 | Unknown |
<!-- CTI:END -->
