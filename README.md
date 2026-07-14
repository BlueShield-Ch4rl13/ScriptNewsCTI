# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Pipeline de **Cyber Threat Intelligence** que se actualiza solo cada 6 horas mediante GitHub Actions. Recolecta IOCs de feeds públicos, los normaliza, deduplica y defanguea, y publica los resultados en este README y en `data/` (JSON + CSV).

> ⚠️ Uso exclusivamente defensivo (TLP:CLEAR). Los IOCs se muestran defangueados.

## Fuentes

| Feed | Datos | API key |
|---|---|---|
| ThreatFox (abuse.ch) | IOCs de malware (IP, dominios, URLs, hashes) | Gratuita, obligatoria |
| URLhaus (abuse.ch) | URLs de distribución de malware | Gratuita, obligatoria |
| AlienVault OTX | Indicadores de pulses suscritos | Gratuita, opcional |
| CISA KEV | CVEs explotados activamente | No requiere |

## Arquitectura

```
feeds públicos ──> collectors.py ──> normalización + dedupe + defang (utils.py)
                                          │
GitHub Actions (cron 6h) <── main.py ──> data/*.json|csv + README autogenerado
```

## Puesta en marcha

1. Crea un repo en GitHub y sube este contenido.
2. Consigue las claves gratuitas:
   - **abuse.ch**: regístrate en https://auth.abuse.ch y genera tu *Auth-Key* (sirve para ThreatFox y URLhaus).
   - **OTX** (opcional): crea cuenta en https://otx.alienvault.com y copia tu API key del perfil.
3. En el repo: *Settings → Secrets and variables → Actions → New repository secret*:
   - `ABUSECH_API_KEY`
   - `OTX_API_KEY` (opcional)
4. Pestaña **Actions** → workflow *CTI Update* → **Run workflow** para la primera ejecución manual.
5. Listo: el cron lo ejecutará cada 6 h (hora UTC) y el bot hará commit de los cambios.

### Ejecución local

```bash
pip install -r requirements.txt
export ABUSECH_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"      # opcional
python main.py
```

## Estructura

```
├── .github/workflows/cti-update.yml   # cron + auto-commit
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── utils.py                           # defang, dedupe, export, README
└── data/                              # iocs_latest.json / iocs_latest.csv
```

## Troubleshooting

- **El workflow no commitea**: revisa *Settings → Actions → General → Workflow permissions* y marca *Read and write permissions*.
- **ThreatFox/URLhaus devuelven 401/403**: falta o es inválida la `ABUSECH_API_KEY`.
- **El cron deja de ejecutarse**: GitHub pausa los schedules tras 60 días sin actividad; los commits del bot cuentan como actividad, así que con que funcione no se pausará.

---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-07-14 03:17 UTC · **IOCs recolectados:** 1021 · **CVEs KEV recientes:** 8

### Últimos IOCs (defangueados, máx. 25)

| IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|
| `hxxps://schuctz[.]click/kkikc54m[.]js` | url | KongTuke | ThreatFox | 2026-07-14 03:09:35 UTC |
| `154[.]88[.]97[.]50:8885` | ip:port | VShell | ThreatFox | 2026-07-14 03:05:06 UTC |
| `154[.]88[.]96[.]43:8885` | ip:port | VShell | ThreatFox | 2026-07-14 03:05:06 UTC |
| `154[.]88[.]97[.]53:8885` | ip:port | VShell | ThreatFox | 2026-07-14 03:05:05 UTC |
| `154[.]88[.]96[.]33:8885` | ip:port | VShell | ThreatFox | 2026-07-14 03:05:05 UTC |
| `45[.]197[.]36[.]34:8885` | ip:port | VShell | ThreatFox | 2026-07-14 03:05:05 UTC |
| `s645gfw3[.]bahsegel90[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 02:54:22 UTC |
| `nqzp[.]jadoou[.]mom` | domain | ClearFake | ThreatFox | 2026-07-14 02:46:24 UTC |
| `pishro[.]bio` | domain | ClearFake | ThreatFox | 2026-07-14 02:32:58 UTC |
| `hxxps://freememusic[.]com/` | url | Vidar | ThreatFox | 2026-07-14 02:15:02 UTC |
| `154[.]88[.]97[.]39:8885` | ip:port | VShell | ThreatFox | 2026-07-14 02:05:07 UTC |
| `154[.]88[.]96[.]55:8885` | ip:port | VShell | ThreatFox | 2026-07-14 02:05:06 UTC |
| `43[.]161[.]215[.]33:21` | ip:port | VShell | ThreatFox | 2026-07-14 02:05:05 UTC |
| `154[.]88[.]96[.]40:8885` | ip:port | VShell | ThreatFox | 2026-07-14 02:05:05 UTC |
| `154[.]88[.]96[.]61:8885` | ip:port | VShell | ThreatFox | 2026-07-14 02:05:05 UTC |
| `sqbw[.]jadoou[.]makeup` | domain | ClearFake | ThreatFox | 2026-07-14 01:49:44 UTC |
| `ydzi[.]jadoou[.]makeup` | domain | ClearFake | ThreatFox | 2026-07-14 01:44:48 UTC |
| `wmgbwskd[.]pdfbama[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 01:38:13 UTC |
| `fbecwqni[.]pdfbama[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 01:37:50 UTC |
| `hxxps://schuctz[.]click/xyzqcsdc[.]js` | url | KongTuke | ThreatFox | 2026-07-14 01:11:00 UTC |
| `154[.]88[.]96[.]35:8885` | ip:port | VShell | ThreatFox | 2026-07-14 01:05:05 UTC |
| `154[.]88[.]96[.]57:8885` | ip:port | VShell | ThreatFox | 2026-07-14 01:05:05 UTC |
| `hczzqwrl[.]pinbahis-bedon-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 00:54:05 UTC |
| `mkneg2lo[.]pinbahis-bedon-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 00:53:48 UTC |
| `pinbahis-bedon-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 00:53:41 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2008-4128 | Cisco IOS | 2026-07-13 | Unknown |
| CVE-2026-56291 | Balbooa Forms | 2026-07-10 | Unknown |
| CVE-2026-48939 | iCagenda iCagenda | 2026-07-10 | Unknown |
| CVE-2026-48908 | JoomShaper SP Page Builder | 2026-07-07 | Unknown |
| CVE-2026-55255 | Langflow Langflow | 2026-07-07 | Unknown |
| CVE-2026-56290 | Joomlack Page Builder | 2026-07-07 | Unknown |
| CVE-2026-48282 | Adobe ColdFusion | 2026-07-07 | Unknown |
| CVE-2026-45659 | Microsoft SharePoint Server | 2026-07-01 | Unknown |
<!-- CTI:END -->
