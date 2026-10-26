"""Sonda temporal: comprueba formato y volumen de las fuentes de vulnerabilidades
desde un runner de GitHub (aquí no hay salida a internet). Imprime anotaciones."""
import csv, io, json, os, time, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone

def get(url, headers=None, limite=None):
    req = urllib.request.Request(url, headers={"User-Agent": "news-cti-sonda", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        datos = r.read(limite) if limite else r.read()
        return r.status, dict(r.headers), datos

def nota(titulo, obj):
    txt = json.dumps(obj, ensure_ascii=False)[:3900].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::notice title={titulo}::{txt}", flush=True)

ahora = datetime.now(timezone.utc)
ini = (ahora - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
fin = ahora.strftime("%Y-%m-%dT%H:%M:%S.000Z")
try:
    t = time.time()
    st, h, d = get("https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(
        {"pubStartDate": ini, "pubEndDate": fin, "resultsPerPage": 2000, "startIndex": 0}))
    j = json.loads(d)
    vs = j.get("vulnerabilities", [])
    con_cvss = sum(1 for v in vs if v["cve"].get("metrics"))
    con_cpe = sum(1 for v in vs if v["cve"].get("configurations"))
    con_es = sum(1 for v in vs if any(x.get("lang") == "es" for x in v["cve"].get("descriptions", [])))
    estados = {}
    for v in vs: estados[v["cve"].get("vulnStatus")] = estados.get(v["cve"].get("vulnStatus"), 0) + 1
    fuentes = {}
    for v in vs: fuentes[v["cve"].get("sourceIdentifier")] = fuentes.get(v["cve"].get("sourceIdentifier"), 0) + 1
    metr = {}
    for v in vs:
        for k in (v["cve"].get("metrics") or {}): metr[k] = metr.get(k, 0) + 1
    nota("NVD", {"http": st, "seg": round(time.time() - t, 1), "bytes": len(d), "total": j.get("totalResults"), "pagina": len(vs),
                 "con_metricas": con_cvss, "metricas": metr, "con_cpe": con_cpe, "con_es": con_es, "estados": estados,
                 "top_cna": sorted(fuentes.items(), key=lambda x: -x[1])[:25]})
    ej = next((v["cve"] for v in vs if v["cve"].get("metrics") and v["cve"].get("configurations")), vs[0]["cve"] if vs else {})
    nota("NVD ejemplo", {k: ej.get(k) for k in ("id", "sourceIdentifier", "published", "vulnStatus", "metrics", "weaknesses")})
    nota("NVD ejemplo cpe", ej.get("configurations", [])[:1])
    ids = [v["cve"]["id"] for v in vs]
except Exception as e:
    nota("NVD error", repr(e)); ids = []
try:
    st, h, d = get("https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": ",".join(ids[:100]), "limit": 100}))
    j = json.loads(d)
    nota("EPSS", {"http": st, "claves": list(j.keys()), "total": j.get("total"), "n": len(j.get("data", [])), "ejemplo": j.get("data", [])[:2]})
except Exception as e:
    nota("EPSS error", repr(e))
tok = os.environ.get("GH_TOKEN", "")
hdr = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {tok}"} if tok else {})}
desde = (ahora - timedelta(days=7)).strftime("%Y-%m-%d")
res = {}
for eco in ["npm", "pip", "maven", "nuget", "composer", "go", "rust", "rubygems", "erlang", "actions", "pub", "swift"]:
    fila = {}
    for tipo in ["malware", "reviewed"]:
        try:
            st, h, d = get("https://api.github.com/advisories?" + urllib.parse.urlencode(
                {"type": tipo, "ecosystem": eco, "published": f">={desde}", "per_page": 100}), hdr)
            j = json.loads(d)
            fila[tipo] = len(j); fila[tipo + "_mas"] = "next" in (h.get("Link") or h.get("link") or "")
            if tipo == "reviewed": fila["sev"] = {s: sum(1 for a in j if a.get("severity") == s) for s in ("critical", "high")}
            fila["rl"] = h.get("X-RateLimit-Remaining") or h.get("x-ratelimit-remaining")
        except Exception as e:
            fila[tipo] = repr(e)[:80]
    res[eco] = fila
nota("GitHub advisories 7d", res)
try:
    st, h, d = get("https://api.github.com/advisories?" + urllib.parse.urlencode({"type": "malware", "ecosystem": "npm", "per_page": 1}), hdr)
    a = json.loads(d)[0]
    nota("GitHub malware ejemplo", {k: a.get(k) for k in ("ghsa_id", "cve_id", "summary", "severity", "published_at", "type", "vulnerabilities", "epss", "html_url", "identifiers")})
    st, h, d = get("https://api.github.com/advisories?" + urllib.parse.urlencode({"type": "reviewed", "ecosystem": "pip", "per_page": 1}), hdr)
    a = json.loads(d)[0]
    nota("GitHub reviewed ejemplo", {k: a.get(k) for k in ("ghsa_id", "cve_id", "summary", "severity", "published_at", "cvss", "cvss_severities", "epss", "vulnerabilities")})
except Exception as e:
    nota("GitHub ejemplo error", repr(e))
osv = {}
for eco in ["npm", "PyPI", "Maven", "NuGet", "Packagist", "Go", "crates.io", "RubyGems", "Pub", "Hex", "SwiftURL", "GitHub Actions"]:
    try:
        st, h, d = get("https://osv-vulnerabilities.storage.googleapis.com/" + urllib.parse.quote(eco) + "/modified_id.csv", limite=400_000)
        lineas = d.decode("utf-8", "replace").splitlines()
        corte = (ahora - timedelta(days=7)).strftime("%Y-%m-%dT")
        rec = [l for l in lineas if l[:11] >= corte[:11]]
        mal = [l for l in rec if ",MAL-" in l]
        osv[eco] = {"http": st, "primeras": lineas[:2], "recientes_7d": len(rec), "mal_7d": len(mal), "leidas": len(lineas)}
    except Exception as e:
        osv[eco] = repr(e)[:100]
nota("OSV modified_id", osv)
try:
    mid = next((l.split(",")[1] for l in urllib.request.urlopen("https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv", timeout=60).read(300000).decode().splitlines() if ",MAL-" in l), None)
    st, h, d = get(f"https://api.osv.dev/v1/vulns/{mid}")
    j = json.loads(d)
    nota("OSV MAL ejemplo", {k: j.get(k) for k in ("id", "summary", "published", "modified", "affected", "database_specific")})
except Exception as e:
    nota("OSV ejemplo error", repr(e))
try:
    st, h, d = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    j = json.loads(d)
    v = j["vulnerabilities"]
    nota("KEV", {"total": len(v), "claves": list(v[0].keys()), "ultimo": max(x["dateAdded"] for x in v)})
except Exception as e:
    nota("KEV error", repr(e))
