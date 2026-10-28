"""Sonda temporal: prueba cada fuente de avisos y de exploits con el código real
y deja el resultado comprimido en /tmp/sonda.b64 (anotaciones de 4000 caracteres)."""
import base64, csv, gzip, io, json, logging, os, sys, time, traceback
from datetime import datetime, timedelta, timezone
sys.path.insert(0, ".")
logging.basicConfig(level=logging.INFO)
import requests
import avisos as A

desde = datetime.now(timezone.utc) - timedelta(days=7)
res = {"fuentes": {}, "alternativas": {}, "extra": {}}

def crudo(url):
    try:
        r = requests.get(url, headers=A.UA, timeout=30)
        return {"http": r.status_code, "tipo": r.headers.get("content-type"), "bytes": len(r.content),
                "inicio": r.content[:300].decode("utf-8", "replace")}
    except Exception as e:
        return {"exc": repr(e)[:300]}

def probar(f):
    t = time.time()
    out = {"url": f["url"]}
    try:
        datos = A.descargar(f["url"])
        out["bytes"] = len(datos)
        ent = A.leer_feed(datos)
        out["entradas"] = len(ent)
        out["con_fecha"] = sum(1 for e in ent if e["fecha"])
        out["mas_nueva"] = max((e["fecha"] for e in ent if e["fecha"]), default=None)
        out["mas_nueva"] = out["mas_nueva"] and out["mas_nueva"].isoformat()
        av = A.de_fuente(f, desde)
        out["avisos_7d"] = len(av)
        out["muestra"] = [{k: a[k] for k in ("titulo", "enlace", "fecha", "cves", "explotada_texto", "dia_cero")} for a in av[:4]]
        out["sin_enlace"] = sum(1 for e in ent if not A.enlace_seguro(e["enlace"]))
        out["ejemplo_crudo"] = {k: (str(v)[:160]) for k, v in (ent[0] if ent else {}).items()}
    except Exception as e:
        out["error"] = repr(e)[:400]
        out["crudo"] = crudo(f["url"])
    out["seg"] = round(time.time() - t, 1)
    return out

for f in A.FUENTES:
    res["fuentes"][f["id"]] = probar(f)

ALT = {
    "ccn_alertas": "https://www.ccn-cert.cni.es/es/seguridad-al-dia/alertas-ccn-cert.feed?type=rss",
    "ccn_avisos": "https://www.ccn-cert.cni.es/es/seguridad-al-dia/avisos-ccn-cert.feed?type=rss",
    "ccn_vulns": "https://www.ccn-cert.cni.es/es/seguridad-al-dia/vulnerabilidades.feed?type=rss",
    "incibe_vulns": "https://www.incibe.es/feed/vulnerabilities",
    "cisa_ics": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "cert_fr_avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "debian_dsa": "https://www.debian.org/security/dsa",
    "debian_rdf": "https://www.debian.org/security/dsa-long.en.rdf",
    "mozilla": "https://www.mozilla.org/en-US/security/advisories/feed/",
    "ivanti": "https://www.ivanti.com/blog/topics/security-advisory/rss",
    "citrix": "https://support.citrix.com/feed/products/all/securitybulletins.rss",
    "vmware": "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/rss",
    "sap": "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.rss",
    "apple": "https://support.apple.com/en-us/rss/security-releases.rss",
    "android": "https://source.android.com/feeds/android-security-bulletins.xml",
    "juniper": "https://supportportal.juniper.net/s/feed/security-advisories",
    "zdi_upcoming": "https://www.zerodayinitiative.com/rss/upcoming/",
    "packetstorm": "https://rss.packetstormsecurity.com/files/tags/exploit/",
    "wordfence": "https://www.wordfence.com/feed/",
    "helpnet": "https://www.helpnetsecurity.com/feed/",
    "darkreading": "https://www.darkreading.com/rss.xml",
    "securityaffairs": "https://securityaffairs.com/feed",
    "segu_info": "https://blog.segu-info.com.ar/feeds/posts/default",
    "github_blog_sec": "https://github.blog/security/feed/",
}
for k, url in ALT.items():
    res["alternativas"][k] = probar({"id": k, "url": url, "filtro": "todo"})

# Exploit-DB: CSV completo (GitLab)
try:
    t = time.time()
    r = requests.get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", headers=A.UA, timeout=60)
    filas = list(csv.DictReader(io.StringIO(r.content.decode("utf-8", "replace"))))
    cves = [c for f in filas for c in (f.get("codes") or "").split(";") if c.startswith("CVE-")]
    res["extra"]["exploitdb_csv"] = {"http": r.status_code, "bytes": len(r.content), "filas": len(filas),
        "cabecera": list(filas[0].keys()) if filas else None, "cves": len(set(cves)),
        "ultimas": [{k: f.get(k) for k in ("id", "date_published", "date_added", "verified", "codes", "description")} for f in sorted(filas, key=lambda f: f.get("date_added") or "")[-5:]],
        "seg": round(time.time() - t, 1)}
except Exception as e:
    res["extra"]["exploitdb_csv"] = {"error": repr(e)[:300]}

# PoC-in-GitHub: árbol del repositorio
try:
    cab = {"Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        cab["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    r = requests.get("https://api.github.com/repos/nomi-sec/PoC-in-GitHub", headers=cab, timeout=30)
    info = r.json()
    rama = info.get("default_branch")
    raiz = requests.get(f"https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/{rama}", headers=cab, timeout=30).json()
    dirs = {e["path"]: e["sha"] for e in raiz.get("tree", []) if e["type"] == "tree"}
    out = {"rama": rama, "pushed_at": info.get("pushed_at"), "dirs": sorted(dirs)[-5:]}
    for anio in ("2026", "2025"):
        if anio in dirs:
            arb = requests.get(f"https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/{dirs[anio]}", headers=cab, timeout=60).json()
            nombres = [e["path"] for e in arb.get("tree", [])]
            out[anio] = {"ficheros": len(nombres), "truncado": arb.get("truncated"), "muestra": nombres[-3:]}
    # un fichero de ejemplo
    if "2026" in dirs and out.get("2026", {}).get("muestra"):
        f = out["2026"]["muestra"][-1]
        j = requests.get(f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/{rama}/2026/{f}", timeout=30).json()
        out["ejemplo"] = j[:1] if isinstance(j, list) else str(j)[:300]
    res["extra"]["poc_github"] = out
except Exception as e:
    res["extra"]["poc_github"] = {"error": repr(e)[:300], "tb": traceback.format_exc()[-500:]}

# ENISA EUVD
for nombre, url in {
    "euvd_explotadas": "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities",
    "euvd_busqueda": "https://euvdservices.enisa.europa.eu/api/vulnerabilities?exploited=true&fromDate=" + (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d") + "&size=100",
    "euvd_busqueda_page1": "https://euvdservices.enisa.europa.eu/api/vulnerabilities?exploited=true&size=100&page=1",
}.items():
    try:
        r = requests.get(url, headers={"User-Agent": A.UA["User-Agent"], "Accept": "application/json"}, timeout=60)
        j = r.json()
        items = j.get("items") if isinstance(j, dict) else j
        res["extra"][nombre] = {"http": r.status_code, "tipo": type(j).__name__,
            "claves": list(j.keys()) if isinstance(j, dict) else None, "total": j.get("total") if isinstance(j, dict) else None,
            "n": len(items or []), "ejemplo": (items or [None])[0]}
    except Exception as e:
        res["extra"][nombre] = {"error": repr(e)[:300]}

blob = base64.b64encode(gzip.compress(json.dumps(res, ensure_ascii=False, default=str).encode(), 9)).decode()
open("/tmp/sonda.b64", "w").write(blob)
resumen = {k: (v.get("avisos_7d"), v.get("error", "")[:60]) for k, v in res["fuentes"].items()}
print("::notice title=resumen::" + json.dumps({"trozos": -(-len(blob) // 4000)}))
print(json.dumps(resumen, indent=1))
