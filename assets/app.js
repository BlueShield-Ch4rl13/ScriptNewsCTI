/* CTI Feed Aggregator — front del subdominio.
   Seguridad: los valores de los feeds son datos no confiables, así que todo
   se inserta con textContent/createElement (nunca innerHTML) y la página
   corre bajo una CSP estricta definida en _headers. */

(function () {
  "use strict";

  var MAX_ROWS = 300;
  var state = { iocs: [], kev: [] };

  var $ = function (id) { return document.getElementById(id); };

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  var SEV_LABEL = { critica: "cr\u00edtica", alta: "alta", media: "media", baja: "baja" };

  function flag(cc) {
    if (!cc || cc.length !== 2) return "";
    var up = cc.toUpperCase();
    var a = up.charCodeAt(0), b = up.charCodeAt(1);
    if (a < 65 || a > 90 || b < 65 || b > 90) return "";
    return String.fromCodePoint(0x1F1E6 + a - 65, 0x1F1E6 + b - 65);
  }

  function setStat(id, value) {
    var node = $(id);
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || value <= 0) { node.textContent = String(value); return; }
    var start = null, dur = 700;
    function step(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      node.textContent = String(Math.round(value * p));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function fillSelect(select, values) {
    values.sort().forEach(function (v) {
      var opt = el("option", null, v);
      opt.value = v;
      select.appendChild(opt);
    });
  }

  function applyFilters() {
    var q = $("f-search").value.trim().toLowerCase();
    var type = $("f-type").value;
    var source = $("f-source").value;
    var level = $("f-level").value;
    var sev = $("f-sev").value;

    var filtered = state.iocs.filter(function (i) {
      var srcs = i.sources || (i.source ? [i.source] : []);
      if (type && i.type !== type) return false;
      if (source && srcs.indexOf(source) === -1) return false;
      if (level && (i.level || "") !== level) return false;
      if (sev && (i.severity || "") !== sev) return false;
      if (q) {
        var hay = ((i.value || "") + " " + (i.threat || "")).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });

    renderRows(filtered);
  }

  function renderRows(iocs) {
    var tbody = $("ioc-rows");
    tbody.textContent = "";
    var shown = iocs.slice(0, MAX_ROWS);

    shown.forEach(function (i) {
      var tr = document.createElement("tr");

      var tdScore = el("td");
      var badge = el("span", "score-badge s-" + (i.level || "baja"),
                     i.score !== undefined && i.score !== null ? i.score : "\u2014");
      var meta = [];
      if (i.sources && i.sources.length > 1) meta.push("Fuentes: " + i.sources.join(", "));
      if (i.age_days !== undefined && i.age_days !== null) meta.push("Edad " + i.age_days + " d");
      if (meta.length) badge.title = meta.join(" \u00b7 ");
      tdScore.appendChild(badge);
      tr.appendChild(tdScore);

      var tdSev = el("td");
      var sev = i.severity || "baja";
      tdSev.appendChild(el("span", "sev-chip sev-" + sev, SEV_LABEL[sev] || sev));
      tr.appendChild(tdSev);

      var tdIoc = el("td", "ioc", i.defanged || i.value || "");
      var tdType = el("td");
      tdType.appendChild(el("span", "type-chip", i.type || "?"));
      tr.appendChild(tdIoc);
      tr.appendChild(tdType);
      tr.appendChild(el("td", null, i.threat || "—"));
      tr.appendChild(el("td", "geo", i.country ? (flag(i.country) + " " + i.country).trim() : "—"));
      var rep = [];
      if (i.vt_detections) rep.push("VT " + i.vt_detections);
      if (i.abuse_score !== undefined && i.abuse_score !== null) rep.push("AB " + i.abuse_score);
      tr.appendChild(el("td", "rep", rep.length ? rep.join(" \u00b7 ") : "—"));
      tr.appendChild(el("td", null, i.source || "—"));
      tr.appendChild(el("td", null, i.first_seen || "—"));
      tbody.appendChild(tr);
    });

    $("result-count").textContent = iocs.length
      ? "Mostrando " + shown.length + " de " + iocs.length + " IOCs"
      : "";
    $("empty-state").hidden = iocs.length > 0;
    if (!iocs.length) $("empty-msg").textContent = "Sin resultados con estos filtros.";
  }

  function renderKev(kev) {
    var grid = $("kev-grid");
    grid.textContent = "";
    $("kev-empty").hidden = kev.length > 0;

    kev.forEach(function (v) {
      var card = el("article", "kev-card");
      card.appendChild(el("p", "kev-cve", v.cve || ""));
      card.appendChild(el("p", "kev-product", (v.vendor || "") + " " + (v.product || "")));
      card.appendChild(el("p", "kev-name", v.name || ""));
      var foot = el("div", "kev-foot");
      foot.appendChild(el("span", "kev-date", "Añadido " + (v.date_added || "")));
      if (v.ransomware === "Known") {
        foot.appendChild(el("span", "badge-ransom", "RANSOMWARE"));
      }
      card.appendChild(foot);
      grid.appendChild(card);
    });
  }

  function showError() {
    $("status-dot").classList.add("err");
    $("sync-time").textContent = "sin datos";
    $("empty-state").hidden = false;
    $("empty-msg").textContent =
      "No hay datos todavía. Ejecuta el workflow \u201CCTI Update\u201D en GitHub Actions y recarga la página.";
    $("kev-empty").hidden = false;
  }

  function init(data) {
    var iocs = data.iocs || [];
    var kev = data.cisa_kev_recent || [];
    state.iocs = iocs;
    state.kev = kev;

    $("status-dot").classList.add("ok");
    $("sync-time").textContent = data.generated_utc || "—";
    setStat("stat-iocs", iocs.length);
    setStat("stat-kev", kev.length);

    var types = [], sources = [];
    iocs.forEach(function (i) {
      if (i.type && types.indexOf(i.type) === -1) types.push(i.type);
      (i.sources || (i.source ? [i.source] : [])).forEach(function (s) {
        if (sources.indexOf(s) === -1) sources.push(s);
      });
    });
    setStat("stat-sources", sources.length);
    fillSelect($("f-type"), types);
    fillSelect($("f-source"), sources);

    ["f-search", "f-type", "f-source", "f-level", "f-sev"].forEach(function (id) {
      $(id).addEventListener("input", applyFilters);
    });

    renderRows(iocs);
    renderKev(kev);
  }

  /* ── Vulnerabilidades (data/vulns_latest.json) ───────────────────────────
     Un fallo aquí no afecta a los IOCs: cada bloque carga su propio fichero. */
  var CVE_RE = /^CVE-\d{4}-\d{4,}$/;
  var GHSA_RE = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/;
  var PRIO = { explotada: "explotada", urgente: "urgente", alta: "alta", media: "media", baja: "baja" };
  var PRIO_SEV = { explotada: "critica", urgente: "critica", alta: "alta", media: "media", baja: "baja" };
  var EST_SIS = {
    explotacion_activa: ["Explotación activa", "critica"],
    riesgo_alto: ["Riesgo alto", "alta"],
    vigilar: ["Vigilar", "media"]
  };
  var EST_LEN = {
    runtime_explotado: ["El lenguaje se explota", "critica"],
    maliciosos: ["Paquetes maliciosos", "critica"],
    critico: ["Avisos críticos", "alta"],
    alto: ["Avisos altos", "media"],
    sin_alertas: ["Sin alertas", "baja"]
  };
  var vstate = { cves: [], nombres: {}, filtrados: [], mostrar: 25 };
  var PASO = 25;
  // Nombre corto de cada sistema para la tabla (las tarjetas usan el largo)
  var CORTO = {
    microsoft: "Microsoft", linux: "Linux", apple: "Apple", android: "Android", navegadores: "Navegador",
    red: "Red / VPN", iot: "Router / IoT", virtualizacion: "Virtual. / nube", ia: "IA / LLM",
    servidores: "Servidor", ics: "OT / ICS", empresarial: "Empresarial", web: "Web / CMS",
    runtimes: "Lenguaje", oss: "Código abierto", otros: "Otros"
  };

  function pct(e) {
    if (e === null || e === undefined) return "\u2014";
    var v = e * 100;
    return (v < 1 ? v.toFixed(2) : v.toFixed(1)) + " %";
  }

  function enlace(texto, url) {
    var a = el("a", null, texto);
    a.href = url;
    a.rel = "noopener noreferrer";
    return a;
  }

  function cveNodo(id) {
    return CVE_RE.test(id || "") ? enlace(id, "https://nvd.nist.gov/vuln/detail/" + id) : el("span", null, id || "\u2014");
  }

  function chip(texto, sev) { return el("span", "sev-chip sev-" + sev, texto); }

  function titulo(nodo, t) { nodo.title = t; return nodo; }

  // Solo http(s) con host: un enlace de un feed nunca puede ser javascript: ni data:
  function urlSegura(u) {
    try {
      var x = new URL(String(u || ""));
      return (x.protocol === "https:" || x.protocol === "http:") && x.host ? x.href : "";
    } catch (e) { return ""; }
  }

  function metrica(valor, etiqueta) {
    var d = el("div", "metrica");
    d.appendChild(el("b", null, valor));
    d.appendChild(el("small", null, etiqueta));
    return d;
  }

  function renderTiles(r) {
    var t = $("vuln-tiles");
    t.textContent = "";
    [[r.cves, "CVE nuevos (7 d)"], [r.explotados, "Ya explotados"], [r.dia_cero, "Explotados desde el d\u00eda 0"],
     [r.urgentes, "Urgentes"], [r.criticos, "CVSS \u2265 9"], [r.epss_10, "EPSS \u2265 10 %"],
     [r.exploit_publico, "Con exploit p\u00fablico"], [r.paquetes_maliciosos, "Paquetes maliciosos"]]
      .forEach(function (x) { t.appendChild(metrica(x[0] || 0, x[1])); });
  }

  function renderSistemas(lista) {
    var g = $("sis-grid");
    g.textContent = "";
    $("sis-empty").hidden = lista.length > 0;
    lista.forEach(function (s) {
      var est = EST_SIS[s.estado] || ["\u2014", "baja"];
      var card = el("article", "estado-card est-" + est[1]);
      var head = el("div", "estado-head");
      head.appendChild(el("h3", null, s.nombre));
      head.appendChild(chip(est[0], est[1]));
      card.appendChild(head);
      var m = el("div", "metricas");
      m.appendChild(metrica(s.cves, "CVE nuevos"));
      m.appendChild(metrica(s.criticos, "CVSS \u2265 9"));
      m.appendChild(metrica(s.kev_recientes_total, "Explotados (30 d)"));
      card.appendChild(m);
      if (s.fabricantes && s.fabricantes.length) card.appendChild(el("p", "estado-fab", s.fabricantes.join(" \u00b7 ")));
      var ul = el("ul", "estado-lista");
      (s.kev_recientes || []).slice(0, 3).forEach(function (k) {
        var li = el("li");
        li.appendChild(cveNodo(k.cve));
        li.appendChild(el("span", null, " " + [k.fabricante, k.producto].filter(Boolean).join(" ")));
        if (k.ransomware) li.appendChild(el("span", "badge-ransom mini", "RANSOMWARE"));
        ul.appendChild(li);
      });
      if (!ul.childNodes.length) {
        (s.destacados || []).slice(0, 3).forEach(function (c) {
          var li = el("li");
          li.appendChild(cveNodo(c.cve));
          li.appendChild(el("span", null, " " + (c.fabricante || "") + " \u00b7 CVSS " + (c.cvss !== null && c.cvss !== undefined ? c.cvss : "\u2014") + " \u00b7 EPSS " + pct(c.epss)));
          ul.appendChild(li);
        });
      }
      if (ul.childNodes.length) card.appendChild(ul);
      g.appendChild(card);
    });
  }

  function renderLenguajes(lista) {
    var g = $("len-grid");
    g.textContent = "";
    $("len-empty").hidden = lista.length > 0;
    lista.forEach(function (x) {
      var est = EST_LEN[x.estado] || (x.error ? ["Sin datos", "baja"] : ["\u2014", "baja"]);
      var card = el("article", "estado-card est-" + est[1]);
      var head = el("div", "estado-head");
      var h = el("h3", null, x.lenguaje);
      h.appendChild(el("span", "registro", " \u00b7 " + x.registro));
      head.appendChild(h);
      head.appendChild(chip(est[0], est[1]));
      card.appendChild(head);
      var rt = x.runtime;
      if (rt && (rt.explotados_total || rt.cves)) {
        var linea = el("p", "estado-rt" + (rt.explotados_total ? " rt-explotado" : ""));
        linea.appendChild(el("b", null, "El propio " + rt.nombre + ": "));
        linea.appendChild(el("span", null, (rt.explotados_total ? rt.explotados_total + " CVE explotados (CISA KEV, 90 d)" : "") +
          (rt.explotados_total && rt.cves ? " \u00b7 " : "") + (rt.cves ? rt.cves + " CVE nuevos esta semana" : "")));
        card.appendChild(linea);
        if (rt.explotados && rt.explotados.length) {
          var ulr = el("ul", "estado-lista");
          rt.explotados.slice(0, 3).forEach(function (k) {
            var li = el("li");
            li.appendChild(cveNodo(k.cve));
            li.appendChild(el("span", "muted", " " + (k.nombre || "") + " \u00b7 a\u00f1adido " + (k.anadido || "")));
            if (k.ransomware) li.appendChild(el("span", "badge-ransom mini", "RANSOMWARE"));
            ulr.appendChild(li);
          });
          card.appendChild(ulr);
        }
      }
      if (x.error) { card.appendChild(el("p", "estado-fab", "El registro de paquetes no respondió en esta actualización.")); g.appendChild(card); return; }
      var m = el("div", "metricas");
      m.appendChild(metrica(x.maliciosos + (x.maliciosos_mas ? "+" : ""), "Paquetes maliciosos"));
      m.appendChild(metrica(x.criticos, "Avisos críticos"));
      m.appendChild(metrica(x.altos, "Avisos altos"));
      card.appendChild(m);
      var ul = el("ul", "estado-lista");
      (x.ejemplos_maliciosos || []).slice(0, 3).forEach(function (a) {
        var li = el("li");
        li.appendChild(el("span", "pkg", a.paquete || "?"));
        li.appendChild(el("span", "muted", " malicioso \u00b7 " + (a.publicado || "")));
        ul.appendChild(li);
      });
      (x.ejemplos_graves || []).slice(0, 2).forEach(function (a) {
        var li = el("li");
        li.appendChild(GHSA_RE.test(a.ghsa || "") ? enlace(a.paquete || a.ghsa, "https://github.com/advisories/" + a.ghsa) : el("span", "pkg", a.paquete || "?"));
        li.appendChild(el("span", "muted", " " + (a.gravedad || "") + (a.corregido_en ? " \u00b7 corregido en " + a.corregido_en : " \u00b7 sin versión corregida")));
        ul.appendChild(li);
      });
      if (ul.childNodes.length) card.appendChild(ul);
      g.appendChild(card);
    });
  }

  function aplicarFiltrosVulns() {
    var q = $("v-search").value.trim().toLowerCase();
    var prio = $("v-prio").value;
    var cat = $("v-cat").value;
    var senal = $("v-senal").value;
    var lista = vstate.cves.filter(function (c) {
      if (prio && c.prioridad !== prio) return false;
      if (cat && c.categoria !== cat) return false;
      if (senal === "exploitdb" || senal === "github") { if (c.exploit_publico !== senal) return false; }
      else if (senal === "avisos") { if (!c.avisos_total) return false; }
      else if (senal && !c[senal]) return false;
      if (q) {
        var hay = (c.cve + " " + (c.fabricante || "") + " " + (c.descripcion || "")).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
    vstate.mostrar = PASO;
    renderCves(lista);
  }

  function renderCves(lista) {
    vstate.filtrados = lista;
    var tbody = $("v-rows");
    tbody.textContent = "";
    var shown = lista.slice(0, vstate.mostrar);
    shown.forEach(function (c) {
      var tr = document.createElement("tr");
      var td = el("td");
      td.appendChild(chip(PRIO[c.prioridad] || c.prioridad, PRIO_SEV[c.prioridad] || "baja"));
      tr.appendChild(td);
      var tdc = el("td", "cve-id");
      tdc.appendChild(cveNodo(c.cve));
      if (c.kev) tdc.appendChild(el("span", "badge-kev", "KEV"));
      if (c.dia_cero) tdc.appendChild(titulo(el("span", "badge-kev b-cero", "D\u00cdA 0"), "CISA la dio por explotada el mismo d\u00eda o al siguiente de publicarse"));
      if (c.ransomware) tdc.appendChild(titulo(el("span", "badge-ransom mini", "RANSOMWARE"), "Usada en campa\u00f1as de ransomware (CISA KEV)"));
      if (c.exploit_publico === "exploitdb" && /^\d+$/.test(String(c.exploitdb))) {
        var x = enlace("EXPLOIT", "https://www.exploit-db.com/exploits/" + c.exploitdb);
        x.className = "badge-kev b-exploit";
        tdc.appendChild(titulo(x, "Exploit p\u00fablico en Exploit-DB (EDB-" + c.exploitdb + ")"));
      } else if (c.exploit_publico === "github") {
        tdc.appendChild(titulo(el("span", "badge-kev b-poc", "PoC"), "Hay una prueba de concepto en GitHub sin verificar: puede ser falsa o contener malware"));
      }
      tr.appendChild(tdc);
      var tds = el("td", "sis");
      var tchip = el("span", "type-chip", CORTO[c.categoria] || c.categoria || "?");
      tchip.title = vstate.nombres[c.categoria] || "";
      tds.appendChild(tchip);
      if (c.fabricante) tds.appendChild(el("span", "fab", c.fabricante));
      tr.appendChild(tds);
      tr.appendChild(el("td", "num", c.cvss !== null && c.cvss !== undefined ? c.cvss : "\u2014"));
      tr.appendChild(el("td", "num", pct(c.epss)));
      tr.appendChild(el("td", "num", c.publicado || "\u2014"));
      var tdd = el("td", "desc", c.descripcion || "");
      tdd.title = (c.cwe || []).join(", ");
      if (c.avisos && c.avisos.length) {
        var cit = el("span", "citado", "Citado en ");
        c.avisos.forEach(function (a, i) {
          var url = urlSegura(a.enlace);
          if (i) cit.appendChild(document.createTextNode(" \u00b7 "));
          cit.appendChild(url ? enlace(a.nombre || a.fuente, url) : el("span", null, a.nombre || a.fuente));
        });
        if (c.avisos_total > c.avisos.length) cit.appendChild(document.createTextNode(" y " + (c.avisos_total - c.avisos.length) + " m\u00e1s"));
        tdd.appendChild(cit);
      }
      tr.appendChild(tdd);
      tbody.appendChild(tr);
    });
    $("v-count").textContent = lista.length ? "Mostrando " + shown.length + " de " + lista.length + " CVE" : "";
    $("v-mas").hidden = shown.length >= lista.length;
    $("v-empty").hidden = lista.length > 0;
    if (!lista.length) $("v-empty-msg").textContent = "Sin CVE con estos filtros.";
  }

  function initVulns(d) {
    var r = d.resumen || {};
    setStat("stat-cves", r.cves || 0);
    renderTiles(r);
    (d.sistemas || []).forEach(function (s) { vstate.nombres[s.categoria] = s.nombre; });
    renderSistemas(d.sistemas || []);
    renderLenguajes(d.lenguajes || []);
    vstate.cves = d.cves || [];
    var cats = [];
    vstate.cves.forEach(function (c) { if (c.categoria && cats.indexOf(c.categoria) === -1) cats.push(c.categoria); });
    cats.sort().forEach(function (c) {
      var opt = el("option", null, vstate.nombres[c] || c);
      opt.value = c;
      $("v-cat").appendChild(opt);
    });
    ["v-search", "v-prio", "v-cat", "v-senal"].forEach(function (id) { $(id).addEventListener("input", aplicarFiltrosVulns); });
    $("v-mas").addEventListener("click", function () { vstate.mostrar += PASO; renderCves(vstate.filtrados); });
    renderCves(vstate.cves);
    var caidas = Object.keys(d.fuentes || {}).filter(function (k) { return d.fuentes[k] !== "ok"; });
    $("v-fuentes").textContent = "Actualizado " + (d.generado_utc || "\u2014") + " UTC \u00b7 " +
      (r.cves || 0) + " CVE en " + (d.ventana_dias || 7) + " d\u00edas (la tabla muestra los " + (d.cves_publicados || 0) + " m\u00e1s prioritarios)" +
      (caidas.length ? " \u00b7 sin respuesta en esta actualizaci\u00f3n: " + caidas.join(", ") : "");
  }

  function sinVulns() {
    $("sis-empty").hidden = false;
    $("len-empty").hidden = false;
    $("v-empty").hidden = false;
    $("v-empty-msg").textContent = "Las vulnerabilidades aparecerán tras la próxima ejecución del pipeline.";
  }

  /* ── Avisos que van saliendo (data/avisos_latest.json) ─────────────────── */
  var SENAL = [
    ["explotada", "Ya se explota", "critica"], ["dia_cero", "D\u00eda cero", "critica"],
    ["sin_parche", "Sin parche", "alta"], ["critica", "Cr\u00edtica", "alta"],
    ["exploit_publico", "Exploit p\u00fablico", "alta"]
  ];
  var astate = { avisos: [], fuentes: {}, filtrados: [], mostrar: 25 };

  function hace(iso) {
    var t = Date.parse(iso || "");
    if (isNaN(t)) return "\u2014";
    var min = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (min < 60) return "hace " + min + " min";
    if (min < 48 * 60) return "hace " + Math.round(min / 60) + " h";
    return "hace " + Math.round(min / 1440) + " d";
  }

  function renderAvTiles(r) {
    var t = $("av-tiles");
    t.textContent = "";
    [[r.avisos, "Avisos (7 d)"], [r.explotados, "De algo ya explotado"], [r.dia_cero, "D\u00eda cero"],
     [r.sin_parche, "Sin parche"], [r.criticos, "Cr\u00edticos"],
     [(r.fuentes_ok || 0) + "/" + (r.fuentes_total || 0), "Fuentes que responden"]]
      .forEach(function (x) { t.appendChild(metrica(x[0] || 0, x[1])); });
  }

  function renderCitados(lista) {
    var ul = $("av-citados-lista");
    ul.textContent = "";
    $("av-citados").hidden = !lista.length;
    lista.forEach(function (c) {
      var li = el("li");
      li.appendChild(cveNodo(c.cve));
      if (c.kev) li.appendChild(el("span", "badge-kev", "KEV"));
      var nombres = (c.fuentes || []).map(function (f) { return (astate.fuentes[f] || {}).nombre || f; });
      li.appendChild(el("span", "muted", " " + nombres.length + " fuentes: " + nombres.join(", ") +
        (c.cvss !== null && c.cvss !== undefined ? " \u00b7 CVSS " + c.cvss : "") +
        (c.epss !== null && c.epss !== undefined ? " \u00b7 EPSS " + pct(c.epss) : "")));
      li.addEventListener("click", function (ev) {
        if (ev.target.tagName === "A") return;
        $("a-search").value = c.cve;
        aplicarFiltrosAvisos();
      });
      ul.appendChild(li);
    });
  }

  function aplicarFiltrosAvisos() {
    var q = $("a-search").value.trim().toLowerCase();
    var f = $("a-fuente").value;
    var senal = $("a-senal").value;
    var lista = astate.avisos.filter(function (a) {
      if (f.indexOf("t:") === 0 && (astate.fuentes[a.fuente] || {}).tipo !== f.slice(2)) return false;
      if (f.indexOf("f:") === 0 && a.fuente !== f.slice(2)) return false;
      if (senal && !a[senal]) return false;
      if (q) {
        var hay = (a.titulo + " " + (a.cves || []).join(" ") + " " + ((astate.fuentes[a.fuente] || {}).nombre || "")).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
    astate.mostrar = PASO;
    renderAvisos(lista);
  }

  function renderAvisos(lista) {
    astate.filtrados = lista;
    var ol = $("a-lista");
    ol.textContent = "";
    var shown = lista.slice(0, astate.mostrar);
    shown.forEach(function (a) {
      var url = urlSegura(a.enlace);
      var fu = astate.fuentes[a.fuente] || { nombre: a.fuente, tipo: "" };
      var li = el("li", "aviso" + (a.explotada ? " av-explotada" : a.dia_cero || a.critica ? " av-grave" : ""));
      var cab = el("div", "aviso-cab");
      cab.appendChild(el("span", "fuente-chip t-" + (fu.tipo || "otro"), fu.nombre));
      cab.appendChild(titulo(el("span", "aviso-hora", hace(a.fecha)), (a.fecha || "").replace("T", " ").replace("Z", " UTC")));
      SENAL.forEach(function (s_) { if (a[s_[0]]) cab.appendChild(chip(s_[1], s_[2])); });
      li.appendChild(cab);
      var h = el("p", "aviso-titulo");
      h.appendChild(url ? enlace(a.titulo, url) : el("span", null, a.titulo));
      li.appendChild(h);
      if (a.cves && a.cves.length) {
        var p = el("p", "aviso-cves");
        a.cves.forEach(function (c) {
          p.appendChild(cveNodo(c));
          if ((a.kev || []).indexOf(c) !== -1) p.appendChild(el("span", "badge-kev", "KEV"));
          p.appendChild(document.createTextNode(" "));
        });
        if (a.cves_total > a.cves.length) p.appendChild(el("span", "muted", "y " + (a.cves_total - a.cves.length) + " m\u00e1s"));
        if (a.epss_max !== null && a.epss_max !== undefined) p.appendChild(el("span", "muted", " \u00b7 EPSS m\u00e1x. " + pct(a.epss_max)));
        li.appendChild(p);
      }
      ol.appendChild(li);
    });
    $("a-count").textContent = lista.length ? "Mostrando " + shown.length + " de " + lista.length + " avisos" : "";
    $("a-mas").hidden = shown.length >= lista.length;
    $("a-empty").hidden = lista.length > 0;
    if (!lista.length) $("a-empty-msg").textContent = "Sin avisos con estos filtros.";
  }

  function initAvisos(d) {
    var r = d.resumen || {};
    setStat("stat-avisos", r.avisos || 0);
    renderAvTiles(r);
    var tipos = d.tipos || {};
    var sel = $("a-fuente");
    Object.keys(tipos).forEach(function (t) {
      var opt = el("option", null, tipos[t] + " (todas)");
      opt.value = "t:" + t;
      sel.appendChild(opt);
    });
    Object.keys(tipos).forEach(function (t) {
      var grupo = document.createElement("optgroup");
      grupo.label = tipos[t];
      (d.fuentes || []).forEach(function (f) {
        astate.fuentes[f.id] = f;
        if (f.tipo !== t) return;
        var opt = el("option", null, f.nombre + " (" + (f.avisos || 0) + ")");
        opt.value = "f:" + f.id;
        grupo.appendChild(opt);
      });
      if (grupo.childNodes.length) sel.appendChild(grupo);
    });
    astate.avisos = d.avisos || [];
    renderCitados(d.mas_citados || []);
    ["a-search", "a-fuente", "a-senal"].forEach(function (id) { $(id).addEventListener("input", aplicarFiltrosAvisos); });
    $("a-mas").addEventListener("click", function () { astate.mostrar += PASO; renderAvisos(astate.filtrados); });
    renderAvisos(astate.avisos);
    var caidas = (d.fuentes || []).filter(function (f) { return f.estado !== "ok"; }).map(function (f) { return f.nombre; });
    $("a-fuentes").textContent = "Actualizado " + (d.generado_utc || "\u2014") + " UTC \u00b7 " + (r.fuentes_ok || 0) + " de " +
      (r.fuentes_total || 0) + " fuentes respondieron" + (caidas.length ? " (sin respuesta: " + caidas.join(", ") + "; se mantienen sus avisos anteriores)" : "");
  }

  function sinAvisos() {
    $("a-empty").hidden = false;
    $("a-empty-msg").textContent = "Los avisos aparecerán tras la próxima ejecución del pipeline.";
  }

  fetch("data/avisos_latest.json", { cache: "no-store" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(initAvisos)
    .catch(sinAvisos);

  fetch("data/vulns_latest.json", { cache: "no-store" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(initVulns)
    .catch(sinVulns);

  fetch("data/iocs_latest.json", { cache: "no-store" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(init)
    .catch(showError);
})();
