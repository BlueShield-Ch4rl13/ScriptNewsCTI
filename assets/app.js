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

    var filtered = state.iocs.filter(function (i) {
      if (type && i.type !== type) return false;
      if (source && i.source !== source) return false;
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
      var tdIoc = el("td", "ioc", i.defanged || i.value || "");
      var tdType = el("td");
      tdType.appendChild(el("span", "type-chip", i.type || "?"));
      tr.appendChild(tdIoc);
      tr.appendChild(tdType);
      tr.appendChild(el("td", null, i.threat || "—"));
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
      if (i.source && sources.indexOf(i.source) === -1) sources.push(i.source);
    });
    setStat("stat-sources", sources.length);
    fillSelect($("f-type"), types);
    fillSelect($("f-source"), sources);

    ["f-search", "f-type", "f-source"].forEach(function (id) {
      $(id).addEventListener("input", applyFilters);
    });

    renderRows(iocs);
    renderKev(kev);
  }

  fetch("data/iocs_latest.json", { cache: "no-store" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(init)
    .catch(showError);
})();
