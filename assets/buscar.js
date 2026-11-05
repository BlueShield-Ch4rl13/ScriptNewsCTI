/* Buscador de todo el panel, gráficas de «la semana de un vistazo» y menú de
   secciones. Usa los datos que app.js ya ha descargado (window.CTI y el evento
   «cti:datos»): no vuelve a pedir nada.

   Seguridad: igual que app.js, todo el texto de los feeds entra con
   textContent / createElement (nunca innerHTML) y las gráficas son SVG hechos
   con createElementNS, sin estilos en línea (la CSP no los admite). */

(function () {
  "use strict";

  var CTI = window.CTI || (window.CTI = {});
  var $ = function (id) { return document.getElementById(id); };
  var SVG = "http://www.w3.org/2000/svg";
  var POR_GRUPO = 5;

  function el(tag, clase, texto) {
    var n = document.createElement(tag);
    if (clase) n.className = clase;
    if (texto !== undefined && texto !== null) n.textContent = String(texto);
    return n;
  }
  function svg(tag, attrs) {
    var n = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    return n;
  }
  var normalizar = CTI.normalizar || function (t) { return String(t || "").toLowerCase(); };

  /* ── Índice de búsqueda ───────────────────────────────────────────────── */
  var indice = { avisos: [], cves: [], iocs: [], sistemas: [] };
  var fuentes = {};
  var PRIO_TXT = { explotada: "Explotada", urgente: "Urgente", alta: "Alta", media: "Media", baja: "Baja" };
  var EST_SIS = { explotacion_activa: "Explotación activa", riesgo_alto: "Riesgo alto", vigilar: "Vigilar" };

  function indexar(nombre) {
    var d = CTI[nombre];
    if (!d) return;
    if (nombre === "avisos") {
      (d.fuentes || []).forEach(function (f) { fuentes[f.id || f.clave || f.nombre] = f.nombre || f.id; });
      indice.avisos = (d.avisos || []).map(function (a) {
        var fuente = fuentes[a.fuente] || a.fuente || "";
        return { tipo: "aviso", dato: a, fuente: fuente,
                 hay: normalizar(a.titulo + " " + (a.cves || []).join(" ") + " " + fuente),
                 peso: (a.explotada ? 4 : 0) + (a.dia_cero ? 3 : 0) + (a.critica ? 2 : 0) };
      });
    } else if (nombre === "vulns") {
      var nombres = {};
      (d.sistemas || []).forEach(function (s) { nombres[s.categoria] = s.nombre; });
      indice.cves = (d.cves || []).map(function (c) {
        return { tipo: "cve", dato: c, sistema: nombres[c.categoria] || "",
                 hay: normalizar(c.cve + " " + (c.fabricante || "") + " " + (c.descripcion || "") + " " + (nombres[c.categoria] || "")),
                 peso: { explotada: 5, urgente: 4, alta: 3, media: 2, baja: 1 }[c.prioridad] || 0 };
      });
      indice.sistemas = (d.sistemas || []).map(function (s) {
        return { tipo: "sistema", dato: s, destino: "s-sistemas",
                 hay: normalizar(s.nombre + " " + (s.fabricantes || []).join(" ")), peso: s.cves || 0 };
      }).concat((d.lenguajes || []).map(function (l) {
        return { tipo: "lenguaje", dato: l, destino: "s-lenguajes",
                 hay: normalizar([l.lenguaje, l.ecosistema, l.registro, (l.runtime || {}).nombre].join(" ")), peso: l.maliciosos || 0 };
      }));
    } else if (nombre === "iocs") {
      indice.iocs = (d.iocs || []).map(function (i) {
        return { tipo: "ioc", dato: i, valor: normalizar(i.value),
                 hay: normalizar((i.value || "") + " " + (i.threat || "") + " " + (i.type || "") + " " + (i.sources || []).join(" ")),
                 peso: i.score || 0 };
      });
    }
  }

  // ¿La consulta es un identificador concreto? Entonces se da un veredicto
  var RX_CVE = /^cve-\d{4}-\d{4,}$/;
  var RX_HASH = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/;
  var RX_IP = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;
  var RX_DOM = /^([a-z0-9-]+\.)+[a-z]{2,}$/;
  function identificador(q) {
    if (RX_CVE.test(q)) return "cve";
    if (RX_HASH.test(q)) return "hash";
    if (RX_IP.test(q)) return "ip";
    if (/^https?:\/\//.test(q)) return "url";
    if (RX_DOM.test(q)) return "dominio";
    return "";
  }

  function buscarEn(lista, palabras, exacto) {
    var res = [];
    for (var i = 0; i < lista.length; i++) {
      var e = lista[i];
      var ok = true;
      for (var j = 0; j < palabras.length; j++) { if (e.hay.indexOf(palabras[j]) === -1) { ok = false; break; } }
      if (!ok) continue;
      // lo exacto primero: el IOC idéntico, el CVE con ese número
      var extra = exacto && ((e.valor && (e.valor === exacto || e.valor.split(":")[0] === exacto)) ||
                             (e.tipo === "cve" && normalizar(e.dato.cve) === exacto)) ? 100 : 0;
      res.push({ e: e, orden: extra + e.peso });
    }
    res.sort(function (a, b) { return b.orden - a.orden; });
    return res.map(function (r) { return r.e; });
  }

  /* ── Resultados ───────────────────────────────────────────────────────── */
  var caja, resultados, activa = -1, opciones = [], ultima = "";

  function marcar(nodo, texto, palabras) {
    // Resalta las palabras buscadas sin innerHTML: se trocea el texto
    texto = String(texto || "");
    var norm = normalizar(texto);
    var tramos = [];
    palabras.forEach(function (p) {
      if (!p) return;
      var desde = 0, k;
      while ((k = norm.indexOf(p, desde)) !== -1 && norm.length === texto.length) { tramos.push([k, k + p.length]); desde = k + p.length; }
    });
    tramos.sort(function (a, b) { return a[0] - b[0]; });
    var pos = 0;
    tramos.forEach(function (t) {
      if (t[0] < pos) return;
      if (t[0] > pos) nodo.appendChild(document.createTextNode(texto.slice(pos, t[0])));
      nodo.appendChild(el("mark", null, texto.slice(t[0], t[1])));
      pos = t[1];
    });
    if (pos < texto.length) nodo.appendChild(document.createTextNode(texto.slice(pos)));
    return nodo;
  }

  function fecha(t) {
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(t || "");
    return m ? m[3] + "/" + m[2] : "";
  }

  function irASeccion(id, filtro, valor) {
    var campo = filtro && $(filtro);
    if (campo) {
      var panel = $(id);
      // Se quitan los demás filtros de esa sección para que el resultado se vea seguro
      if (panel) Array.prototype.forEach.call(panel.querySelectorAll(".filters select"), function (s) { s.value = ""; });
      campo.value = valor;
      campo.dispatchEvent(new Event("input", { bubbles: true }));
    }
    var destino = $(id);
    if (destino) {
      destino.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
      destino.classList.remove("destacada");
      void destino.offsetWidth;
      destino.classList.add("destacada");
    }
    cerrar();
  }

  function opcion(clase, accion) {
    var b = el("button", "r-item " + (clase || ""));
    b.type = "button";
    b.setAttribute("role", "option");
    b.id = "q-op-" + opciones.length;
    b.tabIndex = -1;
    b.addEventListener("click", accion);
    b.addEventListener("mousedown", function (ev) { ev.preventDefault(); });
    opciones.push(b);
    return b;
  }

  function itemAviso(e, palabras) {
    var a = e.dato;
    var b = opcion("r-aviso", function () { if (/^https?:\/\//.test(a.enlace || "")) window.open(a.enlace, "_blank", "noopener"); });
    var t = el("span", "r-titulo"); marcar(t, a.titulo, palabras); b.appendChild(t);
    var m = el("span", "r-meta", [e.fuente, fecha(a.fecha)].filter(Boolean).join(" · "));
    if (a.explotada) m.appendChild(el("span", "r-chip c-explotada", "ya se explota"));
    if (a.dia_cero) m.appendChild(el("span", "r-chip c-explotada", "día cero"));
    if (a.critica) m.appendChild(el("span", "r-chip c-urgente", "crítica"));
    if (a.sin_parche) m.appendChild(el("span", "r-chip c-urgente", "sin parche"));
    b.appendChild(m);
    b.title = "Abrir el aviso en su fuente";
    return b;
  }
  function itemCve(e, palabras) {
    var c = e.dato;
    var b = opcion("r-cve", function () { irASeccion("s-cves", "v-search", c.cve); });
    var t = el("span", "r-titulo");
    marcar(t, c.cve, palabras);
    if (c.fabricante) { t.appendChild(document.createTextNode(" · ")); marcar(t, c.fabricante, palabras); }
    b.appendChild(t);
    var m = el("span", "r-meta");
    m.appendChild(el("span", "r-chip c-" + (c.prioridad || "baja"), PRIO_TXT[c.prioridad] || c.prioridad || ""));
    m.appendChild(document.createTextNode([c.cvss != null ? "CVSS " + c.cvss : "", e.sistema, fecha(c.publicado)].filter(Boolean).join(" · ")));
    b.appendChild(m);
    var d = el("span", "r-desc"); marcar(d, (c.descripcion || "").slice(0, 170), palabras); b.appendChild(d);
    b.title = "Ver este CVE en la tabla de la semana";
    return b;
  }
  function itemIoc(e, palabras) {
    var i = e.dato;
    var b = opcion("r-ioc", function () { CTI.cargarIocs && CTI.cargarIocs(); irASeccion("s-iocs", "f-search", i.value); });
    var t = el("span", "r-titulo r-mono"); marcar(t, i.defanged || i.value, palabras); b.appendChild(t);
    var m = el("span", "r-meta");
    if (i.severity) m.appendChild(el("span", "r-chip c-sev-" + i.severity, "gravedad " + i.severity));
    m.appendChild(document.createTextNode([i.type, i.threat, (i.sources || [i.source]).join(", "), "confianza " + (i.level || "?")].filter(Boolean).join(" · ")));
    b.appendChild(m);
    b.title = "Ver este IOC en la tabla de indicadores";
    return b;
  }
  function itemSistema(e, palabras) {
    var s = e.dato;
    var b = opcion("r-sis", function () { irASeccion(e.destino); });
    var t = el("span", "r-titulo");
    marcar(t, s.nombre || s.lenguaje, palabras);
    b.appendChild(t);
    var txt = e.tipo === "sistema"
      ? [EST_SIS[s.estado] || "", (s.cves || 0) + " CVE esta semana", (s.criticos || 0) + " críticos"]
      : [(s.maliciosos || 0) + " paquetes maliciosos", (s.avisos || 0) + " avisos", s.registro || ""];
    b.appendChild(el("span", "r-meta", txt.filter(Boolean).join(" · ")));
    return b;
  }

  function grupo(titulo, lista, pintar, palabras, seccion, filtro, q) {
    if (!lista.length) return null;
    var g = el("div", "r-grupo");
    var h = el("p", "r-grupo-titulo");
    h.appendChild(el("span", null, titulo));
    h.appendChild(el("span", "r-n", String(lista.length)));
    g.appendChild(h);
    lista.slice(0, POR_GRUPO).forEach(function (e) { g.appendChild(pintar(e, palabras)); });
    if (lista.length > POR_GRUPO && seccion) {
      var mas = opcion("r-mas", function () { irASeccion(seccion, filtro, q); });
      mas.textContent = "Ver los " + lista.length + " en su sección";
      g.appendChild(mas);
    }
    return g;
  }

  function cargando() {
    var falta = [];
    if (!CTI.avisos) falta.push("avisos");
    if (!CTI.vulns) falta.push("CVE");
    if (!CTI.iocs) falta.push("IOCs");
    return falta;
  }

  function buscar() {
    var crudo = caja.value;
    var q = normalizar(crudo).trim().replace(/\s+/g, " ");
    actualizarUrl(crudo.trim());
    if (q === ultima && !resultados.hidden) return;
    ultima = q;
    resultados.textContent = "";
    opciones = []; activa = -1;
    caja.removeAttribute("aria-activedescendant");
    if (q.length < 2) { cerrar(); return; }
    if (!CTI.iocs && CTI.cargarIocs) CTI.cargarIocs();

    var palabras = q.split(" ");
    var id = identificador(q);
    var exacto = id ? q : "";
    var r = {
      cves: buscarEn(indice.cves, palabras, exacto),
      avisos: buscarEn(indice.avisos, palabras, exacto),
      iocs: buscarEn(indice.iocs, palabras, exacto),
      sistemas: buscarEn(indice.sistemas, palabras, "")
    };
    var total = r.cves.length + r.avisos.length + r.iocs.length + r.sistemas.length;

    // Veredicto para un identificador concreto: lo que de verdad se viene a preguntar
    if (id) {
      var v = el("div", "r-veredicto " + (total ? "v-si" : "v-no"));
      var falta = cargando();
      if (total) {
        var donde = [];
        if (r.iocs.length) donde.push(r.iocs.length === 1 ? "1 IOC" : r.iocs.length + " IOCs");
        if (r.cves.length) donde.push(r.cves.length === 1 ? "1 CVE" : r.cves.length + " CVE");
        if (r.avisos.length) donde.push(r.avisos.length === 1 ? "1 aviso" : r.avisos.length + " avisos");
        v.appendChild(el("strong", null, "Sí, aparece"));
        var ioc = r.iocs[0] && r.iocs[0].dato;
        var detalle = "En " + donde.join(", ") + ".";
        if (ioc && (r.iocs[0].valor === q || r.iocs[0].valor.split(":")[0] === q)) {
          detalle += " Es un IOC de " + (ioc.threat || "amenaza sin nombre") + " (" + (ioc.sources || [ioc.source]).join(", ") +
            ", confianza " + (ioc.level || "?") + ", visto " + (ioc.first_seen || "").slice(0, 10) + ").";
        }
        v.appendChild(el("span", null, " " + detalle));
      } else {
        v.appendChild(el("strong", null, "No aparece en los datos de hoy"));
        v.appendChild(el("span", null, falta.length
          ? " Aún se están cargando los " + falta.join(" y ") + "; vuelve a mirar en un momento."
          : " Revisados " + indice.avisos.length + " avisos, " + indice.cves.length + " CVE priorizados y " + indice.iocs.length + " IOCs. Que no esté aquí no quiere decir que sea seguro."));
      }
      resultados.appendChild(v);
    }

    [grupo("CVE de la semana", r.cves, itemCve, palabras, "s-cves", "v-search", crudo.trim()),
     grupo("Avisos", r.avisos, itemAviso, palabras, "s-avisos", "a-search", crudo.trim()),
     grupo("IOCs", r.iocs, itemIoc, palabras, "s-iocs", "f-search", crudo.trim()),
     grupo("Sistemas y lenguajes", r.sistemas, itemSistema, palabras, null, null, "")
    ].forEach(function (g) { if (g) resultados.appendChild(g); });

    if (!total && !id) {
      var nada = el("p", "r-nada", "Nada con «" + crudo.trim() + "».");
      var falta2 = cargando();
      if (falta2.length) nada.appendChild(el("span", null, " Aún se están cargando los " + falta2.join(" y ") + "."));
      else nada.appendChild(el("span", null, " Prueba con menos palabras o con el nombre del fabricante."));
      resultados.appendChild(nada);
    }
    resultados.hidden = false;
    caja.setAttribute("aria-expanded", "true");
  }

  function cerrar() {
    resultados.hidden = true;
    caja.setAttribute("aria-expanded", "false");
    caja.removeAttribute("aria-activedescendant");
    activa = -1;
  }

  function mover(paso) {
    if (!opciones.length) return;
    if (activa >= 0) opciones[activa].classList.remove("activa");
    activa = (activa + paso + opciones.length) % opciones.length;
    var o = opciones[activa];
    o.classList.add("activa");
    o.scrollIntoView({ block: "nearest" });
    caja.setAttribute("aria-activedescendant", o.id);
  }

  var urlTimer;
  function actualizarUrl(q) {
    clearTimeout(urlTimer);
    urlTimer = setTimeout(function () {
      try { history.replaceState(null, "", q ? "#q=" + encodeURIComponent(q) : location.pathname + location.search); } catch (e) { /* sin historial */ }
    }, 400);
  }

  function lanzar(q) {
    caja.value = q;
    ultima = null;
    buscar();
    caja.focus();
  }

  /* ── Búsquedas rápidas: los fabricantes con más CVE de la semana ────────── */
  function sugerencias() {
    var cont = $("q-sugerencias");
    if (!cont || !CTI.vulns || cont.childNodes.length) return;
    var cuenta = {};
    (CTI.vulns.cves || []).forEach(function (c) {
      var f = (c.fabricante || "").trim();
      if (!f || /^c[oó]digo abierto/i.test(f)) return;
      f = f.replace(/\s*\(plugins\)$/i, "");
      cuenta[f] = (cuenta[f] || 0) + (c.prioridad === "explotada" ? 5 : c.prioridad === "urgente" ? 3 : 1);
    });
    var top = Object.keys(cuenta).sort(function (a, b) { return cuenta[b] - cuenta[a]; }).slice(0, 6);
    if (!top.length) return;
    cont.appendChild(el("span", "sug-label", "Prueba:"));
    top.forEach(function (f) {
      var b = el("button", "sug", f);
      b.type = "button";
      b.addEventListener("click", function () { lanzar(f); });
      cont.appendChild(b);
    });
  }

  /* ── Gráficas ─────────────────────────────────────────────────────────── */
  function cuerpo(id) {
    var c = document.querySelector("#" + id + " .graf-cuerpo");
    if (c) c.textContent = "";
    return c;
  }

  function barrasH(id, filas, alPulsar) {
    // filas: [{etiqueta, valor, clase, titulo}]
    var c = cuerpo(id);
    if (!c) return;
    if (!filas.length) { c.appendChild(el("p", "graf-vacio", "Sin datos esta semana.")); return; }
    var max = Math.max.apply(null, filas.map(function (f) { return f.valor; })) || 1;
    var ul = el("ul", "barras");
    filas.forEach(function (f) {
      var li = el("li");
      var b = el("button", "barra");
      b.type = "button";
      b.title = f.titulo || (f.etiqueta + ": " + f.valor);
      b.appendChild(el("span", "barra-etq", f.etiqueta));
      var pista = el("span", "barra-pista");
      var s = svg("svg", { viewBox: "0 0 100 10", preserveAspectRatio: "none", "aria-hidden": "true", focusable: "false" });
      s.appendChild(svg("rect", { x: 0, y: 0, width: Math.max(1.5, 100 * f.valor / max).toFixed(2), height: 10, rx: 1.2, class: "barra-r " + (f.clase || "") }));
      pista.appendChild(s);
      b.appendChild(pista);
      b.appendChild(el("span", "barra-n", f.valor.toLocaleString("es-ES")));
      b.addEventListener("click", function () { alPulsar(f); });
      li.appendChild(b);
      ul.appendChild(li);
    });
    c.appendChild(ul);
  }

  function grafPrioridad() {
    var c = cuerpo("g-prioridad");
    if (!c || !CTI.vulns) return;
    var pp = (CTI.vulns.resumen || {}).por_prioridad || {};
    var orden = ["explotada", "urgente", "alta", "media", "baja"];
    var total = orden.reduce(function (t, k) { return t + (pp[k] || 0); }, 0);
    if (!total) { c.appendChild(el("p", "graf-vacio", "Sin CVE esta semana.")); return; }
    var s = svg("svg", { viewBox: "0 0 1000 40", preserveAspectRatio: "none", class: "pila", role: "img",
                         "aria-label": orden.map(function (k) { return PRIO_TXT[k] + " " + (pp[k] || 0); }).join(", ") });
    var x = 0;
    orden.forEach(function (k) {
      var w = 1000 * (pp[k] || 0) / total;
      if (!w) return;
      // las pocas explotadas tienen que verse aunque sean 2 de 2.900
      var ancho = Math.max(w, pp[k] ? 6 : 0);
      var r = svg("rect", { x: x.toFixed(1), y: 0, width: ancho.toFixed(1), height: 40, class: "seg c-" + k });
      var t = svg("title"); t.textContent = PRIO_TXT[k] + ": " + pp[k]; r.appendChild(t);
      s.appendChild(r);
      x += ancho;
    });
    c.appendChild(s);
    var ley = el("ul", "leyenda");
    orden.forEach(function (k) {
      var li = el("li");
      var b = el("button", "ley-item");
      b.type = "button";
      b.appendChild(el("i", "sw c-" + k));
      b.appendChild(el("span", null, PRIO_TXT[k]));
      b.appendChild(el("b", null, (pp[k] || 0).toLocaleString("es-ES")));
      b.title = "Ver los CVE con prioridad " + PRIO_TXT[k].toLowerCase();
      b.addEventListener("click", function () {
        $("v-prio").value = k;
        $("v-search").value = "";
        $("v-prio").dispatchEvent(new Event("input", { bubbles: true }));
        irASeccion("s-cves");
      });
      li.appendChild(b);
      ley.appendChild(li);
    });
    c.appendChild(ley);
  }

  function grafDias() {
    var c = cuerpo("g-dias");
    if (!c || !CTI.avisos) return;
    var hoy = new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate()));
    var dias = [];
    for (var i = 6; i >= 0; i--) {
      var d = new Date(hoy.getTime() - i * 864e5);
      dias.push({ clave: d.toISOString().slice(0, 10), letra: "DLMXJVS".charAt(d.getUTCDay()), total: 0, graves: 0 });
    }
    (CTI.avisos.avisos || []).forEach(function (a) {
      var k = (a.fecha || "").slice(0, 10);
      for (var j = 0; j < dias.length; j++) {
        if (dias[j].clave === k) {
          dias[j].total++;
          if (a.explotada || a.dia_cero || a.critica) dias[j].graves++;
        }
      }
    });
    var max = Math.max.apply(null, dias.map(function (d) { return d.total; })) || 1;
    var W = 280, H = 168, alto = 128, paso = W / 7, ancho = paso * 0.62;
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, class: "columnas", role: "img",
                         "aria-label": dias.map(function (d) { return d.clave + ": " + d.total + " avisos, " + d.graves + " graves"; }).join("; ") });
    dias.forEach(function (d, i) {
      var x = i * paso + (paso - ancho) / 2;
      var h = alto * d.total / max, hg = alto * d.graves / max;
      var g = svg("g");
      var t = svg("title"); t.textContent = fecha(d.clave) + ": " + d.total + " avisos (" + d.graves + " ya explotados, de día cero o críticos)";
      g.appendChild(t);
      g.appendChild(svg("rect", { x: x.toFixed(1), y: (20 + alto - h).toFixed(1), width: ancho.toFixed(1), height: Math.max(h, 1).toFixed(1), rx: 3, class: "col" }));
      if (hg) g.appendChild(svg("rect", { x: x.toFixed(1), y: (20 + alto - hg).toFixed(1), width: ancho.toFixed(1), height: hg.toFixed(1), rx: 3, class: "col-grave" }));
      var n = svg("text", { x: (x + ancho / 2).toFixed(1), y: (16 + alto - h).toFixed(1), class: "col-n", "text-anchor": "middle" });
      n.textContent = String(d.total);
      g.appendChild(n);
      var l = svg("text", { x: (x + ancho / 2).toFixed(1), y: H - 2, class: "col-l" + (i === 6 ? " hoy" : ""), "text-anchor": "middle" });
      l.textContent = i === 6 ? "hoy" : d.letra;
      g.appendChild(l);
      s.appendChild(g);
    });
    c.appendChild(s);
  }

  // Nombres cortos, como en la tabla de CVE (las tarjetas usan el largo)
  var CORTO = {
    microsoft: "Microsoft", linux: "Linux", apple: "Apple", android: "Android", navegadores: "Navegadores",
    red: "Red / VPN", iot: "Router / IoT", virtualizacion: "Virtualización / nube", ia: "IA / LLM",
    servidores: "Servidores", ics: "OT / ICS", empresarial: "Software empresarial", web: "Web / CMS",
    runtimes: "Lenguajes", oss: "Código abierto", otros: "Otros"
  };
  function grafSistemas() {
    if (!CTI.vulns) return;
    var filas = (CTI.vulns.sistemas || []).filter(function (x) { return x.categoria !== "otros"; }).map(function (x) {
      return { etiqueta: CORTO[x.categoria] || x.nombre, valor: x.cves || 0, cat: x.categoria,
               clase: x.estado === "explotacion_activa" ? "c-explotada" : x.estado === "riesgo_alto" ? "c-urgente" : "c-media",
               titulo: x.nombre + ": " + (x.cves || 0) + " CVE, " + (x.criticos || 0) + " críticos · " + (EST_SIS[x.estado] || "") };
    }).filter(function (f) { return f.valor > 0; }).sort(function (a, b) { return b.valor - a.valor; }).slice(0, 7);
    barrasH("g-sistemas", filas, function (f) {
      $("v-cat").value = f.cat;
      $("v-search").value = "";
      $("v-cat").dispatchEvent(new Event("input", { bubbles: true }));
      irASeccion("s-cves");
    });
  }

  function grafAmenazas() {
    if (!CTI.iocs) return;
    var cuenta = {};
    (CTI.iocs.iocs || []).forEach(function (i) {
      var t = (i.threat || "").trim();
      if (!t || /^(unknown|desconocid|n\/a|none)/i.test(t)) return;
      cuenta[t] = (cuenta[t] || 0) + 1;
    });
    var filas = Object.keys(cuenta).sort(function (a, b) { return cuenta[b] - cuenta[a]; }).slice(0, 7)
      .map(function (t) { return { etiqueta: t, valor: cuenta[t], clase: "c-ioc", titulo: t + ": " + cuenta[t] + " IOCs" }; });
    barrasH("g-amenazas", filas, function (f) { lanzar(f.etiqueta); });
  }

  /* ── Menú de secciones: cifras y sección actual ───────────────────────── */
  function cifra(id, n) { var x = $(id); if (x) x.textContent = n ? n.toLocaleString("es-ES") : ""; }

  function menu() {
    var enlaces = Array.prototype.slice.call(document.querySelectorAll(".secciones a"));
    if (!("IntersectionObserver" in window) || !enlaces.length) return;
    var visibles = {};
    var obs = new IntersectionObserver(function (entradas) {
      entradas.forEach(function (e) { visibles[e.target.id] = e.isIntersecting; });
      var actual = null;
      enlaces.forEach(function (a) { if (!actual && visibles[a.getAttribute("href").slice(1)]) actual = a; });
      enlaces.forEach(function (a) {
        if (a === actual) { a.setAttribute("aria-current", "true"); a.scrollIntoView({ block: "nearest", inline: "nearest" }); }
        else a.removeAttribute("aria-current");
      });
    }, { rootMargin: "-90px 0px -55% 0px" });
    enlaces.forEach(function (a) { var s = $(a.getAttribute("href").slice(1)); if (s) obs.observe(s); });
  }

  /* ── Arranque ─────────────────────────────────────────────────────────── */
  function alLlegar(nombre) {
    indexar(nombre);
    if (nombre === "vulns") { grafPrioridad(); grafSistemas(); sugerencias(); cifra("n-cves", (CTI.vulns.resumen || {}).cves); }
    if (nombre === "avisos") { grafDias(); cifra("n-avisos", (CTI.avisos.avisos || []).length); }
    if (nombre === "iocs") {
      grafAmenazas();
      cifra("n-iocs", (CTI.iocs.iocs || []).length);
      cifra("n-kev", (CTI.iocs.cisa_kev_recent || []).length);
    }
    if (caja && caja.value.trim().length >= 2) { ultima = null; buscar(); if (document.activeElement !== caja) cerrar(); }
  }

  function arrancar() {
    caja = $("q");
    resultados = $("q-resultados");
    if (!caja || !resultados) return;

    var t;
    caja.addEventListener("input", function () { clearTimeout(t); t = setTimeout(buscar, 70); });
    caja.addEventListener("focus", function () { if (caja.value.trim().length >= 2) { ultima = null; buscar(); } });
    caja.addEventListener("keydown", function (ev) {
      if (ev.key === "ArrowDown") { ev.preventDefault(); if (resultados.hidden) buscar(); mover(1); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); mover(-1); }
      else if (ev.key === "Enter") {
        ev.preventDefault();
        if (activa >= 0) opciones[activa].click();
        else if (opciones.length) opciones[0].click();
      } else if (ev.key === "Escape") {
        if (!resultados.hidden) cerrar(); else { caja.value = ""; actualizarUrl(""); }
      }
    });
    caja.addEventListener("blur", function () { setTimeout(function () { if (!resultados.contains(document.activeElement)) cerrar(); }, 120); });

    // «/» o Ctrl+K / Cmd+K para ir al buscador desde cualquier sitio
    document.addEventListener("keydown", function (ev) {
      var escribiendo = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "");
      if ((ev.key === "/" && !escribiendo) || ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k")) {
        ev.preventDefault();
        caja.focus();
        caja.select();
        window.scrollTo({ top: 0, behavior: "auto" });
      }
    });

    menu();

    ["vulns", "avisos", "iocs", "historico"].forEach(function (n) { if (CTI[n]) alLlegar(n); });
    document.addEventListener("cti:datos", function (ev) { alLlegar(ev.detail); });

    // Búsqueda compartida por enlace: …/#q=fortinet
    var m = /^#q=(.+)$/.exec(location.hash);
    if (m) {
      try { caja.value = decodeURIComponent(m[1]).slice(0, 200); } catch (e) { caja.value = ""; }
      if (caja.value) { caja.focus(); buscar(); }
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", arrancar);
  else arrancar();
})();
