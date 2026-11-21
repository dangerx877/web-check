/* NetCommander web dashboard. Vanilla JS, no external resources (CSP: script-src 'self'). */
"use strict";
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const state = { session: null, csrf: "", page: "dashboard", timer: null };
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const can = (perm) => !!state.session && state.session.permissions.includes(perm);

  // ------------------------------------------------------------------ formatting
  const fmtBytes = (n) => {
    if (n === null || n === undefined || n === "" || isNaN(n)) return "–";
    const u = ["B", "KB", "MB", "GB", "TB", "PB"]; let i = 0; n = Number(n);
    while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
  };
  const fmtPct = (n) => (n === null || n === undefined ? "–" : `${Number(n).toFixed(1)}%`);
  const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString() : "–");
  const ago = (t) => {
    if (!t) return "never"; const s = Date.now() / 1000 - t;
    if (s < 90) return `${Math.round(s)}s ago`; if (s < 5400) return `${Math.round(s / 60)}m ago`;
    if (s < 172800) return `${Math.round(s / 3600)}h ago`; return `${Math.round(s / 86400)}d ago`;
  };
  const dur = (s) => (s === null || s === undefined ? "–" : s > 86400 ? `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`);
  const pill = (s) => `<span class="pill s-${esc(s)}">${esc(String(s).replace(/_/g, " "))}</span>`;
  const bar = (pct) => {
    if (pct === null || pct === undefined) return "–";
    const cls = pct >= 90 ? "crit" : pct >= 80 ? "warn" : "";
    return `<div class="row gap-s"><div class="bar ${cls}"><span data-w="${Math.min(100, Math.max(0, Number(pct)))}"></span></div><span class="small">${fmtPct(pct)}</span></div>`;
  };
  const scoreCls = (n) => (n === null || n === undefined ? "unknown" : n >= 80 ? "ok" : n >= 50 ? "warning" : "critical");

  // ------------------------------------------------------------------ theme
  const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
  try { applyTheme(localStorage.getItem("nc-theme")); } catch (e) { /* storage unavailable */ }
  const toggleTheme = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark"; applyTheme(next);
    try { localStorage.setItem("nc-theme", next); } catch (e) { /* ignore */ }
  };

  // ------------------------------------------------------------------ UI helpers
  let toastTimer = null;
  const toast = (msg) => { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), 4200); };

  function modal(title, bodyHtml, okText = "OK", danger = false) {
    return new Promise((resolve) => {
      const d = $("#modal"); $("#modal-title").textContent = title; $("#modal-body").innerHTML = bodyHtml;
      const ok = $("#modal-ok"); ok.textContent = okText; ok.className = danger ? "danger" : "primary";
      const form = $("#modal-form");
      const done = (val) => { form.onsubmit = null; $("#modal-cancel").onclick = null; d.close(); resolve(val); };
      form.onsubmit = (ev) => { ev.preventDefault(); const data = {}; new FormData(form).forEach((v, k) => { data[k] = v; }); done(data); };
      $("#modal-cancel").onclick = () => done(null);
      d.oncancel = (ev) => { ev.preventDefault(); done(null); };
      d.showModal(); const first = $("#modal-body input, #modal-body select, #modal-body textarea"); if (first) first.focus();
    });
  }

  // ------------------------------------------------------------------ API
  async function api(method, path, body, confirm) {
    const opts = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (method !== "GET") { opts.headers["X-CSRF-Token"] = state.csrf; opts.headers["Content-Type"] = "application/json"; }
    if (body !== undefined || confirm) opts.body = JSON.stringify({ ...(body || {}), ...(confirm ? { confirm } : {}) });
    const res = await fetch(path, opts);
    if (res.status === 401 && path !== "/api/login") { showLogin(); throw new Error("Signed out"); }
    const ctype = res.headers.get("Content-Type") || "";
    const data = ctype.includes("json") ? await res.json() : await res.text();
    if (res.status === 409 && data && data.confirm_token) {
      const d = data.details || {};
      const ok = await modal("Confirm action", `<p>${esc(data.error)}</p><p class="warnbox">Risk: <b>${esc(d.risk)}</b> · target <span class="mono">${esc(d.target)}</span>. This is recorded in the audit log.</p>`, "Confirm", d.risk === "destructive");
      if (!ok) throw new Error("Cancelled");
      return api(method, path, body, data.confirm_token);
    }
    if (!res.ok) { const err = new Error((data && data.error) || `HTTP ${res.status}`); err.data = data; throw err; }
    return data;
  }
  const safe = async (fn) => { try { return await fn(); } catch (e) { if (e.message !== "Cancelled" && e.message !== "Signed out") toast(e.message); return undefined; } };
  async function waitTask(task, label) {
    toast(`${label} started…`);
    for (let i = 0; i < 600; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const t = await api("GET", `/api/tasks/${task.id}`);
      if (t.status === "done") { toast(`${label} finished`); return t; }
      if (t.status === "failed") { toast(`${label} failed: ${t.error}`); return t; }
    }
    return null;
  }

  // ------------------------------------------------------------------ charts
  function lineChart(points, opts = {}) {
    if (!points || points.length < 2) return `<div class="empty small">Not enough data yet</div>`;
    const W = 600, H = 140, P = 26;
    const xs = points.map((p) => p[0]), ys = points.map((p) => p[1]);
    const x0 = Math.min(...xs), x1 = Math.max(...xs);
    let y0 = opts.min ?? Math.min(...ys), y1 = opts.max ?? Math.max(...ys); if (y1 === y0) { y1 = y0 + 1; }
    const X = (x) => P + ((x - x0) / (x1 - x0 || 1)) * (W - P * 2), Y = (y) => H - P + 4 - ((y - y0) / (y1 - y0)) * (H - P * 1.5);
    const d = points.map((p, i) => `${i ? "L" : "M"}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join("");
    const area = `${d}L${X(x1).toFixed(1)},${H - P + 4}L${X(x0).toFixed(1)},${H - P + 4}Z`;
    const fmt = opts.fmt || ((v) => Number(v).toFixed(1));
    return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(opts.label || "chart")}">
      <line class="grid" x1="${P}" x2="${W - P}" y1="${Y(y1)}" y2="${Y(y1)}"/><line class="grid" x1="${P}" x2="${W - P}" y1="${Y(y0)}" y2="${Y(y0)}"/>
      <text x="2" y="${Y(y1) + 3}">${esc(fmt(y1))}</text><text x="2" y="${Y(y0) + 3}">${esc(fmt(y0))}</text>
      <path class="area" d="${area}"/><path class="line" d="${d}"/>
      <text x="${P}" y="${H - 4}">${esc(new Date(x0 * 1000).toLocaleTimeString())}</text><text x="${W - P - 60}" y="${H - 4}">${esc(new Date(x1 * 1000).toLocaleTimeString())}</text></svg>`;
  }

  // ------------------------------------------------------------------ table helper
  function table(cols, rows, onClick) {
    if (!rows.length) return `<div class="table-wrap"><div class="empty">Nothing here yet.</div></div>`;
    const head = cols.map((c) => `<th>${esc(c.label)}</th>`).join("");
    const body = rows.map((r, i) => `<tr ${onClick ? `class="click" data-i="${i}"` : ""}>${cols.map((c) => `<td class="${c.wrap ? "wrap" : ""}">${c.render ? c.render(r) : esc(r[c.key])}</td>`).join("")}</tr>`).join("");
    return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }
  function bindRows(root, rows, onClick) { root.querySelectorAll("tbody tr.click").forEach((tr) => { tr.onclick = (ev) => { if (ev.target.closest("button")) return; onClick(rows[Number(tr.dataset.i)]); }; }); }

  // ------------------------------------------------------------------ pages
  const PAGES = [
    ["dashboard", "Dashboard", "▦"], ["inventory", "Inventory", "☰"], ["discovery", "Discovery", "⌕"],
    ["servers", "Servers", "▤"], ["virtualization", "Virtualization", "◫"], ["containers", "Containers", "▣"],
    ["storage", "Storage", "◉"], ["network", "Network", "⇄"], ["monitoring", "Monitoring", "♥"],
    ["automation", "Automation", "⚙"], ["backups", "Backups", "⟲"], ["integrations", "Integrations", "⊕"],
    ["security", "Security", "⚿"],
  ];

  function renderNav(alertCount) {
    $("#nav").innerHTML = PAGES.map(([id, label, icon]) => `<a href="#${id}" class="${state.page === id ? "active" : ""}" data-page="${id}"><span aria-hidden="true">${icon}</span>${esc(label)}${id === "monitoring" && alertCount ? `<span class="badge">${alertCount}</span>` : ""}</a>`).join("");
  }

  async function route() {
    const page = (location.hash || "#dashboard").slice(1).split("?")[0];
    state.page = PAGES.some((p) => p[0] === page) ? page : (page.startsWith("asset/") ? "inventory" : "dashboard");
    clearInterval(state.timer);
    renderNav(state.alertCount || 0);
    $("#sidebar").classList.remove("open");
    const view = $("#view");
    const title = PAGES.find((p) => p[0] === state.page)[1];
    $("#page-title").textContent = page.startsWith("asset/") ? "Asset details" : title;
    view.innerHTML = `<div class="empty">Loading…</div>`;
    try {
      if (page.startsWith("asset/")) await pageAsset(view, decodeURIComponent(page.slice(6)));
      else await VIEWS[state.page](view);
    } catch (e) { if (e.message !== "Signed out") view.innerHTML = `<div class="card error">${esc(e.message)}</div>`; }
  }

  const VIEWS = {};

  // CSP forbids inline style attributes; dynamic sizes are applied through the CSSOM instead.
  function applyDynamicStyles(root) {
    root.querySelectorAll("[data-w]").forEach((el) => { el.style.width = `${el.dataset.w}%`; el.removeAttribute("data-w"); });
    root.querySelectorAll("[data-minw]").forEach((el) => { el.style.minWidth = `${el.dataset.minw}px`; el.removeAttribute("data-minw"); });
  }
  new MutationObserver(() => applyDynamicStyles(document.body)).observe(document.body, { childList: true, subtree: true });

  VIEWS.dashboard = async (view) => {
    const render = async () => {
      const d = await api("GET", "/api/dashboard");
      state.alertCount = d.alerts.critical + d.alerts.warning; renderNav(state.alertCount);
      const t = d.totals, st = d.storage;
      const kinds = Object.entries(t.by_kind).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="pill s-unknown">${esc(k)} ${n}</span>`).join(" ");
      const grp = (label, g) => `<div class="card"><h3>${label}</h3><div class="stat">${g.online}<small> / ${g.total} online</small></div><div class="small">${g.offline ? `<span class="s-offline">${g.offline} offline</span> · ` : ""}${g.degraded ? `<span class="s-degraded">${g.degraded} degraded</span> · ` : ""}health ${g.health ?? "–"}</div></div>`;
      view.innerHTML = `
        <div class="grid cards">
          <div class="card"><h3>Infrastructure health</h3><div class="score s-${scoreCls(d.health)}">${d.health ?? "–"}</div><div class="small muted">score 0–100</div></div>
          <div class="card"><h3>Devices</h3><div class="stat">${t.devices}</div><div class="small"><span class="s-online">${t.online} online</span> · <span class="s-offline">${t.offline} offline</span> · <span class="s-degraded">${t.degraded} degraded</span></div></div>
          ${grp("Servers", d.servers)}${grp("Network", d.network)}${grp("NAS / storage", d.storage_health)}
          <div class="card"><h3>Virtual machines</h3><div class="stat">${d.vms.running}<small> / ${d.vms.total} running</small></div></div>
          <div class="card"><h3>Containers</h3><div class="stat">${d.containers.running}<small> / ${d.containers.total} running</small></div><div class="small">${d.containers.unhealthy ? `<span class="s-unhealthy">${d.containers.unhealthy} unhealthy</span>` : "all healthy"}</div></div>
          <div class="card"><h3>Storage used</h3><div class="stat">${fmtBytes(st.used)}<small> / ${fmtBytes(st.total)}</small></div>${bar(st.total ? (100 * st.used) / st.total : null)}</div>
          <div class="card"><h3>Active alerts</h3><div class="stat"><span class="s-critical">${d.alerts.critical}</span> <small>critical</small> <span class="s-warning">${d.alerts.warning}</span> <small>warning</small></div></div>
          <div class="card"><h3>Backups</h3><div class="stat">${d.backups.ok}<small> / ${d.backups.total} OK</small></div><div class="small">${d.backups.problems ? `<span class="s-failed">${d.backups.problems} need attention</span>` : "no problems"}</div></div>
        </div>
        <div class="card mt"><h3>Inventory by type</h3><div class="row">${kinds || '<span class="muted">No assets yet — run Discovery or add an integration.</span>'}</div></div>
        <div class="grid two mt">
          <div class="card"><h3>Active alerts</h3>${d.alerts.items.length ? `<ul class="events">${d.alerts.items.map((a) => `<li>${pill(a.severity)} ${esc(a.message)} <span class="muted small">${ago(a.last)}</span></li>`).join("")}</ul>` : '<div class="empty">No active alerts</div>'}</div>
          <div class="card"><h3>Recent events</h3><ul class="events">${d.events.map((e) => `<li>${pill(e.severity)} ${esc(e.message)} <span class="muted small">${ago(e.ts)}</span></li>`).join("") || '<li class="muted">No events yet</li>'}</ul></div>
          <div class="card"><h3>Highest CPU</h3>${table([{ label: "Asset", render: (r) => `<a href="#asset/${encodeURIComponent(r.id)}">${esc(r.name)}</a>` }, { label: "Type", key: "kind" }, { label: "CPU", render: (r) => bar(r.cpu_pct) }], d.top_cpu)}</div>
          <div class="card"><h3>Integrations</h3>${table([{ label: "Name", key: "name" }, { label: "Kind", key: "kind" }, { label: "Status", render: (r) => pill(r.ok === null ? "unknown" : r.ok ? "ok" : "failed") }, { label: "Last poll", render: (r) => ago(r.last_poll) }, { label: "Error", key: "last_error", wrap: true }], d.integrations)}</div>
        </div>`;
    };
    await render();
    state.timer = setInterval(() => safe(render), 30000);
  };

  VIEWS.inventory = async (view) => {
    const q = new URLSearchParams(location.hash.split("?")[1] || "");
    view.innerHTML = `<div class="toolbar">
        <input id="f-q" type="search" placeholder="Filter (name, IP, MAC, OS, tag…)" value="${esc(q.get("q") || "")}">
        <select id="f-kind"><option value="">All types</option>${["server", "desktop", "laptop", "router", "switch", "firewall", "access_point", "nas", "hypervisor", "vm", "container", "docker_host", "appliance", "printer", "iot", "service", "unknown"].map((k) => `<option>${k}</option>`).join("")}</select>
        <select id="f-status"><option value="">Any status</option>${["online", "offline", "degraded", "stopped", "unknown"].map((k) => `<option>${k}</option>`).join("")}</select>
        <span class="spacer"></span>
        ${can("edit_inventory") ? '<button id="add-asset" class="primary">Add asset</button><button id="import-csv">Import CSV</button>' : ""}
        <a href="/api/inventory/export?format=csv" download="inventory.csv"><button type="button">Export CSV</button></a>
        <a href="/api/inventory/export?format=json" download="inventory.json"><button type="button">Export JSON</button></a>
      </div><div id="inv-table"></div>`;
    const load = async () => {
      const p = new URLSearchParams({ q: $("#f-q").value, kind: $("#f-kind").value, status: $("#f-status").value });
      const rows = await api("GET", `/api/assets?${p}`);
      const el = $("#inv-table");
      el.innerHTML = table([
        { label: "Name", render: (r) => `<b>${esc(r.name)}</b>` }, { label: "Type", key: "kind" }, { label: "Status", render: (r) => pill(r.status) },
        { label: "Health", render: (r) => `<span class="s-${scoreCls(r.health)}">${r.health}</span>` }, { label: "IP", render: (r) => `<span class="mono">${esc(r.ip)}</span>` },
        { label: "MAC", render: (r) => `<span class="mono">${esc(r.mac)}</span>` }, { label: "OS", key: "os" }, { label: "Vendor", key: "manufacturer" },
        { label: "CPU", render: (r) => bar(r.cpu_pct) }, { label: "Memory", render: (r) => bar(r.mem_pct) }, { label: "Storage", render: (r) => bar(r.storage_pct) },
        { label: "Source", key: "source" }, { label: "Last seen", render: (r) => ago(r.last_seen) },
      ], rows, true);
      bindRows(el, rows, (r) => { location.hash = `asset/${encodeURIComponent(r.id)}`; });
    };
    let deb = null;
    $("#f-q").oninput = () => { clearTimeout(deb); deb = setTimeout(() => safe(load), 250); };
    $("#f-kind").onchange = $("#f-status").onchange = () => safe(load);
    if ($("#add-asset")) $("#add-asset").onclick = () => safe(async () => {
      const f = await modal("Add asset", assetForm({}), "Create");
      if (!f) return;
      await api("POST", "/api/assets", cleanAsset(f)); toast("Asset created"); await load();
    });
    if ($("#import-csv")) $("#import-csv").onclick = () => safe(async () => {
      const f = await modal("Import CSV", `<p class="small muted">Columns: name, kind, ip, mac, hostname, os, manufacturer, model, location, tags (separated by ;), notes</p><label>CSV<textarea name="csv" required>name,kind,ip,tags\n</textarea></label>`, "Import");
      if (!f) return; const r = await api("POST", "/api/assets/import", { csv: f.csv });
      toast(`${r.created} created${r.problems.length ? `, ${r.problems.length} problems: ${r.problems[0]}` : ""}`); await load();
    });
    await load();
  };

  const assetForm = (a) => `
    <label>Name<input name="name" required value="${esc(a.name)}"></label>
    <label>Type<select name="kind">${["server", "desktop", "laptop", "router", "switch", "firewall", "access_point", "nas", "storage", "hypervisor", "vm", "container", "docker_host", "appliance", "printer", "iot", "service", "unknown"].map((k) => `<option ${a.kind === k ? "selected" : ""}>${k}</option>`).join("")}</select></label>
    <div class="grid two"><label>IP address<input name="ip" value="${esc(a.ip)}"></label><label>MAC address<input name="mac" value="${esc(a.mac)}"></label></div>
    <div class="grid two"><label>Hostname<input name="hostname" value="${esc(a.hostname)}"></label><label>Operating system<input name="os" value="${esc(a.os)}"></label></div>
    <div class="grid two"><label>Manufacturer<input name="manufacturer" value="${esc(a.manufacturer)}"></label><label>Model<input name="model" value="${esc(a.model)}"></label></div>
    <div class="grid two"><label>Location<input name="location" value="${esc(a.location)}"></label><label>Tags (comma separated)<input name="tags" value="${esc((a.tags || []).join(", "))}"></label></div>
    <label>Notes<textarea name="notes" class="h-60">${esc(a.notes)}</textarea></label>`;
  const cleanAsset = (f) => { const o = {}; for (const [k, v] of Object.entries(f)) { if (k === "tags") o.tags = v.split(",").map((s) => s.trim()).filter(Boolean); else if (v !== "") o[k] = v; } return o; };

  async function pageAsset(view, id) {
    const a = await api("GET", `/api/assets/${encodeURIComponent(id)}`);
    const editable = can("edit_inventory") && !id.startsWith("net-");
    const facts = [["Type", a.kind], ["Status", pill(a.status)], ["Health", a.health], ["IP", a.ip], ["MAC", a.mac], ["Hostname", a.hostname], ["OS", a.os],
      ["Hardware", [a.manufacturer, a.model].filter(Boolean).join(" ")], ["CPU", [a.cpu_model, a.cpu_cores ? `${a.cpu_cores} cores` : ""].filter(Boolean).join(" · ")],
      ["Memory", a.mem_total ? `${fmtBytes(a.mem_used)} / ${fmtBytes(a.mem_total)}` : ""], ["Storage", a.storage_total ? `${fmtBytes(a.storage_used)} / ${fmtBytes(a.storage_total)}` : ""],
      ["Uptime", a.uptime_s ? dur(a.uptime_s) : ""], ["Location", a.location], ["Tags", (a.tags || []).join(", ")], ["Source", a.source], ["Integration", a.integration],
      ["First seen", fmtTime(a.first_seen)], ["Last seen", fmtTime(a.last_seen)], ["Locked fields", (a.locked || []).join(", ")]];
    const metricNames = Object.keys(a.metrics || {}).filter((m) => !m.startsWith("pool.")).sort();
    view.innerHTML = `<div class="toolbar"><a href="#inventory">← Inventory</a><span class="spacer"></span>
        ${editable ? '<button id="edit">Edit</button><button id="link">Link…</button><button id="mgmt">Management…</button>' : ""}
        ${can("discover") && ((a.management || {}).ssh || (a.management || {}).winrm) ? '<button id="collect">Collect now</button>' : ""}
        ${a.ip || a.hostname ? '<button id="conn">Connectivity test</button>' : ""}
        ${editable ? '<button id="del" class="danger">Delete</button>' : ""}</div>
      <div class="grid two">
        <div class="card"><h3>${esc(a.name)}</h3><dl class="kv">${facts.filter((f) => f[1] !== "" && f[1] !== undefined && f[1] !== null).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${k === "Status" ? v : esc(v)}</dd>`).join("")}</dl>
          ${a.notes ? `<p>${esc(a.notes)}</p>` : ""}<div id="conn-out"></div></div>
        <div class="card"><h3>Latest metrics</h3>${metricNames.length ? `<dl class="kv">${metricNames.map((m) => `<dt>${esc(m)}</dt><dd>${m.endsWith("_bytes") ? fmtBytes(a.metrics[m]) : esc(Math.round(a.metrics[m] * 100) / 100)}</dd>`).join("")}</dl>
          <label>Graph<select id="metric-pick">${metricNames.map((m) => `<option>${esc(m)}</option>`).join("")}</select></label><div id="metric-chart"></div>` : '<div class="empty">No metrics yet</div>'}</div>
        <div class="card"><h3>Alerts</h3>${a.alerts.length ? `<ul class="events">${a.alerts.map((x) => `<li>${pill(x.severity)} ${esc(x.message)}</li>`).join("")}</ul>` : '<div class="empty">No active alerts</div>'}</div>
        <div class="card"><h3>Relationships</h3>${a.parent ? `<p>Runs on <a href="#asset/${encodeURIComponent(a.parent)}">${esc(a.parent)}</a></p>` : ""}
          ${(a.links || []).map((l) => `<div>${esc(l.type.replace(/_/g, " "))} <a href="#asset/${encodeURIComponent(l.to)}">${esc(l.to)}</a> ${l.port ? `<span class="mono">${esc(l.port)}</span>` : ""}</div>`).join("")}
          ${a.children.length ? `<h4 class="mt-s">Hosts</h4>${a.children.map((c) => `<div><a href="#asset/${encodeURIComponent(c.id)}">${esc(c.name)}</a> ${pill(c.status)}</div>`).join("")}` : ""}
          ${!a.parent && !(a.links || []).length && !a.children.length ? '<div class="empty">No relationships</div>' : ""}</div>
        ${(a.services || []).length ? `<div class="card"><h3>Services</h3>${table([{ label: "Name", render: (s) => esc(s.name || s.port) }, { label: "State", render: (s) => esc(s.state || s.proto || "") }, { label: "Detail", render: (s) => esc(s.banner || s.description || "") , wrap: true }], a.services.slice(0, 80))}</div>` : ""}
        ${(a.interfaces || []).length ? `<div class="card"><h3>Network interfaces</h3>${table([{ label: "Name", key: "name" }, { label: "MAC", render: (i) => `<span class="mono">${esc(i.mac)}</span>` }, { label: "Addresses", render: (i) => esc((i.addresses || []).join(", ")), wrap: true }, { label: "RX", render: (i) => fmtBytes(i.rx_bytes) }, { label: "TX", render: (i) => fmtBytes(i.tx_bytes) }], a.interfaces)}</div>` : ""}
        <div class="card"><h3>Events</h3><ul class="events">${a.events.map((e) => `<li>${pill(e.severity)} ${esc(e.message)} <span class="muted small">${ago(e.ts)}</span></li>`).join("") || '<li class="muted">No events</li>'}</ul></div>
      </div>`;
    const drawMetric = async () => { const m = $("#metric-pick").value; const pts = await api("GET", `/api/metrics?${new URLSearchParams({ target: id, metric: m, hours: 24 })}`); $("#metric-chart").innerHTML = lineChart(pts, { label: m, fmt: m.endsWith("_bytes") ? (v) => `${fmtBytes(v)}/s` : undefined }); };
    if ($("#metric-pick")) { $("#metric-pick").onchange = () => safe(drawMetric); safe(drawMetric); }
    if ($("#edit")) $("#edit").onclick = () => safe(async () => { const f = await modal("Edit asset", assetForm(a), "Save"); if (!f) return; await api("PATCH", `/api/assets/${encodeURIComponent(id)}`, cleanAsset(f)); toast("Saved (edited fields are now locked against discovery)"); route(); });
    if ($("#del")) $("#del").onclick = () => safe(async () => { await api("DELETE", `/api/assets/${encodeURIComponent(id)}`, {}); toast("Deleted"); location.hash = "inventory"; });
    if ($("#link")) $("#link").onclick = () => safe(async () => {
      const all = await api("GET", "/api/assets");
      const f = await modal("Link to another asset", `<label>Relationship<select name="type">${["connected_to", "runs_on", "stores_on", "depends_on", "backs_up_to", "member_of"].map((t) => `<option>${t}</option>`).join("")}</select></label>
        <label>Target<select name="to">${all.filter((x) => x.id !== id).map((x) => `<option value="${esc(x.id)}">${esc(x.name)} (${esc(x.kind)})</option>`).join("")}</select></label><label>Port / detail (optional)<input name="port" placeholder="e.g. Gi1/0/12"></label>`, "Link");
      if (!f) return; await api("POST", `/api/assets/${encodeURIComponent(id)}/link`, f); toast("Linked"); route();
    });
    if ($("#mgmt")) $("#mgmt").onclick = () => safe(async () => {
      const m = a.management || {}; const ssh = m.ssh || {}, win = m.winrm || {};
      const f = await modal("Management access", `<p class="small muted">Passwords are encrypted in the vault; only a reference is stored with the asset. SSH host keys must be trusted first (Security page).</p>
        <label>Protocol<select name="proto"><option value="ssh" ${m.winrm ? "" : "selected"}>SSH (Linux/Unix)</option><option value="winrm" ${m.winrm ? "selected" : ""}>WinRM / PowerShell (Windows)</option><option value="none">None (remove)</option></select></label>
        <div class="grid two"><label>Host<input name="host" value="${esc(ssh.host || win.host || a.ip)}"></label><label>Port<input name="port" value="${esc(ssh.port || win.port || "")}" placeholder="22 / 5986"></label></div>
        <label>Username<input name="username" value="${esc(ssh.username || win.username || "")}"></label>
        <label>Password (leave empty to keep / use a key)<input name="password" type="password" autocomplete="new-password"></label>
        <label>SSH private key file on the NetCommander host (optional)<input name="key_file" value="${esc(ssh.key_file || "")}"></label>`, "Save");
      if (!f) return;
      let management = {};
      if (f.proto !== "none") {
        const conf = { host: f.host, username: f.username };
        if (f.port) conf.port = Number(f.port);
        if (f.key_file && f.proto === "ssh") conf.key_file = f.key_file;
        const old = (m[f.proto] || {}).password_ref;
        if (f.password) { const ref = `asset.${id}.${f.proto}`; await api("POST", "/api/secrets", { ref, value: f.password }); conf.password_ref = ref; } else if (old) conf.password_ref = old;
        management = { [f.proto]: conf };
      }
      await api("PATCH", `/api/assets/${encodeURIComponent(id)}`, { management }); toast("Management settings saved"); route();
    });
    if ($("#collect")) $("#collect").onclick = () => safe(async () => { const t = await api("POST", `/api/assets/${encodeURIComponent(id)}/collect`, {}); await waitTask(t, "Collection"); route(); });
    if ($("#conn")) $("#conn").onclick = () => safe(async () => { const r = await api("GET", `/api/assets/${encodeURIComponent(id)}/connectivity`); $("#conn-out").innerHTML = `<h4 class="mt">Connectivity</h4><dl class="kv">${Object.entries(r.ports).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${pill(v === "open" ? "ok" : v === "closed" ? "stopped" : "unknown")} ${esc(v)}</dd>`).join("")}</dl><p class="small">${r.reachable ? `Reachable${r.rtt_ms ? ` · ${r.rtt_ms} ms` : ""}` : "Not reachable"}</p>`; });
  }

  VIEWS.discovery = async (view) => {
    view.innerHTML = `<div class="grid two"><div class="card"><h3>Network sweep</h3>
        <p class="small muted">Read-only: TCP connection probes on common management ports, SSH/HTTP banners, ARP table and reverse DNS. No credentials are sent. Only scan networks you own.</p>
        <form id="disc-form"><label>Targets (CIDR, ranges or addresses — one per line)<textarea name="targets" class="h-80" placeholder="192.168.1.0/24&#10;10.0.0.10-40">${esc(localGet("nc-disc") || "")}</textarea></label>
        <button class="primary" ${can("discover") ? "" : "disabled"}>Start discovery</button></form><div id="disc-out"></div></div>
        <div class="card"><h3>Recently discovered</h3><div id="disc-recent"></div></div></div>`;
    const recent = async () => {
      const rows = (await api("GET", "/api/assets?source=discovery")).sort((a, b) => (b.first_seen || 0) - (a.first_seen || 0)).slice(0, 50);
      $("#disc-recent").innerHTML = table([{ label: "Name", key: "name" }, { label: "IP", render: (r) => `<span class="mono">${esc(r.ip)}</span>` }, { label: "Type", render: (r) => `${esc(r.kind)} <span class="muted small">${esc((r.extra || {}).confidence || "")}</span>` }, { label: "Vendor", key: "manufacturer" }, { label: "Ports", render: (r) => esc(((r.extra || {}).open_ports || []).join(", ")) }], rows, true);
      bindRows($("#disc-recent"), rows, (r) => { location.hash = `asset/${encodeURIComponent(r.id)}`; });
    };
    $("#disc-form").onsubmit = (ev) => { ev.preventDefault(); safe(async () => {
      const targets = ev.target.targets.value.split(/[\s,]+/).filter(Boolean); localSet("nc-disc", ev.target.targets.value);
      const t = await api("POST", "/api/discovery", { targets }); const done = await waitTask(t, "Discovery");
      if (done && done.result) $("#disc-out").innerHTML = `<p>${done.result.alive} hosts alive, ${done.result.new} new.</p>`; await recent();
    }); };
    await recent();
  };
  const localGet = (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } };
  const localSet = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } };

  VIEWS.servers = async (view) => {
    const rows = await api("GET", "/api/assets?q=");
    const srv = rows.filter((r) => ["server", "hypervisor", "docker_host", "desktop", "laptop"].includes(r.kind));
    view.innerHTML = `<p class="small muted">Servers with SSH or WinRM management settings are collected automatically (CPU, memory, disks, network, services, processes) using a fixed read-only command set. Open a server and choose <b>Management…</b> to configure access.</p>
      ${table([{ label: "Name", render: (r) => `<b>${esc(r.name)}</b>` }, { label: "Status", render: (r) => pill(r.status) }, { label: "OS", key: "os" }, { label: "Access", render: (r) => esc(Object.keys(r.management || {}).join(", ") || "–") },
        { label: "CPU", render: (r) => bar(r.cpu_pct) }, { label: "Memory", render: (r) => bar(r.mem_pct) }, { label: "Disk", render: (r) => bar(r.storage_pct) }, { label: "Uptime", render: (r) => dur(r.uptime_s) },
        { label: "Failed services", render: (r) => esc((((r.extra || {}).details || {}).failed_services || []).join(", ")) }, { label: "Collected", render: (r) => ago((r.extra || {}).collected) }], srv, true)}
      <div id="srv-detail"></div>`;
    bindRows(view, srv, (r) => safe(async () => {
      const d = await api("GET", `/api/assets/${encodeURIComponent(r.id)}/server`); const det = d.details || {};
      $("#srv-detail").innerHTML = `<div class="grid two mt"><div class="card"><h3>${esc(r.name)} — disks</h3>${table([{ label: "Mount", key: "mount" }, { label: "Filesystem", key: "filesystem" }, { label: "Size", render: (x) => fmtBytes(x.total) }, { label: "Used", render: (x) => bar(x.pct) }], det.disks || [])}</div>
        <div class="card"><h3>Top processes</h3>${table([{ label: "PID", key: "pid" }, { label: "Command", key: "command", wrap: true }, { label: "CPU %", render: (x) => esc(x.cpu_pct ?? x.cpu_seconds ?? "") }, { label: "RSS", render: (x) => fmtBytes(x.rss) }], det.processes || [])}</div>
        ${(d.errors || []).length ? `<div class="card"><h3>Collection warnings</h3><pre>${esc(d.errors.join("\n"))}</pre></div>` : ""}</div>`;
    }));
  };

  VIEWS.virtualization = async (view) => {
    const [assets, ints] = await Promise.all([api("GET", "/api/assets"), api("GET", "/api/integrations")]);
    const hv = ints.filter((i) => i.category === "hypervisor");
    const hosts = assets.filter((a) => a.kind === "hypervisor");
    const vms = assets.filter((a) => (a.kind === "vm" || (a.kind === "container" && (a.extra || {}).vm_type === "lxc")) && hv.some((i) => i.id === a.integration));
    view.innerHTML = `${hv.length ? "" : '<div class="card">No hypervisor integrations yet. Add Proxmox, ESXi, Hyper-V, VirtualBox or libvirt under <a href="#integrations">Integrations</a>.</div>'}
      <h3 class="mt-s">Hosts</h3>${table([{ label: "Host", key: "name" }, { label: "Status", render: (r) => pill(r.status) }, { label: "Platform", render: (r) => esc((r.extra || {}).platform) }, { label: "CPU", render: (r) => bar(r.cpu_pct) }, { label: "Memory", render: (r) => bar(r.mem_pct) }, { label: "Storage", render: (r) => bar(r.storage_pct) },
        { label: "VMs (running)", render: (r) => { const al = (r.extra || {}).allocation || {}; return `${al.vms ?? "–"} (${al.running ?? "–"})`; } }, { label: "vCPU ratio", render: (r) => esc(((r.extra || {}).allocation || {}).vcpu_ratio ?? "–") }, { label: "RAM assigned", render: (r) => { const al = (r.extra || {}).allocation || {}; return al.mem_ratio !== undefined && al.mem_ratio !== null ? `${Math.round(al.mem_ratio * 100)}%` : "–"; } }], hosts)}
      <h3 class="mt">Virtual machines</h3><div class="toolbar"><input id="vm-q" type="search" placeholder="Filter VMs"></div><div id="vm-table"></div><div id="vm-detail"></div>`;
    const draw = () => {
      const t = $("#vm-q").value.toLowerCase(); const rows = vms.filter((v) => !t || `${v.name} ${v.os} ${(v.extra || {}).hypervisor_host}`.toLowerCase().includes(t));
      $("#vm-table").innerHTML = table([{ label: "Name", render: (r) => `<b>${esc(r.name)}</b>${(r.extra || {}).template ? ' <span class="muted small">template</span>' : ""}` }, { label: "Type", render: (r) => esc((r.extra || {}).vm_type) }, { label: "Host", render: (r) => esc((r.extra || {}).hypervisor_host) }, { label: "Status", render: (r) => pill(r.status) },
        { label: "vCPU", key: "cpu_cores" }, { label: "CPU", render: (r) => bar(r.cpu_pct) }, { label: "Memory", render: (r) => r.mem_total ? `${fmtBytes(r.mem_used)} / ${fmtBytes(r.mem_total)}` : "–" }, { label: "Disk", render: (r) => fmtBytes(r.storage_total) }, { label: "Uptime", render: (r) => dur(r.uptime_s) },
        { label: "", render: (r) => can("control_workloads") ? `<button class="small" data-act="start" data-id="${esc(r.id)}">Start</button> <button class="small" data-act="shutdown" data-id="${esc(r.id)}">Shutdown</button> <button class="small" data-act="reboot" data-id="${esc(r.id)}">Reboot</button> <button class="small danger" data-act="stop" data-id="${esc(r.id)}">Stop</button>` : "" }], rows, true);
      bindRows($("#vm-table"), rows, (r) => safe(async () => {
        const d = await api("GET", `/api/vm?${new URLSearchParams({ integration: r.integration, vm: r.external_id })}`);
        $("#vm-detail").innerHTML = `<div class="grid two mt"><div class="card"><h3>${esc(r.name)} — snapshots</h3>${table([{ label: "Name", key: "name" }, { label: "Created", render: (s) => fmtTime(s.created) }, { label: "Parent", key: "parent" }, { label: "Description", key: "description", wrap: true }], d.snapshots || [])}${d.snapshots_error ? `<p class="error">${esc(d.snapshots_error)}</p>` : ""}</div>
          <div class="card"><h3>Virtual disks</h3>${table([{ label: "Disk", key: "name" }, { label: "Storage", key: "storage" }, { label: "Size", render: (x) => fmtBytes(x.size) }], d.disks || (r.extra || {}).disks || [])}</div>
          <div class="card"><h3>Configuration</h3><pre>${esc(JSON.stringify(d.config || {}, null, 2))}</pre></div></div>`;
      }));
      $("#vm-table").querySelectorAll("button[data-act]").forEach((b) => { b.onclick = () => safe(async () => {
        const v = vms.find((x) => x.id === b.dataset.id);
        const r = await api("POST", "/api/vm/power", { integration: v.integration, vm: v.external_id, action: b.dataset.act });
        toast(`${b.dataset.act} requested: ${r.result}`);
      }); });
    };
    $("#vm-q").oninput = draw; draw();
  };

  VIEWS.containers = async (view) => {
    const ints = (await api("GET", "/api/integrations")).filter((i) => i.category === "docker");
    if (!ints.length) { view.innerHTML = '<div class="card">No Docker hosts yet. Add one under <a href="#integrations">Integrations</a>.</div>'; return; }
    view.innerHTML = `<div class="toolbar"><label class="m0">Docker host <select id="dk-host">${ints.map((i) => `<option value="${esc(i.id)}">${esc(i.name)}</option>`).join("")}</select></label><button id="dk-refresh">Refresh</button></div><div id="dk"></div>`;
    const load = async () => {
      const iid = $("#dk-host").value; const d = await api("GET", `/api/docker/${encodeURIComponent(iid)}`);
      const tab = (name, html) => `<div class="card mt"><h3>${name}</h3>${html}</div>`;
      $("#dk").innerHTML = `<div class="grid cards"><div class="card"><h3>Engine</h3><div class="stat">${esc(d.info.version)}</div><div class="small">${esc(d.info.os)}</div></div><div class="card"><h3>Containers</h3><div class="stat">${d.info.running}<small> / ${d.info.containers} running</small></div></div><div class="card"><h3>Images</h3><div class="stat">${d.info.images}</div></div><div class="card"><h3>Compose projects</h3><div class="stat">${d.projects.length}</div></div></div>
        ${tab("Containers", table([{ label: "Name", render: (c) => `<b>${esc(c.name)}</b>` }, { label: "State", render: (c) => pill(c.state) }, { label: "Health", render: (c) => pill(c.health) }, { label: "Image", key: "image" }, { label: "Status", key: "status" }, { label: "Ports", render: (c) => esc(c.ports.join(", ")), wrap: true }, { label: "Project", key: "compose_project" },
          { label: "", render: (c) => `<button class="small" data-logs="${esc(c.id)}" ${can("run_show") ? "" : "disabled"}>Logs</button> <button class="small" data-inspect="${esc(c.id)}">Inspect</button>${can("control_workloads") ? ` <button class="small" data-act="start" data-c="${esc(c.id)}">Start</button> <button class="small" data-act="restart" data-c="${esc(c.id)}">Restart</button> <button class="small danger" data-act="stop" data-c="${esc(c.id)}">Stop</button>` : ""}` }], d.containers))}
        <div id="dk-out"></div>
        ${tab("Compose projects", table([{ label: "Project", key: "project" }, { label: "Status", render: (p) => pill(p.status) }, { label: "Running", render: (p) => `${p.running}/${p.containers}` }, { label: "Unhealthy", key: "unhealthy" }, { label: "Services", render: (p) => esc(p.services.join(", ")), wrap: true }], d.projects))}
        <div class="grid two">${tab("Images", table([{ label: "Tags", render: (i) => esc(i.tags.join(", ") || "<none>"), wrap: true }, { label: "ID", render: (i) => `<span class="mono">${esc(i.id)}</span>` }, { label: "Size", render: (i) => fmtBytes(i.size) }], d.images))}
        ${tab("Networks", table([{ label: "Name", key: "name" }, { label: "Driver", key: "driver" }, { label: "Subnets", render: (n) => esc(n.subnets.join(", ")) }], d.networks))}
        ${tab("Volumes", table([{ label: "Name", key: "name" }, { label: "Driver", key: "driver" }, { label: "Mountpoint", key: "mountpoint", wrap: true }], d.volumes))}</div>`;
      $("#dk").querySelectorAll("button[data-logs]").forEach((b) => { b.onclick = () => safe(async () => { const lines = await api("GET", `/api/docker/${encodeURIComponent(iid)}/logs?${new URLSearchParams({ container: b.dataset.logs, tail: 300 })}`); $("#dk-out").innerHTML = `<div class="card mt"><h3>Logs (last 300 lines, secrets redacted)</h3><pre>${esc(lines.map((l) => (l.stream === "stderr" ? "! " : "  ") + l.line).join("\n"))}</pre></div>`; }); });
      $("#dk").querySelectorAll("button[data-inspect]").forEach((b) => { b.onclick = () => safe(async () => { const r = await api("GET", `/api/docker/${encodeURIComponent(iid)}/inspect?${new URLSearchParams({ container: b.dataset.inspect })}`); $("#dk-out").innerHTML = `<div class="card mt"><h3>Inspect</h3><p>CPU ${fmtPct(r.stats.cpu_pct)} · memory ${fmtBytes(r.stats.mem_used)} / ${fmtBytes(r.stats.mem_limit)} · net ↓${fmtBytes(r.stats.net_rx)} ↑${fmtBytes(r.stats.net_tx)}</p><pre>${esc(JSON.stringify(r.inspect, null, 2))}</pre></div>`; }); });
      $("#dk").querySelectorAll("button[data-act]").forEach((b) => { b.onclick = () => safe(async () => { const r = await api("POST", `/api/docker/${encodeURIComponent(iid)}/action`, { container: b.dataset.c, action: b.dataset.act }); toast(`${b.dataset.act}: ${r.result}`); await load(); }); });
    };
    $("#dk-host").onchange = $("#dk-refresh").onclick = () => safe(load);
    await load();
  };

  VIEWS.storage = async (view) => {
    const systems = await api("GET", "/api/storage");
    if (!systems.length) { view.innerHTML = '<div class="card">No storage systems yet. Add TrueNAS, Synology, QNAP, UGREEN or a Linux storage server under <a href="#integrations">Integrations</a>.</div>'; return; }
    view.innerHTML = systems.map((s, idx) => `<div class="card mb"><div class="row"><h3 class="m0">${esc(s.name)}</h3> ${pill(s.health)} <span class="muted small">${esc(s.system.model || "")} ${esc(s.system.version || "")}</span><span class="spacer"></span>${can("discover") ? `<button class="small" data-check="${esc(s.asset)}">Test SMB/NFS/iSCSI</button>` : ""}</div>
      <div id="sc-${idx}"></div>
      <h4 class="mt">Pools</h4>${table([{ label: "Pool", key: "name" }, { label: "State", render: (p) => pill(p.healthy === false ? "critical" : p.healthy ? "ok" : "unknown") + ` <span class="small">${esc(p.status)}</span>` }, { label: "Layout", key: "layout" }, { label: "Used", render: (p) => bar(p.pct) }, { label: "Capacity", render: (p) => `${fmtBytes(p.used)} / ${fmtBytes(p.total)}` },
        { label: "Growth / day", render: (p) => p.forecast.growth_per_day === null ? "–" : fmtBytes(p.forecast.growth_per_day) }, { label: "Full in", render: (p) => { const d = p.forecast.days_until || {}; return d["100%"] === undefined ? "–" : d["100%"] === null ? "not growing" : `${d["100%"]} days (90% in ${d["90%"]})`; } }], s.pools)}
      <h4 class="mt">Disks</h4>${table([{ label: "Disk", key: "name" }, { label: "Model", key: "model" }, { label: "Serial", render: (d) => `<span class="mono">${esc(d.serial)}</span>` }, { label: "Size", render: (d) => fmtBytes(d.size) }, { label: "Pool", key: "pool" }, { label: "Temp", render: (d) => (d.temperature_c === null ? "–" : `${d.temperature_c} °C`) }, { label: "SMART", render: (d) => pill(d.health) }, { label: "Power-on", render: (d) => (d.power_on_hours ? `${d.power_on_hours} h` : "–") }, { label: "Realloc / pending", render: (d) => `${d.reallocated ?? "–"} / ${d.pending ?? "–"}` }], s.disks)}
      <h4 class="mt">Shares</h4>${table([{ label: "Name", key: "name", wrap: true }, { label: "Protocol", key: "protocol" }, { label: "Path", key: "path", wrap: true }, { label: "Enabled", render: (x) => pill(x.enabled ? "ok" : "stopped") }], s.shares)}
      ${s.errors.length ? `<p class="small warnbox">${esc(s.errors.join(" · "))}</p>` : ""}</div>`).join("");
    view.querySelectorAll("button[data-check]").forEach((b, idx) => { b.onclick = () => safe(async () => { const r = await api("POST", `/api/assets/${encodeURIComponent(b.dataset.check)}/storage-check`, { protocols: ["smb", "nfs", "iscsi"] }); $(`#sc-${idx}`).innerHTML = `<p>${r.map((c) => `${pill(c.ok ? "ok" : "failed")} ${esc(c.protocol.toUpperCase())}: ${esc(c.detail)}`).join(" &nbsp; ")}</p>`; }); });
  };

  VIEWS.network = async (view) => {
    view.innerHTML = `<div class="tabs"><button data-t="topo" class="active">Topology</button><button data-t="ipam">IP addresses</button><button data-t="vlans">VLANs</button><button data-t="diag">Diagnostics</button></div><div id="net-body"></div>`;
    const tabs = {
      topo: async (el) => {
        const t = await api("GET", "/api/network/topology");
        if (!t.nodes.length) { el.innerHTML = '<div class="empty">No assets yet.</div>'; return; }
        const tiers = {}; t.nodes.forEach((n) => { (tiers[n.tier] = tiers[n.tier] || []).push(n); });
        const levels = Object.keys(tiers).map(Number).sort((a, b) => a - b); const W = Math.max(900, Math.max(...levels.map((l) => tiers[l].length)) * 110), H = levels.length * 110 + 40; const pos = {};
        levels.forEach((l, li) => tiers[l].forEach((n, i) => { pos[n.id] = [((i + 1) * W) / (tiers[l].length + 1), 50 + li * 110]; }));
        const color = (s) => ({ online: "var(--ok)", offline: "var(--crit)", degraded: "var(--warn)" }[s] || "var(--muted)");
        el.innerHTML = `<p class="small muted">Network devices (from Network Commander, LLDP/CDP) and homelab assets in one map. Dashed lines: VM/container runs on host. Click a node for details.</p><div class="scroll-x"><svg class="topo" viewBox="0 0 ${W} ${H}" data-minw="${Math.min(W, 1400)}">${t.edges.map((e) => pos[e.from] && pos[e.to] ? `<line class="${esc(e.type)}" x1="${pos[e.from][0]}" y1="${pos[e.from][1]}" x2="${pos[e.to][0]}" y2="${pos[e.to][1]}"><title>${esc(e.type)} ${esc(e.label)}</title></line>` : "").join("")}
          ${t.nodes.map((n) => `<g data-id="${esc(n.id)}"><circle cx="${pos[n.id][0]}" cy="${pos[n.id][1]}" r="11" fill="${color(n.status)}"><title>${esc(n.name)} (${esc(n.kind)}) ${esc(n.ip)}</title></circle><text x="${pos[n.id][0]}" y="${pos[n.id][1] + 26}" text-anchor="middle">${esc(n.name.length > 16 ? n.name.slice(0, 15) + "…" : n.name)}</text></g>`).join("")}</svg></div>`;
        el.querySelectorAll("g[data-id]").forEach((g) => { g.onclick = () => { location.hash = `asset/${encodeURIComponent(g.dataset.id)}`; }; });
      },
      ipam: async (el) => {
        const d = await api("GET", "/api/network/ipam");
        el.innerHTML = `<div class="toolbar">${can("edit_inventory") ? '<button id="add-subnet" class="primary">Add subnet</button><button id="add-res">Reserve address</button>' : ""}</div>
          ${table([{ label: "Subnet", render: (s) => `<span class="mono">${esc(s.cidr)}</span>` }, { label: "Name", key: "name" }, { label: "VLAN", render: (s) => esc(s.vlan ?? "") }, { label: "Gateway", key: "gateway" }, { label: "Used", render: (s) => `${bar(s.pct)} <span class="small">${s.used}/${s.size}</span>` }, { label: "Conflicts", render: (s) => s.conflicts.length ? `<span class="s-critical">${s.conflicts.map((c) => esc(`${c.ip}: ${c.assets.join(", ")}`)).join("; ")}</span>` : "none", wrap: true }, { label: "Next free", render: (s) => `<span class="mono small">${esc(s.next_free.join(", "))}</span>`, wrap: true }, { label: "", render: (s) => can("edit_inventory") ? `<button class="small danger" data-del="${esc(s.id)}">Delete</button>` : "" }], d.subnets, true)}<div id="ipam-detail"></div>`;
        bindRows(el, d.subnets, (s) => { $("#ipam-detail").innerHTML = `<div class="card mt"><h3>${esc(s.cidr)} addresses</h3>${table([{ label: "IP", render: (x) => `<span class="mono">${esc(x.ip)}</span>` }, { label: "Assets", render: (x) => x.assets.map((a) => `<a href="#asset/${encodeURIComponent(a.id)}">${esc(a.name)}</a>`).join(", ") }], s.addresses)}<h4 class="mt-s">Reservations</h4>${table([{ label: "IP", key: "ip" }, { label: "Name", key: "name" }, { label: "Note", key: "note" }], s.reservations)}</div>`; });
        el.querySelectorAll("button[data-del]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/network/subnets/${b.dataset.del}`, {}); tabs.ipam(el); }); });
        if ($("#add-subnet")) $("#add-subnet").onclick = () => safe(async () => { const f = await modal("Add subnet", `<label>CIDR<input name="cidr" required placeholder="192.168.10.0/24"></label><label>Name<input name="name"></label><div class="grid two"><label>VLAN id<input name="vlan" inputmode="numeric"></label><label>Gateway<input name="gateway"></label></div><label>DNS servers<input name="dns"></label><label>Description<input name="description"></label>`, "Add"); if (!f) return; if (f.vlan) f.vlan = Number(f.vlan); else delete f.vlan; await api("POST", "/api/network/subnets", f); tabs.ipam(el); });
        if ($("#add-res")) $("#add-res").onclick = () => safe(async () => { const f = await modal("Reserve address", `<label>IP address<input name="ip" required></label><label>For<input name="name" required></label><label>Note<input name="note"></label>`, "Reserve"); if (!f) return; await api("POST", "/api/network/reservations", f); tabs.ipam(el); });
      },
      vlans: async (el) => {
        const d = await api("GET", "/api/network/ipam");
        el.innerHTML = `<div class="toolbar">${can("edit_inventory") ? '<button id="add-vlan" class="primary">Add / edit VLAN</button>' : ""}</div>${table([{ label: "VLAN", key: "vid" }, { label: "Name", key: "name" }, { label: "Description", key: "description", wrap: true }, { label: "Subnets", render: (v) => esc(v.subnets.join(", ")) }, { label: "", render: (v) => can("edit_inventory") ? `<button class="small danger" data-vid="${v.vid}">Delete</button>` : "" }], d.vlans)}`;
        el.querySelectorAll("button[data-vid]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/network/vlans/${b.dataset.vid}`, {}); tabs.vlans(el); }); });
        if ($("#add-vlan")) $("#add-vlan").onclick = () => safe(async () => { const f = await modal("VLAN", `<label>VLAN id (1-4094)<input name="vid" required inputmode="numeric"></label><label>Name<input name="name" required></label><label>Description<input name="description"></label>`, "Save"); if (!f) return; f.vid = Number(f.vid); await api("POST", "/api/network/vlans", f); tabs.vlans(el); });
      },
      diag: async (el) => {
        el.innerHTML = `<div class="card"><form id="diag-form" class="row"><select name="tool" class="w-auto"><option>ping</option><option>traceroute</option><option>dns</option><option>tcp</option></select><input name="host" placeholder="host or IP" required class="w-220"><input name="port" placeholder="port (tcp)" class="w-110"><button class="primary" ${can("discover") ? "" : "disabled"}>Run</button></form><div id="diag-out" class="mt"></div></div>`;
        $("#diag-form").onsubmit = (ev) => { ev.preventDefault(); safe(async () => { const f = Object.fromEntries(new FormData(ev.target)); if (f.port) f.port = Number(f.port); else delete f.port; $("#diag-out").innerHTML = '<div class="muted">Running…</div>'; const r = await api("POST", "/api/network/diag", f); $("#diag-out").innerHTML = `<p>${pill(r.ok ? "ok" : "failed")} ${r.avg_ms !== undefined ? `avg ${r.avg_ms} ms · loss ${r.loss_pct}%` : r.ms !== undefined ? `${r.ms} ms` : ""} ${r.addresses ? esc(r.addresses.join(", ")) : ""} ${r.state ? esc(r.state) : ""}</p>${r.output ? `<pre>${esc(r.output)}</pre>` : ""}`; }); };
      },
    };
    const show = (name) => { view.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.t === name)); safe(() => tabs[name]($("#net-body"))); };
    view.querySelectorAll(".tabs button").forEach((b) => { b.onclick = () => show(b.dataset.t); });
    show("topo");
  };

  VIEWS.monitoring = async (view) => {
    view.innerHTML = `<div class="tabs"><button data-t="alerts" class="active">Alerts</button><button data-t="events">Event timeline</button><button data-t="rules">Thresholds</button><button data-t="checks">Checks</button><button data-t="report">Utilization report</button></div><div id="mon-body"></div>`;
    const tabs = {
      alerts: async (el) => {
        const rows = await api("GET", "/api/monitoring/alerts?all=1");
        el.innerHTML = table([{ label: "Severity", render: (a) => pill(a.state === "resolved" ? "ok" : a.severity) }, { label: "Alert", key: "rule_name" }, { label: "Target", render: (a) => `<a href="#asset/${encodeURIComponent(a.target)}">${esc(a.target_name)}</a>` }, { label: "Value", render: (a) => esc(`${Math.round(a.value * 100) / 100} (threshold ${a.threshold})`) }, { label: "Since", render: (a) => ago(a.since) }, { label: "State", render: (a) => esc(a.state) + (a.acked_by ? ` · acked by ${esc(a.acked_by)}` : "") }, { label: "", render: (a) => a.state !== "resolved" && !a.acked_by && can("run_show") ? `<button class="small" data-ack="${esc(a.id)}">Acknowledge</button>` : "" }], rows);
        el.querySelectorAll("button[data-ack]").forEach((b) => { b.onclick = () => safe(async () => { await api("POST", `/api/monitoring/alerts/${encodeURIComponent(b.dataset.ack)}/ack`, {}); tabs.alerts(el); }); });
      },
      events: async (el) => { const ev = await api("GET", "/api/events?limit=300"); el.innerHTML = `<div class="card"><ul class="events nolimit">${ev.map((e) => `<li>${pill(e.severity)} <span class="muted small">${fmtTime(e.ts)}</span> <b>${esc(e.kind)}</b> ${esc(e.message)}</li>`).join("") || '<li class="muted">No events</li>'}</ul></div>`; },
      rules: async (el) => {
        const rows = await api("GET", "/api/monitoring/rules");
        el.innerHTML = `<div class="toolbar">${can("change_settings") ? '<button id="add-rule" class="primary">Add / edit threshold</button>' : ""}</div>${table([{ label: "Name", key: "name" }, { label: "Metric", render: (r) => `<span class="mono">${esc(r.metric)}</span>` }, { label: "Direction", key: "direction" }, { label: "Warning", render: (r) => esc(r.warning ?? "–") }, { label: "Critical", render: (r) => esc(r.critical ?? "–") }, { label: "For N samples", key: "for_count" }, { label: "Scope", render: (r) => esc(r.scope_asset || r.scope_kind || r.scope_tag || "all") }, { label: "Enabled", render: (r) => pill(r.enabled ? "ok" : "stopped") }], rows, true)}`;
        const edit = (r = {}) => safe(async () => { const f = await modal("Threshold", `<input type="hidden" name="id" value="${esc(r.id || "")}"><label>Name<input name="name" value="${esc(r.name || "")}"></label><label>Metric<input name="metric" required value="${esc(r.metric || "")}" placeholder="cpu_pct, mem_pct, disk_pct, latency_ms…"></label><label>Direction<select name="direction"><option ${r.direction === "below" ? "" : "selected"}>above</option><option ${r.direction === "below" ? "selected" : ""}>below</option></select></label><div class="grid two"><label>Warning<input name="warning" value="${esc(r.warning ?? "")}"></label><label>Critical<input name="critical" value="${esc(r.critical ?? "")}"></label></div><div class="grid two"><label>Consecutive samples<input name="for_count" value="${esc(r.for_count || 1)}"></label><label>Only asset type (optional)<input name="scope_kind" value="${esc(r.scope_kind || "")}"></label></div>`, "Save"); if (!f) return; const body = { ...f, warning: f.warning === "" ? null : Number(f.warning), critical: f.critical === "" ? null : Number(f.critical), for_count: Number(f.for_count || 1) }; if (!body.id) delete body.id; await api("POST", "/api/monitoring/rules", body); tabs.rules(el); });
        if ($("#add-rule")) $("#add-rule").onclick = () => edit();
        if (can("change_settings")) bindRows(el, rows, edit);
      },
      checks: async (el) => {
        const [rows, assets] = await Promise.all([api("GET", "/api/monitoring/checks"), api("GET", "/api/assets")]);
        const names = Object.fromEntries(assets.map((a) => [a.id, a.name]));
        el.innerHTML = `<div class="toolbar">${can("edit_inventory") ? '<button id="add-check" class="primary">Add check</button>' : ""}<span class="muted small">Reachability checks are added automatically for assets with an IP address.</span></div>${table([{ label: "Target", render: (c) => esc(names[c.target] || c.target) }, { label: "Type", key: "type" }, { label: "Endpoint", render: (c) => `<span class="mono">${esc(c.url || `${c.host}${c.port ? ":" + c.port : ""}`)}</span>` }, { label: "Name", key: "name" }, { label: "", render: (c) => can("edit_inventory") ? `<button class="small danger" data-del="${esc(c.id)}">Remove</button>` : "" }], rows)}`;
        el.querySelectorAll("button[data-del]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/monitoring/checks/${encodeURIComponent(b.dataset.del)}`, {}); tabs.checks(el); }); });
        if ($("#add-check")) $("#add-check").onclick = () => safe(async () => { const f = await modal("Add check", `<label>Asset<select name="target">${assets.map((a) => `<option value="${esc(a.id)}">${esc(a.name)}</option>`).join("")}</select></label><label>Type<select name="type"><option>tcp</option><option>http</option><option>reachability</option></select></label><div class="grid two"><label>Host<input name="host"></label><label>Port<input name="port"></label></div><label>URL (http checks)<input name="url" placeholder="https://service.lan/health"></label><label>Expect keyword (optional)<input name="keyword"></label><label>Name<input name="name"></label>`, "Add"); if (!f) return; const body = { ...f }; if (body.port) body.port = Number(body.port); else delete body.port; for (const k of ["host", "url", "keyword"]) if (!body[k]) delete body[k]; await api("POST", "/api/monitoring/checks", body); tabs.checks(el); });
      },
      report: async (el) => {
        const r = await api("GET", "/api/report?hours=24");
        const cell = (x) => (x ? `${x.avg} avg / ${x.max} max` : "–");
        el.innerHTML = `<p>Infrastructure health: <b class="s-${scoreCls(r.health)}">${r.health ?? "–"}</b> · last ${r.hours} hours · generated ${fmtTime(r.generated)}</p>${table([{ label: "Asset", render: (x) => `<a href="#asset/${encodeURIComponent(x.id)}">${esc(x.name)}</a>` }, { label: "Type", key: "kind" }, { label: "CPU %", render: (x) => cell(x.cpu_pct) }, { label: "Memory %", render: (x) => cell(x.mem_pct) }, { label: "Disk %", render: (x) => cell(x.disk_pct) }, { label: "Latency ms", render: (x) => cell(x.latency_ms) }, { label: "Loss %", render: (x) => cell(x.loss_pct) }], r.rows)}`;
      },
    };
    const show = (name) => { view.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.t === name)); safe(() => tabs[name]($("#mon-body"))); };
    view.querySelectorAll(".tabs button").forEach((b) => { b.onclick = () => show(b.dataset.t); });
    show("alerts");
  };

  VIEWS.automation = async (view) => {
    view.innerHTML = `<div class="tabs"><button data-t="scripts" class="active">Scripts</button><button data-t="runs">Runs &amp; approvals</button><button data-t="workflows">Workflows</button><button data-t="policies">Remediation policies</button></div><div id="auto-body"></div>`;
    const tabs = {
      scripts: async (el) => {
        const rows = await api("GET", "/api/automation/scripts");
        el.innerHTML = `<div class="toolbar">${can("manage_automation") ? '<button id="new-script" class="primary">New script</button>' : ""}<span class="muted small">Change and destructive scripts need approval by a second person. Approval is bound to the script's exact content.</span></div>${table([{ label: "Name", render: (s) => `<b>${esc(s.name)}</b>${s.builtin ? ' <span class="muted small">built-in</span>' : ""}` }, { label: "Kind", key: "kind" }, { label: "Risk", render: (s) => pill(s.risk === "read_only" ? "ok" : s.risk === "change" ? "warning" : "critical") + ` <span class="small">${esc(s.risk)}</span>` }, { label: "Approval", render: (s) => (s.needs_approval ? "required" : "–") }, { label: "Description", key: "description", wrap: true }, { label: "", render: (s) => `${can("run_automation") ? `<button class="small primary" data-run="${esc(s.id)}">Run…</button>` : ""} <button class="small" data-view="${esc(s.id)}">View</button>${can("manage_automation") && !s.builtin ? ` <button class="small danger" data-del="${esc(s.id)}">Delete</button>` : ""}` }], rows)}<div id="script-out"></div>`;
        el.querySelectorAll("button[data-view]").forEach((b) => { b.onclick = () => { const s = rows.find((x) => x.id === b.dataset.view); $("#script-out").innerHTML = `<div class="card mt"><h3>${esc(s.name)} <span class="muted small mono">sha256 ${esc(s.sha256.slice(0, 16))}…</span></h3><pre>${esc(s.body)}</pre></div>`; }; });
        el.querySelectorAll("button[data-del]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/automation/scripts/${encodeURIComponent(b.dataset.del)}`, {}); tabs.scripts(el); }); });
        el.querySelectorAll("button[data-run]").forEach((b) => { b.onclick = () => safe(async () => {
          const s = rows.find((x) => x.id === b.dataset.run); const assets = s.kind === "python" ? [] : (await api("GET", "/api/assets")).filter((a) => (a.management || {})[s.kind === "ssh" ? "ssh" : "winrm"]);
          const f = await modal(`Run “${s.name}”`, `${s.needs_approval ? '<p class="warnbox">This script needs approval by another administrator before it runs.</p>' : ""}${s.kind !== "python" ? `<label>Targets (hold Ctrl/Cmd for several)<select name="targets" multiple size="6">${assets.map((a) => `<option value="${esc(a.id)}">${esc(a.name)}</option>`).join("")}</select></label>${assets.length ? "" : '<p class="small muted">No assets have management access configured for this script type.</p>'}` : '<p class="small muted">Runs on the NetCommander host.</p>'}${(s.params || []).map((p) => `<label>${esc(p.name)}<input name="p_${esc(p.name)}" value="${esc(p.default || "")}" required></label>`).join("")}<label>Note for the approver<input name="note"></label>`, "Request run");
          if (!f) return; const sel = $("#modal-body select[name=targets]"); const targets = sel ? Array.from(sel.selectedOptions).map((o) => o.value) : [];
          const params = {}; for (const [k, v] of Object.entries(f)) if (k.startsWith("p_")) params[k.slice(2)] = v;
          const run = await api("POST", "/api/automation/runs", { script_id: s.id, targets, params, note: f.note }); toast(run.status === "pending_approval" ? "Waiting for approval" : "Running…"); show("runs");
        }); });
        if ($("#new-script")) $("#new-script").onclick = () => safe(async () => {
          const f = await modal("New script", `<label>Name<input name="name" required></label><div class="grid two"><label>Kind<select name="kind"><option value="ssh">SSH command (Linux)</option><option value="powershell">PowerShell (Windows)</option><option value="python">Python (NetCommander host)</option></select></label><label>Risk<select name="risk"><option value="read_only">read only</option><option value="change">change</option><option value="destructive">destructive</option></select></label></div><label>Body — parameters as {{name}}<textarea name="body" required></textarea></label><label>Parameters (comma separated names; values must match [A-Za-z0-9_.@:-])<input name="params"></label><label>Description<input name="description"></label>`, "Save");
          if (!f) return; const params = f.params.split(",").map((s) => s.trim()).filter(Boolean).map((name) => ({ name }));
          await api("POST", "/api/automation/scripts", { name: f.name, kind: f.kind, risk: f.risk, body: f.body, description: f.description, params }); tabs.scripts(el);
        });
      },
      runs: async (el) => {
        const rows = await api("GET", "/api/automation/runs");
        el.innerHTML = table([{ label: "Created", render: (r) => fmtTime(r.created) }, { label: "Script", key: "script_name" }, { label: "Risk", key: "risk" }, { label: "Requested by", key: "requested_by" }, { label: "Targets", render: (r) => esc(r.targets.join(", ")), wrap: true }, { label: "Status", render: (r) => pill(r.status) }, { label: "Approved by", key: "approved_by" },
          { label: "", render: (r) => r.status === "pending_approval" && can("approve_automation") && r.requested_by !== state.session.user ? `<button class="small primary" data-ap="${esc(r.id)}">Approve</button> <button class="small danger" data-rj="${esc(r.id)}">Reject</button>` : r.status === "pending_approval" && r.requested_by === state.session.user ? `<button class="small" data-cn="${esc(r.id)}">Cancel</button>` : "" }], rows, true) + '<div id="run-out"></div>';
        bindRows(el, rows, (r) => { $("#run-out").innerHTML = `<div class="card mt"><h3>${esc(r.script_name)} — ${esc(r.status)}</h3><p class="small muted">Preview of the command that ${r.status === "pending_approval" ? "will run" : "ran"} (secrets redacted):</p><pre>${esc(r.preview)}</pre>${Object.entries(r.results || {}).map(([t, v]) => `<h4>${esc(t)} ${pill(v.ok ? "ok" : "failed")} <span class="small muted">exit ${v.exit_code}</span></h4><pre>${esc(v.stdout)}${v.stderr ? "\n--- stderr ---\n" + esc(v.stderr) : ""}</pre>`).join("")}${r.error ? `<p class="error">${esc(r.error)}</p>` : ""}</div>`; });
        el.querySelectorAll("button[data-ap],button[data-rj]").forEach((b) => { b.onclick = () => safe(async () => { const approve = !!b.dataset.ap; const id = b.dataset.ap || b.dataset.rj; const r = rows.find((x) => x.id === id); const f = await modal(approve ? "Approve run" : "Reject run", `<p>${esc(r.requested_by)} wants to run <b>${esc(r.script_name)}</b> (${esc(r.risk)}) on ${esc(r.targets.join(", ") || "the NetCommander host")}.</p><pre>${esc(r.preview)}</pre><label>Comment<input name="comment"></label>`, approve ? "Approve and run" : "Reject", !approve); if (!f) return; await api("POST", `/api/automation/runs/${encodeURIComponent(id)}/decide`, { approve, comment: f.comment }); tabs.runs(el); }); });
        el.querySelectorAll("button[data-cn]").forEach((b) => { b.onclick = () => safe(async () => { await api("POST", `/api/automation/runs/${encodeURIComponent(b.dataset.cn)}/cancel`, {}); tabs.runs(el); }); });
      },
      workflows: async (el) => {
        const [rows, scripts] = await Promise.all([api("GET", "/api/automation/workflows"), api("GET", "/api/automation/scripts")]);
        const names = Object.fromEntries(scripts.map((s) => [s.id, s.name]));
        el.innerHTML = table([{ label: "Workflow", key: "name" }, { label: "Risk", key: "risk" }, { label: "Steps", render: (w) => esc(w.steps.map((s) => names[s.script_id] || s.script_id).join(" → ")), wrap: true }, { label: "", render: (w) => can("run_automation") ? `<button class="small primary" data-wf="${esc(w.id)}">Run</button>` : "" }], rows) + '<p class="small muted">Workflows are created through the API or CLI (POST /api/automation/workflows). Steps that need approval pause the workflow.</p>';
        el.querySelectorAll("button[data-wf]").forEach((b) => { b.onclick = () => safe(async () => { const t = await api("POST", `/api/automation/workflows/${encodeURIComponent(b.dataset.wf)}/run`, {}); await waitTask(t, "Workflow"); }); });
      },
      policies: async (el) => {
        const rows = await api("GET", "/api/automation/policies");
        el.innerHTML = `<p class="small muted">Automatic remediation only happens through these explicit, expiring policies created by an administrator. Each run is audited.</p>${table([{ label: "Alert metric", key: "alert_metric" }, { label: "Script", key: "script_id" }, { label: "Scope", render: (p) => esc(p.scope_asset || p.scope_kind || "all") }, { label: "Min severity", key: "min_severity" }, { label: "Expires", render: (p) => fmtTime(p.expires) }, { label: "Created by", key: "created_by" }, { label: "", render: (p) => can("manage_automation") ? `<button class="small danger" data-del="${esc(p.id)}">Remove</button>` : "" }], rows)}`;
        el.querySelectorAll("button[data-del]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/automation/policies/${encodeURIComponent(b.dataset.del)}`, {}); tabs.policies(el); }); });
      },
    };
    const show = (name) => { view.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.t === name)); safe(() => tabs[name]($("#auto-body"))); };
    view.querySelectorAll(".tabs button").forEach((b) => { b.onclick = () => show(b.dataset.t); });
    show("scripts");
  };

  VIEWS.backups = async (view) => {
    const rows = await api("GET", "/api/backups");
    view.innerHTML = `<div class="toolbar">${can("manage_schedules") ? '<button id="add-job" class="primary">Add backup job</button>' : ""}${can("backup") ? '<button id="check-now">Check now</button>' : ""}<span class="spacer"></span><a href="/api/recovery/runbook" download="recovery-runbook.md"><button type="button">Recovery runbook (Markdown)</button></a>${can("change_settings") ? '<a href="/api/config/export" download="netcommander-config.json"><button type="button">Export configuration</button></a>' : ""}</div>
      ${table([{ label: "Job", render: (j) => `<b>${esc(j.name)}</b>` }, { label: "Platform", key: "platform" }, { label: "State", render: (j) => pill(j.status.state) }, { label: "Last good", render: (j) => ago(j.status.last_success) }, { label: "Expected every", render: (j) => `${j.max_age_hours} h` }, { label: "Size", render: (j) => fmtBytes(j.status.last_size) }, { label: "Message", render: (j) => esc(j.status.message), wrap: true }, { label: "Destination", key: "destination", wrap: true }, { label: "", render: (j) => `${j.platform === "manual" && can("backup") ? `<button class="small" data-rec="${esc(j.id)}">Record run</button>` : ""}${can("manage_schedules") ? ` <button class="small danger" data-del="${esc(j.id)}">Delete</button>` : ""}` }], rows, true)}<div id="bk-detail"></div>`;
    bindRows(view, rows, (j) => { $("#bk-detail").innerHTML = `<div class="card mt"><h3>${esc(j.name)} — recovery points</h3>${table([{ label: "Time", render: (p) => fmtTime(p.ts) }, { label: "Size", render: (p) => fmtBytes(p.size) }, { label: "Detail", render: (p) => esc(p.name || p.node || p.device || "") }], j.status.recovery_points || [])}<p class="small">Verification: ${esc(JSON.stringify(j.status.verified || {}))}</p>${j.notes ? `<p><b>Restore procedure:</b> ${esc(j.notes)}</p>` : ""}</div>`; });
    view.querySelectorAll("button[data-del]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/backups/${encodeURIComponent(b.dataset.del)}`, {}); VIEWS.backups(view); }); });
    view.querySelectorAll("button[data-rec]").forEach((b) => { b.onclick = () => safe(async () => { const f = await modal("Record backup run", `<label>Result<select name="ok"><option value="1">Succeeded</option><option value="">Failed</option></select></label><label>Size in bytes (optional)<input name="size"></label><label>Message<input name="message"></label>`, "Record"); if (!f) return; await api("POST", `/api/backups/${encodeURIComponent(b.dataset.rec)}/record`, { ok: !!f.ok, size: f.size ? Number(f.size) : null, message: f.message }); toast("Recorded — status updates at the next check"); }); });
    if ($("#check-now")) $("#check-now").onclick = () => safe(async () => { const t = await api("POST", "/api/backups/check", {}); await waitTask(t, "Backup check"); VIEWS.backups(view); });
    if ($("#add-job")) $("#add-job").onclick = () => safe(async () => {
      const [ints, assets] = await Promise.all([api("GET", "/api/integrations"), api("GET", "/api/assets")]);
      const f = await modal("Add backup job", `<label>Name<input name="name" required></label><label>Platform<select name="platform"><option value="proxmox">Proxmox vzdump</option><option value="truenas">TrueNAS replication / cloud sync</option><option value="file">Files in a directory</option><option value="netcommander">NetCommander network config backups</option><option value="manual">Manual (record runs yourself)</option></select></label>
        <label>Integration (Proxmox / TrueNAS)<select name="integration"><option value="">–</option>${ints.map((i) => `<option value="${esc(i.id)}">${esc(i.name)} (${esc(i.kind)})</option>`).join("")}</select></label>
        <label>Match — VM id, task name, directory path or device name<input name="match"></label><div class="grid two"><label>Expected every (hours)<input name="max_age_hours" value="26"></label><label>Minimum size (bytes)<input name="min_size" value="0"></label></div>
        <label>Protects asset<select name="source_asset"><option value="">–</option>${assets.map((a) => `<option value="${esc(a.id)}">${esc(a.name)}</option>`).join("")}</select></label><label>Destination<input name="destination"></label><label>Restore procedure (for the runbook)<textarea name="notes" class="h-60"></textarea></label>`, "Add");
      if (!f) return; f.max_age_hours = Number(f.max_age_hours); f.min_size = Number(f.min_size || 0); await api("POST", "/api/backups", f); VIEWS.backups(view);
    });
  };

  VIEWS.integrations = async (view) => {
    const [rows, adapters] = await Promise.all([api("GET", "/api/integrations"), api("GET", "/api/adapters")]);
    view.innerHTML = `<div class="toolbar">${can("manage_integrations") ? '<button id="add-int" class="primary">Add integration</button>' : ""}<span class="muted small">Credentials are encrypted in your vault. Integrations are polled every few minutes.</span></div>
      ${table([{ label: "Name", render: (i) => `<b>${esc(i.name)}</b>` }, { label: "Type", render: (i) => `${esc(i.title)}${i.maturity !== "stable" ? ` <span class="muted small">${esc(i.maturity)}</span>` : ""}` }, { label: "Status", render: (i) => pill(i.ok === null ? "unknown" : i.ok ? "ok" : "failed") }, { label: "Last poll", render: (i) => ago(i.last_poll) }, { label: "Summary / error", render: (i) => esc(i.last_error || JSON.stringify(i.summary || {})), wrap: true }, { label: "TLS", render: (i) => (i.config.verify_tls === false && !i.config.pin_sha256 ? '<span class="s-warning">not verified</span>' : "verified") },
        { label: "", render: (i) => `${can("discover") ? `<button class="small" data-poll="${esc(i.id)}">Poll now</button>` : ""}${can("manage_integrations") ? ` <button class="small danger" data-del="${esc(i.id)}">Remove</button>` : ""}` }], rows)}
      <h3 class="mt">Available adapters</h3>${table([{ label: "Adapter", key: "title" }, { label: "Category", key: "category" }, { label: "Maturity", key: "maturity" }, { label: "Capabilities", render: (a) => esc(a.capabilities.join(", ")), wrap: true }, { label: "Notes", key: "notes", wrap: true }], adapters)}`;
    view.querySelectorAll("button[data-poll]").forEach((b) => { b.onclick = () => safe(async () => { const t = await api("POST", `/api/integrations/${encodeURIComponent(b.dataset.poll)}/poll`, {}); await waitTask(t, "Poll"); VIEWS.integrations(view); }); });
    view.querySelectorAll("button[data-del]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/integrations/${encodeURIComponent(b.dataset.del)}`, {}); VIEWS.integrations(view); }); });
    if ($("#add-int")) $("#add-int").onclick = () => safe(async () => {
      const pick = await modal("Add integration", `<label>Adapter<select name="key">${adapters.map((a) => `<option value="${esc(a.category)}/${esc(a.kind)}">${esc(a.title)} (${esc(a.category)})</option>`).join("")}</select></label>`, "Next");
      if (!pick) return; const [category, kind] = pick.key.split("/"); const spec = adapters.find((a) => a.category === category && a.kind === kind);
      const fields = spec.fields.map((fd) => fd.kind === "bool" ? `<label><input type="checkbox" name="${esc(fd.name)}" ${fd.default ? "checked" : ""} class="w-auto"> ${esc(fd.label)}</label>` : `<label>${esc(fd.label)}${fd.required ? " *" : ""}<input name="${esc(fd.name)}" ${fd.secret ? 'type="password" autocomplete="new-password"' : ""} value="${esc(fd.secret ? "" : fd.default ?? "")}" ${fd.required ? "required" : ""} placeholder="${esc(fd.help || "")}"></label>`).join("");
      const f = await modal(`Add ${spec.title}`, `${spec.notes ? `<p class="small muted">${esc(spec.notes)}</p>` : ""}<label>Name *<input name="__name" required value="${esc(spec.title)}"></label>${fields}`, "Save");
      if (!f) return; const config = {}, secrets = {};
      for (const fd of spec.fields) { if (fd.kind === "bool") config[fd.name] = !!f[fd.name]; else if (fd.secret) { if (f[fd.name]) secrets[fd.name] = f[fd.name]; } else if (f[fd.name] !== "") config[fd.name] = fd.kind === "int" ? Number(f[fd.name]) : f[fd.name]; }
      const rec = await api("POST", "/api/integrations", { category, kind, name: f.__name, config, secrets }); toast("Saved — testing connection…");
      const t = await api("POST", `/api/integrations/${encodeURIComponent(rec.id)}/poll`, {}); await waitTask(t, "First poll"); VIEWS.integrations(view);
    });
  };

  VIEWS.security = async (view) => {
    view.innerHTML = `<div class="tabs"><button data-t="audit" class="active">Audit log</button><button data-t="hostkeys">SSH host keys</button><button data-t="sessions">Sessions</button><button data-t="secrets">Secrets</button></div><div id="sec-body"></div>`;
    const tabs = {
      audit: async (el) => { if (!can("read_audit")) { el.innerHTML = '<div class="empty">Your role cannot read the audit log.</div>'; return; } const a = await api("GET", "/api/security/audit?limit=500"); el.innerHTML = `<p>${pill(a.verified ? "ok" : "critical")} Hash chain: ${esc(a.message)}</p>${table([{ label: "Time", render: (e) => fmtTime(e.ts) }, { label: "Actor", key: "actor" }, { label: "Action", render: (e) => `<span class="mono">${esc(e.action)}</span>` }, { label: "Target", key: "target", wrap: true }, { label: "Outcome", render: (e) => pill(e.outcome === "ok" ? "ok" : e.outcome === "denied" ? "warning" : "failed") }, { label: "Detail", key: "detail", wrap: true }], a.entries)}`; },
      hostkeys: async (el) => {
        el.innerHTML = `<div class="card"><p class="small muted">NetCommander only connects to SSH hosts whose key is in known_hosts. Fetch a host's key, compare the fingerprint with the one shown on the device's console, then trust it.</p><form id="hk-form" class="row"><input name="host" placeholder="host or IP" required class="w-220"><input name="port" value="22" class="w-90"><button>Fetch fingerprint</button></form><div id="hk-out" class="mt"></div></div>`;
        $("#hk-form").onsubmit = (ev) => { ev.preventDefault(); safe(async () => { const f = Object.fromEntries(new FormData(ev.target)); const k = await api("GET", `/api/security/hostkey?${new URLSearchParams(f)}`); $("#hk-out").innerHTML = `<p>${esc(k.type)} <span class="mono">${esc(k.fingerprint)}</span></p>${can("change_settings") ? '<button id="hk-trust" class="primary">I compared it — trust this key</button>' : ""}`; if ($("#hk-trust")) $("#hk-trust").onclick = () => safe(async () => { const r = await api("POST", "/api/security/trust", { host: f.host, port: Number(f.port), fingerprint: k.fingerprint }); toast(`Trusted ${r.host} (${r.fingerprint})`); }); }); };
      },
      sessions: async (el) => { if (!can("manage_users")) { el.innerHTML = '<div class="empty">Administrators can view and revoke sessions.</div>'; return; } const rows = await api("GET", "/api/security/sessions"); el.innerHTML = table([{ label: "User", key: "user" }, { label: "Role", key: "role" }, { label: "From", key: "remote" }, { label: "Signed in", render: (s) => fmtTime(s.created) }, { label: "Last activity", render: (s) => ago(s.last_seen) }, { label: "Browser", key: "user_agent", wrap: true }, { label: "", render: (s) => `<button class="small danger" data-rv="${esc(s.id)}">Revoke</button>` }], rows); el.querySelectorAll("button[data-rv]").forEach((b) => { b.onclick = () => safe(async () => { await api("DELETE", `/api/security/sessions/${encodeURIComponent(b.dataset.rv)}`, {}); tabs.sessions(el); }); }); },
      secrets: async (el) => { if (!can("manage_integrations")) { el.innerHTML = '<div class="empty">Administrators manage stored secrets.</div>'; return; } const refs = await api("GET", "/api/secrets"); el.innerHTML = `<p class="small muted">Only names are shown — secret values are never returned by the API. ${state.session.persistent_secrets ? "" : '<span class="s-warning">Guest session: secrets are kept in memory only.</span>'}</p>${table([{ label: "Reference", render: (r) => `<span class="mono">${esc(r.ref)}</span>` }], refs.map((r) => ({ ref: r })))}`; },
    };
    const show = (name) => { view.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.t === name)); safe(() => tabs[name]($("#sec-body"))); };
    view.querySelectorAll(".tabs button").forEach((b) => { b.onclick = () => show(b.dataset.t); });
    show("audit");
  };

  // ------------------------------------------------------------------ session
  function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); clearInterval(state.timer); }
  async function start() {
    try { state.session = await api("GET", "/api/session"); } catch (e) { showLogin(); return; }
    state.csrf = state.session.csrf;
    $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
    $("#who").textContent = `${state.session.user} · ${state.session.role} · v${state.session.version}`;
    if (state.session.must_change_password) { $("#view").innerHTML = '<div class="card warnbox">Your account still uses a temporary password. Change it in the NetCommander desktop app (Account &amp; Security) before using the web interface.</div>'; return; }
    await route();
  }
  $("#login-form").onsubmit = async (ev) => {
    ev.preventDefault(); $("#login-error").textContent = "";
    const f = Object.fromEntries(new FormData(ev.target));
    try { await api("POST", "/api/login", f); ev.target.reset(); await start(); } catch (e) { $("#login-error").textContent = e.message; }
  };
  $("#logout-btn").onclick = async () => { try { await api("POST", "/api/logout", {}); } catch (e) { /* ignore */ } showLogin(); };
  $("#theme-btn").onclick = toggleTheme;
  $("#menu-btn").onclick = () => $("#sidebar").classList.toggle("open");
  $("#global-search").onkeydown = (ev) => { if (ev.key === "Enter") location.hash = `inventory?q=${encodeURIComponent(ev.target.value)}`; };
  window.addEventListener("hashchange", () => { if (state.session) route(); });
  start();
})();
