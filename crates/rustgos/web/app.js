(() => {
  "use strict";

  const POLL_MILLIS = 2000;
  const MAX_BACKOFF_MILLIS = 30000;
  const HISTORY_REFRESH_MILLIS = 30000;
  const controllers = new Map();
  const state = {
    overview: null,
    detail: null,
    sessionData: null,
    clientSearch: "",
    clientSort: "online",
    clientDescending: true,
    failures: 0,
    timer: null,
    pollInFlight: false,
    pollQueued: false,
    pollGeneration: 0,
    serverHistory: { key: "", expiresAt: 0, retryAfter: 0, generation: 0 },
    clientHistory: { key: "", expiresAt: 0, retryAfter: 0, generation: 0 },
  };
  const $ = (id) => document.getElementById(id);
  const text = (id, value) => { const node = $(id); if (node) node.textContent = value; };

  function formatBytes(value) {
    if (!Number.isFinite(value) || value < 0) return "Unavailable";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let amount = value;
    let unit = 0;
    while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
    return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
  }

  function formatRate(value) {
    return value == null ? "Unavailable" : `${formatBytes(value)}/s`;
  }

  function formatPercent(basisPoints) {
    return basisPoints == null ? "Unavailable" : `${(basisPoints / 100).toFixed(1)}%`;
  }

  function formatTime(timestamp) {
    return Number.isFinite(timestamp) && timestamp > 0 ? new Date(timestamp).toLocaleString() : "Unavailable";
  }

  function formatAge(millis) {
    if (millis == null) return "unavailable";
    if (millis < 1000) return "just now";
    if (millis < 60000) return `${Math.floor(millis / 1000)}s ago`;
    if (millis < 3600000) return `${Math.floor(millis / 60000)}m ago`;
    return `${Math.floor(millis / 3600000)}h ago`;
  }

  function formatDuration(millis) {
    if (!Number.isFinite(millis)) return "Unavailable";
    const seconds = Math.floor(millis / 1000);
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  }

  function setStatus(message, kind) {
    const node = $("connection-status");
    if (!node) return;
    node.textContent = message;
    node.dataset.kind = kind;
  }

  async function requestJson(path, key) {
    controllers.get(key)?.abort();
    const controller = new AbortController();
    controllers.set(key, controller);
    try {
      const response = await fetch(path, { credentials: "same-origin", signal: controller.signal });
      if (response.status === 401) {
        window.location.assign("/login");
        throw new Error("authentication required");
      }
      if (!response.ok) throw new Error(`request failed (${response.status})`);
      return await response.json();
    } finally {
      if (controllers.get(key) === controller) controllers.delete(key);
    }
  }

  function activeRoute() {
    const raw = location.hash.replace(/^#/, "");
    if (raw === "sessions") return { view: "sessions" };
    if (raw.startsWith("client/")) {
      try { return { view: "client", name: decodeURIComponent(raw.slice("client/".length)) }; } catch (_) { return { view: "overview" }; }
    }
    return { view: "overview" };
  }

  function showRoute() {
    const route = activeRoute();
    for (const view of document.querySelectorAll("[data-view]")) view.hidden = view.dataset.view !== route.view;
    for (const link of document.querySelectorAll("[data-nav]")) {
      if (link.dataset.nav === route.view) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    return route;
  }

  function metricNote(metrics) {
    if (!metrics?.available) return "Metrics unavailable";
    if (metrics.clock_skew) return "Clock skew detected";
    return metrics.stale ? `Stale · ${formatAge(metrics.age_millis)}` : `Sampled ${formatAge(metrics.age_millis)}`;
  }

  function renderOverview(overview) {
    const server = overview.server;
    const metrics = server.metrics;
    text("snapshot-summary", `Snapshot ${formatTime(overview.generated_unix_millis)} · ${server.online_clients} online clients · ${server.active_sessions.active} active sessions`);
    text("server-cpu", formatPercent(metrics.cpu_basis_points));
    text("server-cpu-note", metricNote(metrics));
    text("server-memory", metrics.memory_used_bytes == null ? "Unavailable" : `${formatBytes(metrics.memory_used_bytes)} / ${formatBytes(metrics.memory_total_bytes)}`);
    text("server-memory-note", metricNote(metrics));
    text("server-storage", metrics.disk_used_bytes == null ? "Unavailable" : `${formatBytes(metrics.disk_used_bytes)} / ${formatBytes(metrics.disk_total_bytes)}`);
    text("server-storage-note", metricNote(metrics));
    text("server-upload", formatRate(metrics.network_sent_bytes_per_second));
    text("server-upload-note", `${formatBytes(server.traffic.sent_bytes)} logical sent`);
    text("server-download", formatRate(metrics.network_received_bytes_per_second));
    text("server-download-note", `${formatBytes(server.traffic.received_bytes)} logical received`);
    const healthy = !overview.snapshot_stale && overview.observability.dropped_events === 0;
    text("service-health", healthy ? "Healthy" : "Degraded");
    text("service-health-note", overview.history.available ? `${overview.observability.event_queue_depth} queued events` : "History unavailable");
    renderClientGrid(overview.clients);
  }

  function sortedClients(clients) {
    const folded = state.clientSearch.trim().toLocaleLowerCase();
    const entries = clients.items
      .map((client, index) => ({ client, index }))
      .filter(({ client }) => !folded || client.name.toLocaleLowerCase().includes(folded));
    const direction = state.clientDescending ? -1 : 1;
    const compare = (left, right) => {
      const a = left.client;
      const b = right.client;
      let result = 0;
      if (state.clientSort === "online") result = Number(a.online) - Number(b.online);
      else if (state.clientSort === "name") result = a.name.localeCompare(b.name);
      else if (state.clientSort === "traffic") {
        const aTraffic = BigInt(a.traffic_sort_bytes);
        const bTraffic = BigInt(b.traffic_sort_bytes);
        result = aTraffic === bTraffic ? 0 : (aTraffic > bTraffic ? 1 : -1);
      } else if (state.clientSort === "cpu") {
        const aCpu = a.telemetry.cpu_basis_points;
        const bCpu = b.telemetry.cpu_basis_points;
        if (aCpu == null && bCpu != null) return 1;
        if (aCpu != null && bCpu == null) return -1;
        result = aCpu == null ? 0 : aCpu - bCpu;
      }
      if (result === 0) {
        const byName = a.name.localeCompare(b.name);
        return byName || left.index - right.index;
      }
      return result * direction;
    };
    return entries.sort(compare).map(({ client }) => client);
  }

  function badge(label, className) {
    const node = document.createElement("span");
    node.className = `badge ${className}`;
    node.textContent = label;
    return node;
  }

  function appendDefinition(list, term, value) {
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    list.append(dt, dd);
  }

  function activePathLabel(path) {
    return ({ relay: "Relay", "p2p-direct": "Direct P2P", "p2p-fallback": "Fallback P2P", mixed: "Mixed active paths", none: "No active path" })[path] || "Unavailable";
  }

  function clientCard(client) {
    const article = document.createElement("article");
    article.className = "client-card";
    const top = document.createElement("div"); top.className = "card-top";
    const title = document.createElement("h3");
    const link = document.createElement("a");
    link.href = `#client/${encodeURIComponent(client.name)}`;
    link.textContent = client.name;
    title.append(link);
    top.append(title, badge(client.online ? "Online" : "Offline", client.online ? "badge-online" : "badge-offline"));
    const badges = document.createElement("div"); badges.className = "badges";
    if (client.telemetry.stale || client.heartbeat.stale) badges.append(badge("Stale", "badge-stale"));
    if (!client.telemetry.available) badges.append(badge("Metrics unavailable", "badge-warning"));
    if (client.reconnects > 0) badges.append(badge(`${client.reconnects} reconnects`, "badge-warning"));
    const details = document.createElement("dl");
    appendDefinition(details, "Version", client.version || "Unavailable");
    appendDefinition(details, "Heartbeat", formatAge(client.heartbeat.age_millis));
    appendDefinition(details, "CPU", formatPercent(client.telemetry.cpu_basis_points));
    appendDefinition(details, "Memory", client.telemetry.memory_used_bytes == null ? "Unavailable" : formatBytes(client.telemetry.memory_used_bytes));
    appendDefinition(details, "Storage", client.telemetry.disk_used_bytes == null ? "Unavailable" : formatBytes(client.telemetry.disk_used_bytes));
    appendDefinition(details, "Upload / download", `${formatRate(client.telemetry.network_sent_bytes_per_second)} / ${formatRate(client.telemetry.network_received_bytes_per_second)}`);
    appendDefinition(details, "Logical traffic", `${formatBytes(client.traffic.sent_bytes)} / ${formatBytes(client.traffic.received_bytes)}`);
    appendDefinition(details, "Exports / forwards", `${client.inventory.exports.total} / ${client.inventory.forwards.total}`);
    appendDefinition(details, "Sessions", `${client.sessions.active} active · ${client.sessions.total} total`);
    appendDefinition(details, "Active path", activePathLabel(client.active_path));
    article.append(top, badges, details);
    return article;
  }

  function renderClientGrid(clients) {
    const grid = $("client-grid");
    const empty = $("client-empty");
    if (!grid || !empty) return;
    const items = sortedClients(clients);
    grid.replaceChildren(...items.map(clientCard));
    empty.hidden = items.length !== 0;
    text("clients-summary", `${items.length} shown of ${clients.total} clients`);
  }

  function describeSeries(label, points, formatValue) {
    const values = points.map((point) => point.value).filter(Number.isFinite);
    if (!values.length) return `${label}: no data`;
    const first = values[0];
    const latest = values[values.length - 1];
    const trend = latest > first ? "rising" : latest < first ? "falling" : "steady";
    return `${label}: latest ${formatValue(latest)}, minimum ${formatValue(Math.min(...values))}, maximum ${formatValue(Math.max(...values))}, ${trend}`;
  }

  function chartNode(id, primary, secondary, options) {
    const container = $(id);
    if (!container) return;
    const { title, unit, range, primaryLabel, secondaryLabel = "", formatValue } = options;
    const summary = [
      `${title}. Range: ${range}. Units: ${unit}.`,
      describeSeries(primaryLabel, primary, formatValue),
      secondaryLabel ? describeSeries(secondaryLabel, secondary, formatValue) : "",
    ].filter(Boolean).join(" ");
    container.replaceChildren();
    container.setAttribute("aria-label", summary);
    const all = [...primary, ...secondary].filter((point) => Number.isFinite(point.value));
    if (!all.length) {
      const empty = document.createElement("p");
      empty.className = "chart-empty";
      empty.textContent = `${title}: no history is available for ${range} (${unit}).`;
      container.append(empty);
      return;
    }
    const width = 620; const height = 180; const padding = 16;
    const minX = Math.min(...all.map((point) => point.timestamp_unix_millis));
    const maxX = Math.max(...all.map((point) => point.timestamp_unix_millis));
    const minY = Math.min(...all.map((point) => point.value));
    const maxY = Math.max(...all.map((point) => point.value));
    const pointFor = (point) => {
      const x = padding + ((point.timestamp_unix_millis - minX) / Math.max(1, maxX - minX)) * (width - padding * 2);
      const y = height - padding - ((point.value - minY) / Math.max(1, maxY - minY)) * (height - padding * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    };
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    const svgTitle = document.createElementNS("http://www.w3.org/2000/svg", "title");
    svgTitle.textContent = title;
    const description = document.createElementNS("http://www.w3.org/2000/svg", "desc");
    description.textContent = summary;
    svg.append(svgTitle, description);
    const makeLine = (points, className) => {
      if (!points.length) return;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
      line.setAttribute("points", points.map(pointFor).join(" "));
      line.setAttribute("class", className);
      svg.append(line);
    };
    makeLine(primary, "primary");
    makeLine(secondary, "secondary");
    const caption = document.createElement("span");
    caption.className = "sr-only";
    caption.textContent = summary;
    container.append(svg, caption);
  }

  async function loadHistory(scope, client, metric, range, key) {
    const end = Date.now();
    const query = new URLSearchParams({ scope, metric, start_unix_millis: String(end - range), end_unix_millis: String(end), resolution: "auto", max_points: "400" });
    if (client) query.set("client", client);
    return requestJson(`/api/v1/history?${query}`, key);
  }

  function historyRangeLabel(range) {
    return range === 3600000 ? "1 hour" : range === 604800000 ? "7 days" : "24 hours";
  }

  function historyDue(cache, key) {
    const now = Date.now();
    return cache.key !== key || now >= cache.expiresAt && now >= cache.retryAfter;
  }

  function markHistorySuccess(cache, key) {
    cache.key = key;
    cache.expiresAt = Date.now() + HISTORY_REFRESH_MILLIS;
    cache.retryAfter = 0;
  }

  function markHistoryFailure(cache, key) {
    cache.key = key;
    cache.expiresAt = 0;
    cache.retryAfter = Date.now() + HISTORY_REFRESH_MILLIS;
  }

  async function refreshServerHistory() {
    if (!state.overview) return;
    const range = Number($("history-range")?.value || 86400000);
    const key = `${range}`;
    if (!historyDue(state.serverHistory, key)) return true;
    const generation = state.serverHistory.generation;
    try {
      const [cpu, memory, received, sent, trafficReceived, trafficSent] = await Promise.all([
        loadHistory("server", "", "cpu_basis_points", range, "history-server-cpu"),
        loadHistory("server", "", "memory_used_bytes", range, "history-server-memory"),
        loadHistory("server", "", "network_received_bytes_per_second", range, "history-server-rx"),
        loadHistory("server", "", "network_sent_bytes_per_second", range, "history-server-tx"),
        loadHistory("server", "", "traffic_received_bytes", range, "history-server-traffic-rx"),
        loadHistory("server", "", "traffic_sent_bytes", range, "history-server-traffic-tx"),
      ]);
      if (state.serverHistory.generation !== generation) return true;
      markHistorySuccess(state.serverHistory, key);
      const rangeLabel = historyRangeLabel(range);
      chartNode("chart-cpu", cpu.points, [], { title: "Server CPU history", unit: "percent", range: rangeLabel, primaryLabel: "CPU", formatValue: formatPercent });
      chartNode("chart-memory", memory.points, [], { title: "Server memory history", unit: "bytes", range: rangeLabel, primaryLabel: "Memory", formatValue: formatBytes });
      chartNode("chart-network", received.points, sent.points, { title: "Server network history", unit: "bytes per second", range: rangeLabel, primaryLabel: "Download", secondaryLabel: "Upload", formatValue: formatRate });
      chartNode("chart-traffic", trafficReceived.points, trafficSent.points, { title: "Server Rustgo traffic history", unit: "bytes", range: rangeLabel, primaryLabel: "Logical download", secondaryLabel: "Logical upload", formatValue: formatBytes });
      return true;
    } catch (error) {
      if (error.name === "AbortError") throw error;
      if (state.serverHistory.generation !== generation) return true;
      markHistoryFailure(state.serverHistory, key);
      const rangeLabel = historyRangeLabel(range);
      for (const id of ["chart-cpu", "chart-memory", "chart-network", "chart-traffic"]) chartNode(id, [], [], { title: "History unavailable", unit: "data", range: rangeLabel, primaryLabel: "History", formatValue: String });
      return false;
    }
  }

  function renderClientDetail(detail) {
    const client = detail.client;
    text("client-title", client.name);
    text("client-detail-summary", `${client.online ? "Online" : "Offline"} · heartbeat ${formatAge(client.heartbeat.age_millis)} · ${client.sessions.active} active sessions`);
    const metrics = $("client-detail-metrics");
    if (metrics) {
      metrics.replaceChildren();
      const values = [["CPU", formatPercent(client.telemetry.cpu_basis_points), metricNote(client.telemetry)], ["Memory", formatBytes(client.telemetry.memory_used_bytes), metricNote(client.telemetry)], ["Storage", formatBytes(client.telemetry.disk_used_bytes), metricNote(client.telemetry)], ["Upload", formatRate(client.telemetry.network_sent_bytes_per_second), `${formatBytes(client.traffic.sent_bytes)} logical sent`], ["Download", formatRate(client.telemetry.network_received_bytes_per_second), `${formatBytes(client.traffic.received_bytes)} logical received`], ["Path", activePathLabel(client.active_path), `${client.reconnects} reconnects`]];
      for (const [label, value, note] of values) {
        const card = document.createElement("article"); card.className = "metric-card";
        const heading = document.createElement("h2"); heading.textContent = label;
        const amount = document.createElement("p"); amount.className = "metric-value"; amount.textContent = value;
        const description = document.createElement("p"); description.className = "metric-note"; description.textContent = note;
        card.append(heading, amount, description); metrics.append(card);
      }
    }
    const inventory = $("client-inventory");
    if (inventory) { inventory.replaceChildren(); appendDefinition(inventory, "Exports", `${client.inventory.exports.total} (${client.inventory.exports.items.join(", ") || "none"})`); appendDefinition(inventory, "Forwards", `${client.inventory.forwards.total} (${client.inventory.forwards.items.join(", ") || "none"})`); appendDefinition(inventory, "Tunnels", `${client.inventory.tunnels.total} (${client.inventory.tunnels.items.join(", ") || "none"})`); }
    const paths = $("client-paths");
    if (paths) { paths.replaceChildren(); appendDefinition(paths, "Direct P2P", String(client.paths.p2p_direct)); appendDefinition(paths, "Fallback P2P", String(client.paths.p2p_fallback)); appendDefinition(paths, "Relay", String(client.paths.relay)); appendDefinition(paths, "TCP / UDP / P2P", `${client.sessions.tcp} / ${client.sessions.udp} / ${client.sessions.p2p}`); }
    const sessions = $("client-sessions");
    if (sessions) {
      const list = document.createElement("ol"); list.className = "session-list";
      for (const session of detail.sessions.items) { const item = document.createElement("li"); item.textContent = `${session.id} · ${session.kind} · ${session.path} · ${session.state} · ${formatBytes(session.traffic.sent_bytes + session.traffic.received_bytes)}`; list.append(item); }
      sessions.replaceChildren(list);
    }
  }

  async function refreshClientHistory(name) {
    const range = Number($("history-range")?.value || 86400000);
    const key = `${name}\u0000${range}`;
    if (!historyDue(state.clientHistory, key)) return true;
    const generation = state.clientHistory.generation;
    try {
      const [cpu, received, sent] = await Promise.all([
        loadHistory("client", name, "cpu_basis_points", range, "history-client-cpu"),
        loadHistory("client", name, "traffic_received_bytes", range, "history-client-rx"),
        loadHistory("client", name, "traffic_sent_bytes", range, "history-client-tx"),
      ]);
      if (state.clientHistory.generation !== generation) return true;
      markHistorySuccess(state.clientHistory, key);
      const rangeLabel = historyRangeLabel(range);
      chartNode("client-chart-cpu", cpu.points, [], { title: "Client CPU history", unit: "percent", range: rangeLabel, primaryLabel: "CPU", formatValue: formatPercent });
      chartNode("client-chart-traffic", received.points, sent.points, { title: "Client traffic history", unit: "bytes", range: rangeLabel, primaryLabel: "Logical download", secondaryLabel: "Logical upload", formatValue: formatBytes });
      return true;
    } catch (error) {
      if (error.name === "AbortError") throw error;
      if (state.clientHistory.generation !== generation) return true;
      markHistoryFailure(state.clientHistory, key);
      const rangeLabel = historyRangeLabel(range);
      chartNode("client-chart-cpu", [], [], { title: "Client history unavailable", unit: "data", range: rangeLabel, primaryLabel: "History", formatValue: String });
      chartNode("client-chart-traffic", [], [], { title: "Client history unavailable", unit: "data", range: rangeLabel, primaryLabel: "History", formatValue: String });
      return false;
    }
  }

  function sessionFilterPath() {
    const form = $("session-filters");
    const params = new URLSearchParams({ sort: "opened", order: "desc", limit: "512" });
    if (form) for (const [key, value] of new FormData(form)) if (value) params.set(key, value);
    return `/api/v1/sessions?${params}`;
  }

  function renderSessions(data) {
    const body = $("sessions-table");
    if (!body) return;
    body.replaceChildren();
    for (const session of data.sessions.items) {
      const row = document.createElement("tr");
      const cells = [session.id, session.client, session.kind, session.path, session.state, formatBytes(session.traffic.sent_bytes + session.traffic.received_bytes), formatTime(session.opened_unix_millis), formatDuration(session.duration_millis)];
      for (const value of cells) { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); }
      body.append(row);
    }
    text("sessions-summary", `${data.sessions.returned} shown of ${data.sessions.total} sessions. Only shortened session identifiers are shown.`);
  }

  async function refreshCurrentRoute() {
    const route = showRoute();
    if (route.view === "overview") {
      if (state.overview) renderOverview(state.overview);
      return refreshServerHistory();
    } else if (route.view === "client" && route.name) {
      const detail = await requestJson(`/api/v1/clients/${encodeURIComponent(route.name)}`, "detail");
      if (activeRoute().view !== "client" || activeRoute().name !== route.name) return true;
      state.detail = detail;
      renderClientDetail(detail);
      return refreshClientHistory(route.name);
    } else if (route.view === "sessions") {
      const sessions = await requestJson(sessionFilterPath(), "sessions");
      if (activeRoute().view !== "sessions") return true;
      state.sessionData = sessions;
      renderSessions(sessions);
    }
    return true;
  }

  function scheduleNext() {
    clearTimeout(state.timer);
    if (document.hidden) return;
    const delay = state.failures ? Math.min(MAX_BACKOFF_MILLIS, POLL_MILLIS * 2 ** state.failures) : POLL_MILLIS;
    state.timer = window.setTimeout(poll, delay);
  }

  function requestPoll() {
    clearTimeout(state.timer);
    if (document.hidden) return;
    if (state.pollInFlight) {
      state.pollQueued = true;
      return;
    }
    void poll();
  }

  async function poll() {
    if (document.hidden || state.pollInFlight) return;
    state.pollInFlight = true;
    const generation = ++state.pollGeneration;
    try {
      const overview = await requestJson("/api/v1/overview", "overview");
      state.overview = overview;
      const viewSucceeded = await refreshCurrentRoute();
      if (!viewSucceeded) throw new Error("current dashboard view did not refresh");
      state.failures = 0;
      setStatus(overview.snapshot_stale ? "Live snapshot is stale" : "Live · updates every 2 seconds", overview.snapshot_stale ? "stale" : "live");
    } catch (error) {
      if (error.name !== "AbortError") {
        state.failures += 1;
        setStatus(`Data is stale · retrying in ${Math.min(MAX_BACKOFF_MILLIS, POLL_MILLIS * 2 ** state.failures) / 1000}s`, "stale");
      }
    } finally {
      if (generation === state.pollGeneration) state.pollInFlight = false;
      if (document.hidden) {
        state.pollQueued = false;
      } else if (state.pollQueued) {
        state.pollQueued = false;
        requestPoll();
      } else {
        scheduleNext();
      }
    }
  }

  function abortHistoryRequests() {
    for (const [key, controller] of controllers) if (key.startsWith("history-")) controller.abort();
  }

  function abortSupersededViewRequests() {
    controllers.get("detail")?.abort();
    controllers.get("sessions")?.abort();
  }

  function resetHistory() {
    abortHistoryRequests();
    for (const cache of [state.serverHistory, state.clientHistory]) {
      cache.key = "";
      cache.expiresAt = 0;
      cache.retryAfter = 0;
      cache.generation += 1;
    }
  }

  $("client-search")?.addEventListener("input", (event) => { state.clientSearch = event.target.value; if (state.overview) renderClientGrid(state.overview.clients); });
  $("client-sort")?.addEventListener("change", (event) => { state.clientSort = event.target.value; state.clientDescending = event.target.value !== "name"; text("client-order", state.clientDescending ? "Descending" : "Ascending"); if (state.overview) renderClientGrid(state.overview.clients); });
  $("client-order")?.addEventListener("click", () => { state.clientDescending = !state.clientDescending; text("client-order", state.clientDescending ? "Descending" : "Ascending"); if (state.overview) renderClientGrid(state.overview.clients); });
  $("history-range")?.addEventListener("change", () => { resetHistory(); requestPoll(); });
  $("session-filters")?.addEventListener("submit", (event) => { event.preventDefault(); abortSupersededViewRequests(); if (activeRoute().view === "sessions") requestPoll(); });
  $("logout-button")?.addEventListener("click", async () => { try { await fetch("/logout", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, credentials: "same-origin", body: "" }); } finally { window.location.assign("/login"); } });
  window.addEventListener("hashchange", () => { abortSupersededViewRequests(); resetHistory(); requestPoll(); });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearTimeout(state.timer);
      state.pollQueued = false;
      for (const controller of controllers.values()) controller.abort();
    } else {
      requestPoll();
    }
  });
  showRoute();
  requestPoll();
})();
