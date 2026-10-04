'use strict';

const METRICS = [
  { key: 'cpu_pct', label: 'CPU', unit: '%', digits: 1, color: '#818cf8' },
  { key: 'memory_pct', label: 'Memory', unit: '%', digits: 1, color: '#a78bfa' },
  { key: 'net_kbps', label: 'Network in', unit: ' KB/s', digits: 1, color: '#22d3ee' },
  { key: 'latency_ms', label: 'Latency', unit: ' ms', digits: 1, color: '#fbbf24' },
];
const MODEL_ROWS = [
  { key: 'iforest', label: 'Isolation Forest' },
  { key: 'lstm', label: 'LSTM autoencoder' },
  { key: 'transformer', label: 'Transformer (Attention)' },
  { key: 'vae', label: 'VAE' },
  { key: 'ensemble', label: 'Ensemble' },
];
const MAX_POINTS = 900;

const state = {
  nodes: new Map(),
  selected: null,
  minutes: 60,
  anomalies: [],
  filter: 'all',
  health: null,
  history: [],
  clockOffset: 0,
  socket: null,
  retry: 0,
  weightsTimer: null,
  weightsInitialized: false,
  defense: null,
  defenseEvents: [],
};

const DEFENSE_LABELS = {
  safe_mode: 'Safe Mode',
  block: 'Block',
  block_failed: 'Block failed',
  block_skipped: 'Block skipped',
  unblock: 'Unblock',
  unblock_failed: 'Unblock failed',
};
const DRIVER_LABELS = { cpu: 'CPU', memory: 'Memory', network: 'Network', latency: 'Latency' };

(function initTheme() {
  const saved = localStorage.getItem('nexus-theme');
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  document.documentElement.dataset.theme = saved || (prefersLight ? 'light' : 'dark');
})();

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function serverNow() {
  return Date.now() / 1000 + state.clockOffset;
}

function fmt(value, digits = 1) {
  return value === null || value === undefined || Number.isNaN(value) ? '–' : Number(value).toFixed(digits);
}

function timeLabel(ts, withSeconds) {
  const d = new Date(ts * 1000);
  const opts = { hour: '2-digit', minute: '2-digit', hour12: false };
  if (withSeconds) opts.second = '2-digit';
  if (state.minutes >= 1440) {
    return d.toLocaleString([], { month: 'short', day: 'numeric', ...opts });
  }
  return d.toLocaleTimeString([], opts);
}

function ago(seconds) {
  if (seconds < 90) return `${Math.max(0, Math.round(seconds))}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function staleAfter() {
  const h = state.health;
  if (!h) return 600;
  return h.interval * 3 + (h.source === 'cloudwatch' ? 600 : 30);
}

function isStale(node) {
  return serverNow() - node.ts > staleAfter();
}

function chartBase(yOptions = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(15, 20, 38, 0.96)',
        borderColor: 'rgba(148, 163, 184, 0.25)',
        borderWidth: 1,
        titleColor: '#e5e9f5',
        bodyColor: '#b6bfd6',
        padding: 10,
      },
    },
    scales: {
      x: { grid: { color: 'rgba(148,163,184,0.06)' }, ticks: { color: '#8a94ad', maxTicksLimit: 7, maxRotation: 0, font: { size: 10 } } },
      y: { grid: { color: 'rgba(148,163,184,0.06)' }, ticks: { color: '#8a94ad', font: { size: 10 } }, ...yOptions },
    },
  };
}

function lineDataset(color, extra = {}) {
  return { data: [], borderColor: color, backgroundColor: `${color}22`, borderWidth: 1.8, pointRadius: 0, tension: 0.25, fill: true, spanGaps: false, ...extra };
}

const scoreChart = new Chart($('scoreChart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      lineDataset('#22d3ee', { label: 'Ensemble score', pointBackgroundColor: [], pointRadius: [] }),
      { label: 'Threshold', data: [], borderColor: '#fbbf24', borderDash: [6, 5], borderWidth: 1.4, pointRadius: 0, fill: false },
    ],
  },
  options: chartBase({ min: 0, max: 1 }),
});

const metricCharts = Object.fromEntries(
  METRICS.map((m) => [
    m.key,
    new Chart($(`chart-${m.key}`), {
      type: 'line',
      data: { labels: [], datasets: [lineDataset(m.color)] },
      options: chartBase({ beginAtZero: true }),
    }),
  ]),
);

function threshold() {
  const model = state.health && state.health.model;
  return model && model.ready ? model.threshold : null;
}

function pointFromNode(n) {
  return {
    ts: n.ts,
    cpu_pct: n.cpu_pct,
    memory_pct: n.memory_pct,
    net_kbps: n.net_kbps,
    latency_ms: n.latency_ms,
    score: n.scores ? n.scores.ensemble : null,
    is_anomaly: n.status === 'anomaly',
  };
}

function redrawCharts() {
  const withSeconds = state.minutes <= 60;
  const labels = state.history.map((p) => timeLabel(p.ts, withSeconds));
  const t = threshold();

  scoreChart.data.labels = labels;
  scoreChart.data.datasets[0].data = state.history.map((p) => p.score);
  scoreChart.data.datasets[0].pointBackgroundColor = state.history.map((p) => (p.is_anomaly ? '#fb7185' : 'transparent'));
  scoreChart.data.datasets[0].pointRadius = state.history.map((p) => (p.is_anomaly ? 4 : 0));
  scoreChart.data.datasets[1].data = t === null ? [] : state.history.map(() => t);
  scoreChart.update('none');

  METRICS.forEach((m) => {
    const chart = metricCharts[m.key];
    chart.data.labels = labels;
    chart.data.datasets[0].data = state.history.map((p) => p[m.key]);
    chart.update('none');
  });
}

async function loadHistory() {
  if (!state.selected) {
    state.history = [];
    redrawCharts();
    return;
  }
  const node = state.selected;
  try {
    const res = await fetch(`/api/metrics/${encodeURIComponent(node)}?minutes=${state.minutes}&points=600`);
    if (!res.ok) throw new Error(res.status);
    const body = await res.json();
    if (state.selected !== node) return;
    state.history = body.points;
  } catch {
    state.history = [];
  }
  redrawCharts();
}

function appendLive(node) {
  const point = pointFromNode(node);
  const last = state.history[state.history.length - 1];
  if (last && last.ts === point.ts) return;
  state.history.push(point);
  if (state.history.length > MAX_POINTS) state.history.shift();
  redrawCharts();
}

function selectNode(id) {
  if (state.selected === id) return;
  state.selected = id;
  renderFleet();
  renderDetail();
  loadHistory();
}

function sortedNodes() {
  return [...state.nodes.values()].sort((a, b) => a.node.localeCompare(b.node, undefined, { numeric: true }));
}

function renderFleet() {
  const nodes = sortedNodes();
  $('fleetEmpty').hidden = nodes.length > 0;
  $('fleetCount').textContent = nodes.length ? `${nodes.length} node${nodes.length === 1 ? '' : 's'}` : '';
  $('fleetList').innerHTML = nodes
    .map((n) => {
      const stale = isStale(n);
      const status = stale ? 'stale' : n.status;
      const label = stale ? 'stale' : n.status === 'ok' ? 'normal' : n.status;
      const score = n.scores ? n.scores.ensemble : 0;
      const classes = ['node', n.node === state.selected ? 'selected' : '', n.status === 'anomaly' && !stale ? 'anomaly' : '', stale ? 'stale' : '']
        .filter(Boolean)
        .join(' ');
      return `<button type="button" class="${classes}" data-node="${esc(n.node)}">
        <div class="node-top"><span class="node-name" title="${esc(n.node)}">${esc(n.node)}</span><span class="badge ${status}">${label}</span></div>
        <div class="node-stats">
          <span>CPU<b>${fmt(n.cpu_pct, 0)}%</b></span>
          <span>MEM<b>${fmt(n.memory_pct, 0)}%</b></span>
          <span>NET<b>${fmt(n.net_kbps, 0)}</b></span>
          <span>LAT<b>${fmt(n.latency_ms, 0)}</b></span>
        </div>
        <div class="node-bar"><i style="width:${Math.round(Math.min(1, score) * 100)}%"></i></div>
      </button>`;
    })
    .join('');
}

function renderDetail() {
  const node = state.selected ? state.nodes.get(state.selected) : null;
  $('detailTitle').textContent = node ? node.node : 'Select a node';
  $('detailSub').textContent = node ? `last sample ${ago(serverNow() - node.ts)}` : '';
  METRICS.forEach((m) => {
    $(`now-${m.key}`).textContent = node ? `${fmt(node[m.key], m.digits)}${m.unit}` : '';
  });

  $('scoreBars').innerHTML = MODEL_ROWS.map((row) => {
    const value = node && node.scores ? node.scores[row.key] : null;
    const pct = value === null || value === undefined ? 0 : Math.round(Math.min(1, value) * 100);
    const hot = value !== null && value !== undefined && value >= 0.5 ? ' hot' : '';
    const text = value === null || value === undefined ? (node && node.scores ? 'warm-up' : '–') : value.toFixed(2);
    return `<div class="score-row${hot}"><span>${row.label}</span><div class="track"><i style="width:${pct}%"></i></div><output>${text}</output></div>`;
  }).join('');

  renderDrivers(node);
}

function topDrivers(contributions, count) {
  return Object.entries(contributions || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, count);
}

function renderDrivers(node) {
  const contributions = node && node.contributions && Object.keys(node.contributions).length ? node.contributions : null;
  if (!contributions) {
    $('driverBars').innerHTML = `<p class="muted">${node && node.scores ? 'No data' : 'Available once a model is trained.'}</p>`;
    return;
  }
  const leader = topDrivers(contributions, 1)[0][0];
  $('driverBars').innerHTML = Object.entries(contributions)
    .sort((a, b) => b[1] - a[1])
    .map(([key, share]) => {
      const hot = key === leader && node.status === 'anomaly' ? ' hot' : '';
      return `<div class="score-row${hot}"><span>${esc(DRIVER_LABELS[key] || key)}</span><div class="track"><i style="width:${Math.round(share * 100)}%"></i></div><output>${Math.round(share * 100)}%</output></div>`;
    })
    .join('');
}

function renderKpis() {
  const nodes = sortedNodes();
  const live = nodes.filter((n) => !isStale(n)).length;
  $('kpiNodes').textContent = nodes.length;
  $('kpiNodesSub').textContent = nodes.length ? `${live} reporting` : 'waiting for data';

  const cutoff = serverNow() - 86400;
  const recent = state.anomalies.filter((a) => a.ts >= cutoff);
  const critical = recent.filter((a) => a.severity === 'critical').length;
  $('kpiAnomalies').textContent = recent.length;
  $('kpiAnomaliesSub').textContent = recent.length ? `${critical} critical` : 'none detected';

  const t = threshold();
  $('kpiThreshold').textContent = t === null ? '–' : t.toFixed(2);

  const h = state.health;
  if (h) {
    $('kpiInterval').textContent = h.interval >= 60 ? `${Math.round(h.interval / 60)} min` : `${h.interval}s`;
    $('kpiPollSub').textContent = h.last_poll ? `last poll ${ago(serverNow() - h.last_poll)}` : 'no poll yet';
  }
}

function renderAnomalies() {
  const rows = state.anomalies.filter((a) => state.filter === 'all' || a.culprit === state.filter).slice(0, 100);
  $('anomalyEmpty').hidden = rows.length > 0;
  $('anomalyBody').innerHTML = rows
    .map((a) => {
      const flags = (a.flags || []).map((f) => `<span class="chip">${esc(f)}</span>`).join('');
      const why = topDrivers(a.contributions, 2).map(([k, v]) => `${esc(DRIVER_LABELS[k] || k)} ${Math.round(v * 100)}%`).join(' · ');
      return `<tr>
        <td class="mono">${esc(new Date(a.ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }))}</td>
        <td class="mono">${esc(a.node)}</td>
        <td>${esc(a.culprit)}</td>
        <td class="muted">${why || '–'}</td>
        <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
        <td class="mono">${fmt(a.scores.ensemble, 2)}</td>
        <td>${flags || '–'}</td>
      </tr>`;
    })
    .join('');
}

function renderDefense() {
  const d = state.defense;
  if (!d) return;
  const now = serverNow();

  const modeText = { off: 'Off', dry_run: 'Dry run', enforce: 'Enforcing' }[d.mode] || d.mode;
  const pillClass = d.safe_mode ? 'bad' : d.mode === 'enforce' ? 'ok' : d.mode === 'dry_run' ? 'warn' : '';
  setPill('defensePill', 'defenseLabel', pillClass, d.safe_mode ? 'Safe Mode' : `Defense: ${modeText}`);

  $('safeBanner').hidden = !d.safe_mode;
  if (d.safe_mode && d.safe_mode_until) {
    $('safeText').textContent = `Non-essential API traffic is being rejected for another ${Math.max(0, Math.round(d.safe_mode_until - now))}s.`;
  }

  const badge = $('defenseMode');
  badge.textContent = modeText;
  badge.className = `badge ${d.mode === 'enforce' ? 'ok' : d.mode === 'dry_run' ? 'learning' : 'stale'}`;
  $('defenseSub').textContent = d.mode === 'off'
    ? 'Disabled'
    : `${d.firewall} \u00b7 blocks last ${Math.round(d.block_seconds / 60)} min${d.mode === 'dry_run' ? ' \u00b7 simulated, no firewall changes' : ''}`;

  $('blockedEmpty').hidden = d.blocked.length > 0;
  $('blockedBody').innerHTML = d.blocked.map((b) => {
    const remaining = Math.max(0, Math.round(b.until - now));
    const label = b.simulated ? '<span class="chip">simulated</span>' : '';
    return `<tr><td class="mono">${esc(b.ip)} ${label}</td><td class="mono">${esc(b.node)}</td><td>${remaining}s</td>
      <td><button type="button" class="btn btn-small" data-unblock="${esc(b.ip)}">Unblock</button></td></tr>`;
  }).join('');

  const events = state.defenseEvents.slice(0, 30);
  $('defenseEmpty').hidden = events.length > 0;
  $('defenseBody').innerHTML = events.map((e) => {
    const cls = e.ok === false ? 'critical' : e.type === 'safe_mode' ? 'warning' : e.type === 'block' ? 'critical' : 'ok';
    const target = [e.node, e.ip].filter(Boolean).join(' \u00b7 ') || '\u2013';
    return `<tr>
      <td class="mono">${esc(new Date(e.ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }))}</td>
      <td><span class="badge ${cls}">${esc(DEFENSE_LABELS[e.type] || e.type)}</span></td>
      <td class="mono">${esc(target)}</td>
      <td class="muted wrap">${esc(e.detail || '')}</td>
    </tr>`;
  }).join('');
}

function setPill(id, labelId, cls, text) {
  const pill = $(id);
  pill.classList.remove('ok', 'warn', 'bad');
  if (cls) pill.classList.add(cls);
  $(labelId).textContent = text;
}

function renderHealth() {
  const h = state.health;
  if (!h) return;
  const sourceNames = { cloudwatch: 'AWS CloudWatch' };
  setPill('sourcePill', 'sourceLabel', h.last_error ? 'bad' : 'ok', sourceNames[h.source] || h.source);

  const model = h.model;
  if (model.ready) {
    const trained = Date.parse(model.trained_at) / 1000;
    setPill('modelPill', 'modelLabel', 'ok', `Model trained ${ago(serverNow() - trained)}`);
  } else {
    setPill('modelPill', 'modelLabel', 'warn', 'Learning mode');
  }

  const learning = !model.ready;
  $('learningBanner').hidden = !learning;
  if (learning) {
    const command = 'python -m training.train';
    $('learningText').innerHTML = `Collecting data from ${esc(sourceNames[h.source] || h.source)}. Scores start once a model is trained: <code>docker compose run --rm nexus ${esc(command)}</code>`;
  }

  $('errorBanner').hidden = !h.last_error;
  if (h.last_error) $('errorText').textContent = h.last_error;

  const report = model.report || {};
  const rows = model.ready
    ? [
        ['Source', report.source],
        ['Trained', new Date(model.trained_at).toLocaleString()],
        ['Samples', `${report.rows} from ${report.nodes} node${report.nodes === 1 ? '' : 's'}`],
        ['Window', `${model.window} steps`],
        ['Evaluated on', report.eval_on],
        ['False-positive rate', report.false_positive_rate === undefined ? '–' : `${(report.false_positive_rate * 100).toFixed(2)}%`],
        ['Spike recall (4σ)', report.recall_4sigma === undefined ? '–' : `${(report.recall_4sigma * 100).toFixed(1)}%`],
        ['Spike recall (8σ)', report.recall_8sigma === undefined ? '–' : `${(report.recall_8sigma * 100).toFixed(1)}%`],
      ]
    : [['Status', 'no trained model']];
  $('report').innerHTML = rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');

  if (model.ready && !state.weightsInitialized) {
    document.querySelectorAll('#weights input').forEach((input) => {
      input.value = Math.round(model.weights[input.dataset.key] * 100);
    });
    state.weightsInitialized = true;
  }
  updateWeightLabels();
}

function updateWeightLabels() {
  const inputs = [...document.querySelectorAll('#weights input')];
  const total = inputs.reduce((sum, i) => sum + Number(i.value), 0) || 1;
  inputs.forEach((i) => {
    i.nextElementSibling.textContent = `${Math.round((Number(i.value) / total) * 100)}%`;
  });
}

function onWeightsInput() {
  updateWeightLabels();
  clearTimeout(state.weightsTimer);
  state.weightsTimer = setTimeout(async () => {
    const body = {};
    document.querySelectorAll('#weights input').forEach((i) => {
      body[i.dataset.key] = Number(i.value);
    });
    if (Object.values(body).every((v) => v === 0)) return;
    await fetch('/api/weights', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  }, 300);
}

let toastTimer = null;
function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 4500);
}

function applyNodes(nodes) {
  nodes.forEach((n) => state.nodes.set(n.node, n));
  if (!state.selected && state.nodes.size) {
    selectNode(sortedNodes()[0].node);
  }
}

function onMessage(event) {
  const msg = JSON.parse(event.data);
  if (msg.type === 'snapshot') {
    state.health = msg.health;
    state.clockOffset = msg.health.server_time - Date.now() / 1000;
    state.nodes.clear();
    state.anomalies = msg.anomalies;
    state.defense = msg.health.defense;
    state.defenseEvents = msg.defense_events || [];
    applyNodes(msg.nodes);
    renderHealth();
    renderAll();
    return;
  }
  if (msg.type === 'defense') {
    state.defense = msg.status;
    state.defenseEvents = [msg.event, ...state.defenseEvents].slice(0, 100);
    if (msg.event.type === 'safe_mode' || msg.event.type === 'block') {
      toast(`DEFENSE \u00b7 ${DEFENSE_LABELS[msg.event.type]}${msg.event.ip ? ` \u00b7 ${msg.event.ip}` : ''}${msg.event.mode === 'dry_run' ? ' (dry run)' : ''}`);
    }
    renderDefense();
    return;
  }
  if (msg.type === 'update') {
    applyNodes(msg.nodes);
    msg.nodes.forEach((n) => {
      if (n.node === state.selected) appendLive(n);
    });
    if (msg.anomalies.length) {
      state.anomalies = [...msg.anomalies, ...state.anomalies].slice(0, 200);
      const worst = msg.anomalies.find((a) => a.severity === 'critical') || msg.anomalies[0];
      toast(`${worst.severity.toUpperCase()} · ${worst.node} · ${worst.culprit} (score ${worst.scores.ensemble.toFixed(2)})`);
    }
    renderAll();
  }
}

function renderAll() {
  renderKpis();
  renderFleet();
  renderDetail();
  renderAnomalies();
  renderDefense();
}

function connect() {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${scheme}//${location.host}/ws`);
  state.socket = socket;
  socket.onopen = () => {
    state.retry = 0;
    setPill('linkPill', 'linkLabel', 'ok', 'Live');
  };
  socket.onmessage = onMessage;
  socket.onclose = () => {
    setPill('linkPill', 'linkLabel', 'bad', 'Offline');
    state.retry += 1;
    setTimeout(connect, Math.min(15000, 1000 * state.retry));
  };
  socket.onerror = () => socket.close();
}

async function refreshHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) return;
    state.health = await res.json();
    state.clockOffset = state.health.server_time - Date.now() / 1000;
    if (state.health.defense) state.defense = state.health.defense;
    renderHealth();
    renderKpis();
    renderDefense();
    redrawCharts();
  } catch {
    return;
  }
}

function tickClock() {
  $('clock').textContent = new Date().toLocaleTimeString([], { hour12: false });
}

$('fleetList').addEventListener('click', (event) => {
  const button = event.target.closest('[data-node]');
  if (button) selectNode(button.dataset.node);
});

$('rangeSelect').addEventListener('click', (event) => {
  const button = event.target.closest('[data-minutes]');
  if (!button) return;
  state.minutes = Number(button.dataset.minutes);
  document.querySelectorAll('#rangeSelect button').forEach((b) => b.classList.toggle('active', b === button));
  loadHistory();
});

$('metricFilter').addEventListener('click', (event) => {
  const button = event.target.closest('[data-filter]');
  if (!button) return;
  state.filter = button.dataset.filter;
  document.querySelectorAll('#metricFilter button').forEach((b) => b.classList.toggle('active', b === button));
  renderAnomalies();
});

document.querySelectorAll('#weights input').forEach((input) => input.addEventListener('input', onWeightsInput));

$('themeToggle').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('nexus-theme', next);
});

$('blockedBody').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-unblock]');
  if (!button) return;
  button.disabled = true;
  try {
    const res = await fetch(`/api/defense/unblock/${encodeURIComponent(button.dataset.unblock)}`, { method: 'POST' });
    if (!res.ok) throw new Error(res.status);
    toast(`Unblocked ${button.dataset.unblock}`);
  } catch {
    toast(`Could not unblock ${button.dataset.unblock}`);
    button.disabled = false;
  }


tickClock();
setInterval(tickClock, 1000);
setInterval(refreshHealth, 15000);
setInterval(() => {
  renderFleet();
  renderDetail();
  renderKpis();
  renderDefense();
}, 5000);
refreshHealth();
connect();
