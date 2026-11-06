import { clock, h } from "./ui.js";

const SERIES = [
  { key: "cpu_pct", title: "CPU", unit: "%", max: 100 },
  { key: "memory_pct", title: "RAM", unit: "%", max: 100 },
  { key: "net_kbps", title: "Network", unit: " KB/s" },
  { key: "latency_ms", title: "Latency", unit: " ms" },
  { key: "score", title: "Anomaly score", unit: "", wide: true, empty: "No score yet. The anomaly model is still learning." },
];
const charts = new Map();

const token = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const format = (value, unit) => `${Number(value).toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)}${unit}`;

const crosshair = {
  id: "crosshair",
  afterDatasetsDraw(chart) {
    const active = chart.tooltip?.getActiveElements?.()[0];
    if (!active) return;
    const { ctx, chartArea } = chart;
    ctx.save();
    ctx.strokeStyle = token("--line-strong");
    ctx.beginPath();
    ctx.moveTo(active.element.x, chartArea.top);
    ctx.lineTo(active.element.x, chartArea.bottom);
    ctx.stroke();
    ctx.restore();
  },
};

export function chartPanels() {
  return SERIES.map((s) => {
    const canvas = h("canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", `${s.title} over time`);
    const panel = h(
      "div",
      s.wide ? "chart wide" : "chart",
      h("div", "chart-head", h("h3", "what", s.title), h("span", "meta")),
      h("div", "chart-box", canvas),
      h("p", "meta"),
    );
    panel.dataset.metric = s.key;
    return panel;
  });
}

function create(canvas, s) {
  const ink = token("--fg");
  const danger = token("--danger");
  const muted = token("--muted");
  const line = token("--line");
  return new window.Chart(canvas, {
    type: "line",
    data: {
      datasets: [
        {
          data: [],
          borderColor: ink,
          borderWidth: 2,
          tension: 0,
          pointRadius: (c) => (c.raw?.anomaly ? 4 : 0),
          pointHoverRadius: 4,
          pointBackgroundColor: (c) => (c.raw?.anomaly ? danger : ink),
          pointBorderColor: token("--surface"),
          pointBorderWidth: 2,
        },
      ],
    },
    plugins: [crosshair],
    options: {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      parsing: false,
      interaction: { mode: "nearest", axis: "x", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          displayColors: false,
          backgroundColor: ink,
          callbacks: {
            title: (items) => clock(items[0].raw.x / 1000),
            label: (item) => `${format(item.raw.y, s.unit)}${item.raw.anomaly ? ", anomaly" : ""}`,
          },
        },
      },
      scales: {
        x: {
          type: "linear",
          grid: { display: false },
          border: { color: line },
          ticks: { color: muted, maxTicksLimit: 5, maxRotation: 0, callback: (v) => clock(v / 1000) },
        },
        y: {
          beginAtZero: true,
          max: s.max,
          grid: { color: line },
          border: { display: false },
          ticks: { color: muted, maxTicksLimit: 4 },
        },
      },
    },
  });
}

export function drawCharts(root, points) {
  window.Chart.defaults.font.family = token("--font");
  for (const s of SERIES) {
    const panel = root.querySelector(`[data-metric="${s.key}"]`);
    const data = points
      .filter((p) => p[s.key] != null)
      .map((p) => ({ x: p.ts * 1000, y: p[s.key], anomaly: s.key === "score" && p.is_anomaly }));
    const box = panel.querySelector(".chart-box");
    const [now, summary] = panel.querySelectorAll(".meta");
    box.hidden = !data.length;
    if (!data.length) {
      now.textContent = "";
      summary.textContent = s.empty ?? "No data in this time range.";
      continue;
    }
    const peak = Math.max(...data.map((d) => d.y));
    const last = data.at(-1).y;
    now.textContent = `Now ${format(last, s.unit)}`;
    const marks = data.filter((d) => d.anomaly).length;
    summary.textContent = `Peak ${format(peak, s.unit)} in this range.${marks ? ` ${marks} anomalies marked in red.` : ""}`;
    const canvas = box.querySelector("canvas");
    const chart = charts.get(canvas) ?? create(canvas, s);
    charts.set(canvas, chart);
    chart.data.datasets[0].data = data;
    chart.update("none");
  }
}

export function destroyCharts() {
  for (const chart of charts.values()) chart.destroy();
  charts.clear();
}
