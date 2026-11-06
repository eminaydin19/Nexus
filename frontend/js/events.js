import { api } from "./api.js";
import { customerButton } from "./actions.js";
import { eventRow } from "./overview.js";
import { h, list, section } from "./ui.js";
import { isAnomaly, knownRules, ruleName, serverName } from "./wording.js";

const LIMIT = 200;
const TYPES = [
  ["", "All events", {}],
  ["blocked", "Blocked", { action: ["block_port", "block_all"], simulated: false }],
  ["slowed", "Slowed", { action: "rate_limit", simulated: false }],
  ["watching", "Would have blocked", { simulated: true }],
  ["alerts", "Alerts", { action: "alert" }],
  ["unusual", "Unusual load", null],
];
const filters = { node: "", type: "", rule: "" };

function optionNodes(options, value) {
  return options.map(([v, label]) => {
    const o = h("option", "", label);
    o.value = v;
    o.selected = v === value;
    return o;
  });
}

function select(id, text, options, value, onChange) {
  const el = h("select", "", ...optionNodes(options, value));
  el.id = id;
  el.addEventListener("change", () => onChange(el.value));
  const label = h("label", "", text, el);
  label.htmlFor = id;
  return label;
}

const serverOptions = (ctx) => [["", "All servers"], ...ctx.overview.servers.map((s) => [s.node_id, serverName(s)])];

function syncServers(ctx) {
  const el = document.getElementById("f-node");
  if (!el) return;
  const options = serverOptions(ctx);
  if (options.length === el.options.length && options.every(([v, l], i) => el.options[i].value === v && el.options[i].text === l)) return;
  el.replaceChildren(...optionNodes(options, filters.node));
  filters.node = el.value;
}

function filterBar(ctx) {
  const change = (name) => (value) => {
    filters[name] = value;
    ctx.refresh();
  };
  const form = h(
    "form",
    "controls",
    select("f-node", "Server", serverOptions(ctx), filters.node, change("node")),
    select("f-type", "Type", TYPES.map(([v, l]) => [v, l]), filters.type, change("type")),
    select("f-rule", "Rule", [["", "All rules"], ...knownRules.map((r) => [r, ruleName(r)])], filters.rule, change("rule")),
  );
  form.addEventListener("submit", (e) => e.preventDefault());
  form.dataset.keep = "filters";
  return form;
}

async function load() {
  const { node, type, rule } = filters;
  const params = TYPES.find(([v]) => v === type)[2];
  const wantEvents = params !== null;
  const wantAnomalies = (type === "" || type === "unusual") && !rule;
  const [events, anomalies] = await Promise.all([
    wantEvents ? api.events({ ...params, node, rule, limit: LIMIT }) : { events: [] },
    wantAnomalies ? api.anomalies({ node, limit: LIMIT }) : { anomalies: [] },
  ]);
  return { rows: [...events.events, ...anomalies.anomalies].sort((a, b) => b.ts - a.ts).slice(0, LIMIT) };
}

export default {
  title: "Events",
  nav: "events",
  load,
  render(data, _params, ctx) {
    syncServers(ctx);
    const filtered = filters.node || filters.type || filters.rule;
    const rows = data.rows.map((r) => {
      const offer = !isAnomaly(r) && r.action !== "alert";
      return eventRow(r, ctx, offer ? customerButton(r, ctx, `event:${r.id}`) : null);
    });
    return [
      h("div", "state", h("h1", "", "Events"), h("p", "lede", "What the rules and anomaly models found. A score alone never blocks anyone.")),
      filterBar(ctx),
      section("Newest first", data.rows.length === LIMIT ? `Showing the latest ${LIMIT}` : null, list(rows, filtered ? "No events match these filters." : "No events yet. They appear here as your servers report them.")),
    ];
  },
};
