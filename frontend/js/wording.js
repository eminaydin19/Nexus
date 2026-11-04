const RULES = new Map([
  ["ssh_bruteforce", "SSH password guessing"],
  ["web_login_bruteforce", "Login guessing"],
  ["web_probe", "Scanning for admin files"],
  ["web_exploit", "Attack patterns in requests"],
  ["conn_flood", "Too many connections"],
  ["distributed_flood", "Flood from many addresses"],
  ["port_scan", "Port scan"],
  ["breaker", "Blocking paused for safety"],
]);
const SERVER_WIDE_RULES = new Set(["distributed_flood", "breaker"]);
const MODE_LABELS = new Map([["enforce", "Blocking"], ["observe", "Watching"], ["off", "Off"]]);

export const MODES = ["off", "observe", "enforce"];
export const knownRules = [...RULES.keys()];
export const ruleName = (rule) => RULES.get(rule) ?? rule;
export const modeName = (mode) => MODE_LABELS.get(mode) ?? mode;
export const serverName = (server) => server.name || server.node_id;

export const isServerWide = (row) => row.ip === "0.0.0.0" || row.ip === "::" || SERVER_WIDE_RULES.has(row.rule);

export function modeState(server) {
  if (server.status === "revoked") return { cls: "neutral", text: "Revoked" };
  if (server.status === "never") return { cls: "warn", text: "Not seen yet" };
  if (server.status === "offline") return { cls: "danger", text: "Offline" };
  const cls = server.reported_mode === "enforce" ? "ok" : server.reported_mode === "observe" ? "warn" : "neutral";
  return { cls, text: modeName(server.reported_mode) };
}

/* IPv6 blocks cover a whole /64 and the agent reports only its network address. */
export const blockAddress = (block) => (block.ip.includes(":") && !block.ip.includes("/") ? `${block.ip}/64` : block.ip);

const portsText = (ports) => `${ports.length === 1 ? "port" : "ports"} ${ports.join(", ")}`;
const capital = (s) => s[0].toUpperCase() + s.slice(1);
/* Keeps acronyms and raw rule codes as they are. */
const inSentence = (name) => (/^[A-Z][a-z]/.test(name) ? name[0].toLowerCase() + name.slice(1) : name);

export function blockScope(block, left) {
  if (block.kind === "rate_limit") return "New connections limited";
  if (block.kind === "block_port" && block.ports.length) return `${capital(portsText(block.ports))} only`;
  return `All ports, ${left} left`;
}

export function wouldDo(item, duration) {
  const time = item.ttl ? ` for ${duration(item.ttl)}` : "";
  if (item.action === "rate_limit") return `Would limit new connections${time}`;
  if (item.action === "block_port" && item.ports.length) return `Would block ${portsText(item.ports)}${time}`;
  return `Would block all ports${time}`;
}

function eventHeadline(e) {
  const name = inSentence(ruleName(e.rule));
  if (e.action === "alert") return ruleName(e.rule);
  if (e.action === "rate_limit") {
    if (e.simulated) return `Would slow one address: ${name}`;
    return e.ok ? `Slowed one address: ${name}` : `Could not slow one address: ${name}`;
  }
  if (e.simulated) return `Would block ${name}`;
  return e.ok ? `Blocked ${name}` : `Could not block ${name}`;
}

function eventPill(e) {
  if (e.simulated) return { cls: "warn", text: "Watching" };
  if (e.action === "alert") return { cls: "neutral", text: "Alert" };
  if (!e.ok) return { cls: "danger", text: "Failed" };
  return e.action === "rate_limit" ? { cls: "warn", text: "Slowed" } : { cls: "danger", text: "Blocked" };
}

export const isAnomaly = (row) => "culprit" in row;

/* One event or ML anomaly as the same row content. Anomalies never block, so they say so. */
export function describeRow(row) {
  if (isAnomaly(row)) {
    const score = row.scores?.ensemble;
    return {
      node: row.node,
      what: "Unusual load, no block",
      who: "Server-wide",
      code: null,
      evidence: `Anomaly score ${typeof score === "number" ? score.toFixed(2) : "unknown"}: ${row.culprit}`,
      pill: { cls: "neutral", text: "Alert" },
    };
  }
  return {
    node: row.node_id,
    what: eventHeadline(row),
    who: isServerWide(row) ? "Server-wide" : row.ip,
    code: row.rule,
    evidence: row.evidence,
    pill: eventPill(row),
  };
}
