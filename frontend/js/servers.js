import { api, ApiError } from "./api.js";
import { modeControl } from "./actions.js";
import { chartPanels, destroyCharts, drawCharts } from "./charts.js";
import { btn, confirmDialog, dialogButton, dialogCancel, dialogForm, duration, h, keyValues, linkButton, list, pill, plural, section, showDialog, toast } from "./ui.js";
import { modeState, serverName } from "./wording.js";

const RANGES = [["60", "Last hour"], ["1440", "Last 24 hours"], ["10080", "Last 7 days"]];
let minutes = "60";

const THRESHOLDS = new Map([
  ["ssh_fail_threshold", "SSH failed logins before a block"],
  ["web_login_threshold", "Login attempts before a block"],
  ["probe_threshold", "Admin file probes before a block"],
  ["exploit_threshold", "Attack requests before a block"],
  ["scan_ports", "Closed ports before a port scan block"],
  ["max_conn_per_ip", "Connections per address before slowing"],
  ["max_new_conn_rate", "New connections per second before slowing"],
  ["syn_recv_alert", "Half-open connections before an alert"],
  ["max_tracked_ips", "Addresses tracked at once"],
  ["ssh_ports", "SSH ports"],
  ["web_ports", "Web ports"],
]);

function lastSeen(server, now) {
  if (server.status === "revoked") return `Revoked ${duration(now - server.revoked_at)} ago`;
  if (!server.last_seen) return "Never checked in";
  return `Last seen ${duration(now - server.last_seen)} ago`;
}

/* Exactly one of these two shapes reaches the operator, depending on whether central knows its public address. */
export function installCommand(token, publicUrl, origin) {
  const url = publicUrl || origin;
  // The agent refuses plain http to a remote central unless told, so a command without the flag could only fail.
  const insecure = /^http:\/\/(?!localhost\b|127\.|\[::1\])/.test(origin) ? " --insecure" : "";
  const tail = publicUrl ? "bash" : `bash -s -- --url ${origin}${insecure}`;
  return `curl -fsSL ${url}/install-agent.sh | NEXUS_ENROLL_TOKEN=${token} sudo --preserve-env=NEXUS_ENROLL_TOKEN ${tail}`;
}

async function copy(button, text, pre) {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch {
    getSelection().selectAllChildren(pre);
    button.textContent = "Selected, press Ctrl+C";
  }
}

async function showCommand(name, answer, ctx) {
  const command = installCommand(answer.token, answer.public_url, location.origin);
  const pre = h("pre", "cmd", command);
  pre.tabIndex = 0;
  const copyButton = h("button", "", "Copy command");
  copyButton.type = "button";
  copyButton.addEventListener("click", () => copy(copyButton, command, pre));
  const local = answer.public_url
    ? null
    : h("p", "", `PUBLIC_URL is not set, so this uses the address in your browser. Only agents on this machine can reach it. If you came through an SSH tunnel on a different port, change the port to the one Nexus listens on.`);
  const form = dialogForm(
    `Install the agent on ${name}`,
    h("p", "", "Run this once on the server. The token works one time and expires in 24 hours. It is not shown again."),
    pre,
    local,
    h("p", "sub", "The server starts by watching and blocks nothing until you approve it."),
    h("p", "sub", "If sudo refuses to keep the variable, allow SETENV in sudoers or run this from a root shell (sudo -i)."),
    h("div", "acts", copyButton, dialogButton("Done", "done", { ghost: true })),
  );
  await showDialog(form);
  await ctx.refresh();
}

async function addServer(ctx) {
  const input = h("input");
  input.type = "text";
  input.required = true;
  input.maxLength = 128;
  input.autofocus = true;
  input.autocomplete = "off";
  const problem = h("p", "sub");
  problem.setAttribute("role", "alert");
  const create = dialogButton("Create install command", "create");
  const form = dialogForm(
    "Add a server",
    h("label", "", "Server name", input),
    problem,
    h("div", "acts", dialogCancel("Cancel"), create),
  );
  let answer = null;
  form.addEventListener("submit", async (e) => {
    if (e.submitter?.value !== "create") return;
    e.preventDefault();
    create.disabled = true;
    try {
      answer = await api.createToken(input.value.trim());
      form.closest("dialog").close("created");
    } catch (err) {
      problem.textContent = err.message;
    } finally {
      create.disabled = false;
    }
  });
  const name = () => input.value.trim();
  const value = await showDialog(form);
  if (value === "created" && answer) await showCommand(name(), answer, ctx);
}

async function revoke(server, ctx) {
  const name = serverName(server);
  const yes = await confirmDialog({
    title: `Revoke ${name}?`,
    body: [h("p", "", "The agent stops being able to report, and nothing can be sent to it. Blocks already in the kernel expire on their own. This cannot be undone: to bring the server back, add it again.")],
    yes: "Revoke",
    danger: true,
  });
  if (!yes) return;
  await api.revoke(server.node_id);
  toast(`${name} is revoked.`);
  await ctx.refresh();
}

const addButton = (ctx) => btn("Add server", { key: "add-server", onClick: () => addServer(ctx) });

function serverRow(s, ctx) {
  const who = h("div", "stack", h("div", "what", serverName(s)), serverName(s) === s.node_id ? null : h("div", "ev", s.node_id));
  return h(
    "li",
    "row servers-rows",
    who,
    pill(modeState(s)),
    h("span", "meta", lastSeen(s, ctx.now())),
    h("div", "acts", linkButton("Details", `#/servers/${encodeURIComponent(s.node_id)}`, { ghost: true, label: `Details of ${serverName(s)}` })),
  );
}

export const serverList = {
  title: "Servers",
  nav: "servers",
  load: () => api.agents(),
  render(data, _params, ctx) {
    const live = data.agents.filter((a) => a.status !== "revoked");
    const revoked = data.agents.filter((a) => a.status === "revoked");
    const online = live.filter((a) => a.status === "online").length;
    const title = live.length ? `${online} of ${plural(live.length, "server")} checked in recently.` : "No servers yet.";
    const lede = live.length ? "Open a server for its charts and thresholds." : "Add a server to get its install command. It watches first and blocks nothing until you approve it.";
    const out = [
      h("div", "state-head", h("div", "state", h("h1", "", title), h("p", "lede", lede)), addButton(ctx)),
      section("Enrolled", null, list(live.map((s) => serverRow(s, ctx)), "No servers enrolled.")),
    ];
    if (revoked.length) out.push(section("Revoked", "These agents can no longer report", list(revoked.map((s) => serverRow(s, ctx)))));
    return out;
  },
};

function rangeSelect(ctx, nodeId) {
  const el = h("select", "", ...RANGES.map(([v, label]) => {
    const o = h("option", "", label);
    o.value = v;
    o.selected = v === minutes;
    return o;
  }));
  el.id = "range";
  el.addEventListener("change", () => {
    minutes = el.value;
    ctx.refresh();
  });
  const label = h("label", "", "Time range", el);
  label.htmlFor = "range";
  const kept = h("div", "section", h("div", "controls", label), h("div", "charts", ...chartPanels()));
  kept.dataset.keep = `charts:${nodeId}`;
  return kept;
}

function thresholds(rules) {
  const pairs = Object.entries(rules ?? {}).map(([k, v]) => [THRESHOLDS.get(k) ?? k, Array.isArray(v) ? v.join(", ") : String(v)]);
  return pairs.length ? keyValues(pairs) : list([], "The agent has not reported its thresholds yet.");
}

function cdnText(config) {
  if (config.behind_cdn === undefined) return "Not reported yet";
  return config.behind_cdn ? "Behind a CDN: web rules only alert" : "Not behind a CDN";
}

/* Log lines the agent skipped as older than 10 minutes. A wrong clock or timezone makes all of them look old, and detection then sees nothing. */
function staleText(config) {
  if (config.stale_lines === undefined) return "Not reported yet";
  return config.stale_lines ? `${config.stale_lines} skipped. If this keeps growing, check this server's clock and timezone` : "None";
}

function capabilities(s) {
  const can = s.capabilities?.enforce;
  return keyValues([
    ["Can block with nftables", can === undefined ? "Not reported yet" : can ? "Yes" : "No"],
    ["Highest mode allowed", modeState({ status: "online", reported_mode: s.max_mode }).text],
    ["CDN", cdnText(s.config ?? {})],
    ["Old log lines", staleText(s.config ?? {})],
    ["Platform", String(s.capabilities?.platform ?? "Not reported yet")],
    ["Agent version", s.version || "Not reported yet"],
  ]);
}

export const serverDetail = {
  title: "Server",
  nav: "servers",
  async load({ id }) {
    const [{ agents }, metrics] = await Promise.all([api.agents(), api.metrics(id, minutes)]);
    const server = agents.find((a) => a.node_id === id);
    if (!server) throw new ApiError(404, "This server does not exist. It may have been removed.");
    return { server, points: metrics.points };
  },
  render({ server }, _params, ctx) {
    const name = serverName(server);
    const live = server.status !== "revoked";
    const head = h(
      "div",
      "state-head",
      h(
        "div",
        "state",
        h("h1", "", name),
        h("div", "stack", pill(modeState(server)), h("span", "meta", lastSeen(server, ctx.now())), name === server.node_id ? null : h("span", "ev", server.node_id)),
      ),
      live ? btn("Revoke", { ghost: true, key: `revoke:${server.node_id}`, onClick: () => revoke(server, ctx) }) : null,
    );
    return [
      head,
      live ? section("Mode", "Applies at the next check-in", modeControl(server, ctx)) : null,
      rangeSelect(ctx, server.node_id),
      section("Thresholds", "Read-only. Set in the agent's file on the server", thresholds(server.config?.rules)),
      section("Capabilities", null, capabilities(server)),
    ].filter(Boolean);
  },
  after(root, { points }) {
    drawCharts(root, points);
  },
  leave: destroyCharts,
};
