import { api } from "./api.js";
import { NEXT_CHECK_IN, markCustomer, modeControl, notSaved } from "./actions.js";
import { btn, confirmDialog, h, keyValues, list, pill, plural, section, toast } from "./ui.js";
import { modeState, serverName } from "./wording.js";

const EVERYWHERE = "";

async function changeAllowlist(nodeId, change) {
  const { agents } = await api.agents();
  const server = agents.find((a) => a.node_id === nodeId);
  await api.setAllowlist(nodeId, change(server?.allowlist ?? []));
}

function addForm(servers, ctx) {
  const input = h("input");
  input.type = "text";
  input.id = "allow-ip";
  input.required = true;
  input.autocomplete = "off";
  input.placeholder = "203.0.113.7";
  const target = h("select", "", ...[[EVERYWHERE, "All servers, as a customer"], ...servers.map((s) => [s.node_id, serverName(s)])].map(([v, l]) => {
    const o = h("option", "", l);
    o.value = v;
    return o;
  }));
  target.id = "allow-target";
  const addressLabel = h("label", "", "Address or range", input);
  addressLabel.htmlFor = input.id;
  const targetLabel = h("label", "", "Where", target);
  targetLabel.htmlFor = target.id;
  const submit = h("button", "", "Add to allowlist");
  const problem = h("p", "sub form-note");
  problem.setAttribute("role", "alert");
  const form = h("form", "controls", addressLabel, targetLabel, submit, problem);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    problem.textContent = "";
    submit.disabled = true;
    try {
      const value = input.value.trim();
      if (target.value === EVERYWHERE) {
        await markCustomer(value, ctx);
      } else {
        await changeAllowlist(target.value, (current) => (current.includes(value) ? current : [...current, value]));
        toast(`${value} sent to ${ctx.name(target.value)}, ${NEXT_CHECK_IN}.`);
        await ctx.refresh();
      }
      input.value = "";
    } catch (err) {
      problem.textContent = err.message;
    } finally {
      submit.disabled = false;
    }
  });
  form.dataset.keep = "allow-form";
  return form;
}

function holderSelect(holders) {
  const scope = h("select", "", ...[[EVERYWHERE, `All ${plural(holders.length, "server")} that have it`], ...holders.map((s) => [s.node_id, serverName(s)])].map(([v, l]) => {
    const o = h("option", "", l);
    o.value = v;
    return o;
  }));
  scope.id = "remove-from";
  return scope;
}

async function removeEntry(entry, holders, ctx) {
  const only = holders.length === 1 ? holders[0] : null;
  const scope = only ? null : holderSelect(holders);
  let label = null;
  if (scope) {
    label = h("label", "", "Remove from", scope);
    label.htmlFor = scope.id;
  }
  const yes = await confirmDialog({
    title: only ? `Remove ${entry} from ${serverName(only)}?` : `Remove ${entry}?`,
    body: [label, h("p", "", `${only ? serverName(only) : "These servers"} can block this address again if it breaks a rule. Entries in an agent's own file on the server stay in force.`)],
    yes: "Remove",
    danger: true,
  });
  if (!yes) return;
  const nodeId = only ? only.node_id : scope.value;
  if (nodeId) {
    await changeAllowlist(nodeId, (current) => current.filter((e) => e !== entry));
    toast(`Removal of ${entry} sent to ${ctx.name(nodeId)}, ${NEXT_CHECK_IN}.`);
  } else {
    const { sent, failed } = await api.removeCustomer(entry);
    const done = sent.length ? `Removal of ${entry} sent to ${plural(sent.length, "server")}, ${NEXT_CHECK_IN}.` : "";
    toast([done, failed.length ? notSaved(failed, ctx) : ""].filter(Boolean).join(" ") || "No server has this entry any more.");
  }
  await ctx.refresh();
}

function allowRows(servers, ctx) {
  const holders = new Map();
  for (const server of servers) {
    for (const entry of server.allowlist ?? []) holders.set(entry, [...(holders.get(entry) ?? []), server]);
  }
  return [...holders].map(([entry, on]) =>
    h(
      "li",
      "row allow",
      h("div", "who", entry),
      h("div", "meta", on.length === servers.length && on.length > 1 ? `All ${on.length} servers` : on.map(serverName).join(", ")),
      h("div", "acts", btn("Remove", { ghost: true, key: `allow:${entry}`, label: `Remove ${entry}`, onClick: () => removeEntry(entry, on, ctx) })),
    ),
  );
}

function allowPending(servers) {
  const names = servers.filter((s) => s.pending.some((c) => c.type === "allowlist")).map(serverName);
  return names.length ? `Changes sent to ${names.join(", ")}, ${NEXT_CHECK_IN}` : "Addresses Nexus never blocks. Adding to all servers also removes any block on the address";
}

export default {
  title: "Settings",
  nav: "settings",
  async load() {
    const [{ agents }, health] = await Promise.all([api.agents(), api.health()]);
    return { servers: agents.filter((a) => a.status !== "revoked"), health };
  },
  render({ servers, health }, _params, ctx) {
    const modeRows = servers.map((s) =>
      h("li", "row modes-row", h("div", "stack", h("div", "what", serverName(s)), pill(modeState(s))), modeControl(s, ctx)),
    );
    const out = [
      h("div", "state", h("h1", "", "Settings"), h("p", "lede", "Modes and allowlists are per server and reach it at its next check-in. Thresholds live in each agent's file and are shown on its server page.")),
      section("Mode", null, list(modeRows, "No servers enrolled.")),
    ];
    if (servers.length) {
      out.push(section("Allowlist", allowPending(servers)));
      out.push(addForm(servers, ctx));
      out.push(list(allowRows(servers, ctx), "Nothing added from this panel. Entries in an agent's own file are not shown here."));
    }
    out.push(
      section(
        "Central",
        "Read-only. Set in the .env file on the central server",
        keyValues([
          ["Slack alerts", health.slack ? "On" : "Off"],
          ["Anomaly model", health.model?.ready ? "Trained" : "Still learning"],
        ]),
      ),
    );
    return out;
  },
};
