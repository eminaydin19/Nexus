import { api } from "./api.js";
import { NEXT_CHECK_IN, markCustomer, modeControl } from "./actions.js";
import { btn, confirmDialog, h, keyValues, list, pill, section, toast } from "./ui.js";
import { modeState, serverName } from "./wording.js";

const EVERYWHERE = "";

/* Read first, right before writing, so entries added elsewhere since this page last refreshed are never wiped. */
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

async function removeEntry(server, entry, ctx) {
  const name = serverName(server);
  const yes = await confirmDialog({
    title: `Remove ${entry} from ${name}?`,
    body: [h("p", "", `${name} can block this address again if it breaks a rule. Entries in the agent's own file on the server stay in force.`)],
    yes: "Remove",
    danger: true,
  });
  if (!yes) return;
  await changeAllowlist(server.node_id, (current) => current.filter((e) => e !== entry));
  toast(`Removal of ${entry} sent to ${name}, ${NEXT_CHECK_IN}.`);
  await ctx.refresh();
}

function allowRows(servers, ctx) {
  return servers.flatMap((server) =>
    (server.allowlist ?? []).map((entry) =>
      h(
        "li",
        "row allow",
        h("div", "who", entry),
        h("div", "meta", serverName(server)),
        h("div", "acts", btn("Remove", { ghost: true, key: `allow:${server.node_id}:${entry}`, label: `Remove ${entry} from ${serverName(server)}`, onClick: () => removeEntry(server, entry, ctx) })),
      ),
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
