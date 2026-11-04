import { api } from "./api.js";
import { MODES, blockAddress, isServerWide, modeName, ruleName, serverName } from "./wording.js";
import { btn, confirmDialog, h, plural, toast } from "./ui.js";

export const NEXT_CHECK_IN = "applies at next check-in";

export function statusNote(text, key) {
  const note = h("span", "note", text);
  if (key) {
    note.dataset.key = key;
    note.tabIndex = -1;
  }
  return note;
}

export function removeButton(block, ctx) {
  if (isServerWide(block)) return null;
  const key = `remove:${block.node_id}:${block.ip}:${block.kind}`;
  if (block.pending_removal) return statusNote(`Removal sent, ${NEXT_CHECK_IN}`, key);
  const address = blockAddress(block);
  return btn("Remove", {
    ghost: true,
    key,
    label: `Remove ${address} on ${ctx.name(block.node_id)}`,
    onClick: async () => {
      await api.unblock(block.node_id, block.ip);
      toast(`Removal of ${address} sent to ${ctx.name(block.node_id)}, ${NEXT_CHECK_IN}.`);
      await ctx.refresh();
    },
  });
}

export function customerButton(row, ctx, scope) {
  if (isServerWide(row)) return null;
  return btn("This is a customer", {
    ghost: true,
    key: `customer:${scope}:${row.ip}`,
    label: `${row.cover ?? row.ip} is a customer`,
    onClick: () => markCustomer(row.ip, ctx),
  });
}

export const notSaved = (failed, ctx) => `Not saved for ${failed.map(ctx.name).join(", ")}. Try again.`;

export async function markCustomer(ip, ctx) {
  const { entry, sent, full, failed } = await api.markCustomer(ip);
  const parts = [];
  if (sent.length) parts.push(`${entry} sent to ${plural(sent.length, "server")}, ${NEXT_CHECK_IN}.`);
  else if (!full.length && !failed.length) parts.push("There are no servers to send this to.");
  if (full.length) parts.push(`Not allowed on ${full.map(ctx.name).join(", ")}: the allowlist is full.`);
  if (failed.length) parts.push(notSaved(failed, ctx));
  toast(parts.join(" "));
  await ctx.refresh();
}

export function enforceProblem(server) {
  if (server.status === "never") return "This server has not checked in yet.";
  if (server.max_mode !== "enforce") {
    return `This server's agent is capped at ${modeName(server.max_mode)}. To allow blocking, set NEXUS_MAX_MODE=enforce in /etc/nexus-agent.env and run: sudo systemctl restart nexus-agent`;
  }
  if (server.capabilities?.enforce === false) return "This server cannot block because nftables is not usable on it.";
  return null;
}

function summaryLines(summary) {
  const lines = [];
  if (summary.would_block) lines.push(`${plural(summary.would_block, "block")} on ${plural(summary.addresses, "address", "addresses")}`);
  if (summary.would_slow) lines.push(`${plural(summary.would_slow, "connection limit")} on ${plural(summary.limited_addresses, "address", "addresses")}`);
  if (summary.waiting) lines.push(`${plural(summary.waiting, "address", "addresses")} still waiting for review`);
  const top = summary.by_rule[0];
  if (top) lines.push(`Most common: ${ruleName(top.rule)} (${top.count})`);
  return lines;
}

export async function askEnforce(server, ctx) {
  const summary = await api.watchOne(server.node_id);
  const name = serverName(server);
  const lines = summaryLines(summary);
  const intro = lines.length
    ? `In the last ${summary.window_days} days of watching, ${name} would have done the following:`
    : `${name} recorded nothing it would have blocked in the last ${summary.window_days} days.`;
  const short = summary.ready ? null : `It has watched for ${plural(summary.watched_days, "day")}, so this summary covers less than the usual ${summary.window_days}.`;
  const body = [
    h("p", "", intro),
    lines.length ? h("ul", "", ...lines.map((l) => h("li", "", l))) : null,
    short ? h("p", "", short) : null,
    h("p", "sub", `Blocks expire by themselves. You can turn this off at any time, and doing so lifts every block on ${name}.`),
  ].filter(Boolean);
  const yes = await confirmDialog({ title: `Start blocking on ${name}?`, body, yes: "Start blocking", no: "Keep watching" });
  if (!yes) return;
  await api.setMode(server.node_id, "enforce");
  toast(`Sent, ${name} starts blocking at its next check-in.`);
  await ctx.refresh();
}

async function askLowerMode(server, mode, ctx) {
  const name = serverName(server);
  const label = modeName(mode);
  const after = mode === "off" ? "It also stops acting on attacks." : "It keeps reporting what it would have blocked.";
  const yes = await confirmDialog({
    title: `Switch ${name} to ${label}?`,
    body: [h("p", "", `All blocks on ${name} are lifted. ${after}`)],
    yes: `Switch to ${label}`,
    danger: true,
  });
  if (!yes) return;
  await api.setMode(server.node_id, mode);
  toast(`Sent, ${name} switches to ${label} at its next check-in.`);
  await ctx.refresh();
}

async function withdrawMode(server, mode, replaced, ctx) {
  const name = serverName(server);
  await api.setMode(server.node_id, mode);
  toast(`Sent, this replaced the switch to ${modeName(replaced)}. ${name} stays on ${modeName(mode)}, ${NEXT_CHECK_IN}.`);
  await ctx.refresh();
}

/* What the server is doing now is the pressed button; a request still on its way is stated next to it, and can be replaced. */
export function modeControl(server, ctx) {
  const problem = enforceProblem(server);
  const pendingMode = server.pending.filter((c) => c.type === "mode").at(-1)?.payload?.mode;
  const switching = pendingMode && pendingMode !== server.reported_mode ? pendingMode : null;
  const choose = (mode) => {
    if (mode === server.reported_mode) return switching ? withdrawMode(server, mode, switching, ctx) : null;
    return mode === "enforce" ? askEnforce(server, ctx) : askLowerMode(server, mode, ctx);
  };
  const buttons = MODES.slice().reverse().map((mode) => {
    const capped = server.status === "never" || (mode === "enforce" ? Boolean(problem) : MODES.indexOf(mode) > MODES.indexOf(server.max_mode));
    const b = btn(modeName(mode), {
      ghost: true,
      key: `mode:${server.node_id}:${mode}`,
      disabled: capped,
      onClick: () => choose(mode),
    });
    b.setAttribute("aria-pressed", String(server.reported_mode === mode));
    return b;
  });
  const group = h("div", "modes", ...buttons);
  group.setAttribute("role", "group");
  group.setAttribute("aria-label", `Mode of ${serverName(server)}`);
  const notes = [
    switching ? h("span", "meta", `Switching to ${modeName(switching)}, ${NEXT_CHECK_IN}.`) : null,
    server.config?.enforce_waiting_sample ? h("span", "meta", "Waiting for a first look at open ports before blocking.") : null,
    problem ? h("span", "meta", problem) : null,
  ];
  return h("div", "stack", group, ...notes);
}
