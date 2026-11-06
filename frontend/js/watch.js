import { api } from "./api.js";
import { NEXT_CHECK_IN, askEnforce, customerButton, enforceProblem, statusNote } from "./actions.js";
import { btn, duration, h, list, plural, section } from "./ui.js";
import { isServerWide, ruleName, serverName, wouldDo } from "./wording.js";

function watchRow(item, nodeId, ctx) {
  const detail = h(
    "div",
    "stack",
    h("div", "what", ruleName(item.rule)),
    h("div", "meta", wouldDo(item, duration), `, ${plural(item.count, "time")} in 7 days `, h("span", "code", item.rule)),
    item.evidence ? h("div", "ev", item.evidence) : null,
  );
  const key = `customer:watch:${nodeId}:${item.ip}:${item.rule}`;
  const act = item.pending ? statusNote(`Customer sent, ${NEXT_CHECK_IN}`, key) : customerButton(item, ctx, `watch:${nodeId}:${item.rule}`);
  const who = isServerWide(item) ? "Server-wide" : item.cover;
  return h("li", "row watch", h("div", "who", who), detail, h("div", "acts", act));
}

function call(entry, ctx) {
  const server = entry.server;
  const name = serverName(server);
  const problem = enforceProblem(server);
  const text = entry.ready
    ? `${name} has watched for ${entry.watched_days} days. Blocking starts only when you approve it.`
    : `${name} is on day ${entry.watched_days + 1} of ${entry.window_days}.${problem ? "" : " You can start blocking earlier if you are sure."}`;
  const review = btn("Review and start blocking", {
    ghost: !entry.ready,
    key: `enforce:${server.node_id}`,
    disabled: Boolean(problem),
    label: `Review and start blocking on ${name}`,
    onClick: () => askEnforce(server, ctx),
  });
  return h("div", entry.ready ? "call" : "call quiet", h("div", "stack", h("p", "", text), problem ? h("p", "", problem) : null), review);
}

export default {
  title: "Watch",
  nav: "watch",
  load: () => api.watchAll(),
  render(data, _params, ctx) {
    const servers = data.servers;
    if (!servers.length) {
      return [h("div", "state", h("h1", "", "No server is watching right now."), h("p", "lede", "A server watches first and reports what it would have blocked. New servers start here."))];
    }
    const title = servers.length === 1 ? `${serverName(servers[0].server)} is watching. Nothing is being blocked.` : `${servers.length} servers are watching. Nothing is being blocked on them.`;
    const out = [
      h("div", "state", h("h1", "", title), h("p", "lede", "These addresses would have been blocked. Mark any real customer, and Nexus will not block that address on any server.")),
    ];
    for (const entry of servers) {
      const name = serverName(entry.server);
      const rows = entry.items.map((item) => watchRow(item, entry.node_id, ctx));
      const sub = entry.would_block || entry.would_slow ? `${plural(entry.would_block, "would-be block")}, ${plural(entry.would_slow, "would-be limit")} in 7 days` : null;
      const cut = entry.items_total > entry.items.length ? h("p", "sub", `Showing the newest ${entry.items.length} of ${entry.items_total} entries.`) : null;
      out.push(section(`${name}: would have been blocked`, sub, call(entry, ctx), cut, list(rows, `No addresses to review. New ones appear here as ${name} sees them.`)));
    }
    return out;
  },
};
