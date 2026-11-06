import { clock, duration, facts, h, linkButton, list, pill, section } from "./ui.js";
import { describeRow, modeState, serverName } from "./wording.js";

const JOURNAL = "sudo journalctl -u nexus-agent -n 50";
const RESTART = "sudo systemctl restart nexus-agent";

const REJECTED = new Map([
  ["max_mode", { text: "The agent is capped below Blocking, so it keeps watching. Set NEXUS_MAX_MODE=enforce in /etc/nexus-agent.env, then run:", command: RESTART }],
  ["no_nft", { text: "nftables is not available on this server, so it keeps watching. Install nftables, then run:", command: RESTART }],
  ["setup_failed", { text: "The agent could not set up its firewall table. To see why, run this on the server:", command: JOURNAL }],
]);

function attentionContent(a, now) {
  const name = a.name || a.node_id;
  switch (a.type) {
    case "offline":
      return a.last_seen
        ? { p: { cls: "danger", text: "Offline" }, title: `${name} stopped checking in`, text: `Last seen ${duration(now - a.last_seen)} ago. Blocks it already applied expire by themselves if the server is still up. To see why the agent stopped, run this on the server:`, command: JOURNAL }
        : { p: { cls: "warn", text: "Not seen" }, title: `${name} has not checked in yet`, text: "Its install may not have finished. To check the agent, run this on the server:", command: JOURNAL };
    case "watch_ready":
      return { p: { cls: "warn", text: "Ready" }, title: `${name} finished 7 days of watching`, text: "Review what it would have blocked, then decide. It will not start blocking by itself.", link: ["Review", "#/watch"] };
    case "enforce_rejected": {
      const known = REJECTED.get(a.reason) ?? { text: `The agent refused to start blocking. Reason: ${a.reason ?? "not given"}. To see more, run this on the server:`, command: JOURNAL };
      return { p: { cls: "danger", text: "Refused" }, title: `${name} could not start blocking`, ...known };
    }
    case "breaker_open":
      return { p: { cls: "danger", text: "Paused" }, title: `Blocking paused for safety on ${name}`, text: "Too many new blocks appeared at once, so new ones become rate limits. Check recent events for a rule firing wrongly. Blocking resumes by itself once the rate falls.", link: ["See events", "#/events"] };
    case "lift_pending":
      return { p: { cls: "warn", text: "Lifting" }, title: `${name} could not lift its blocks yet`, text: "The agent keeps retrying, and the blocks expire by themselves. To look at them, run this on the server:", command: "sudo nft list table inet nexus" };
    case "behind_cdn":
      return { p: { cls: "neutral", text: "CDN" }, title: `${name} is behind a CDN`, text: "The firewall sees the CDN's address, so web rules only raise alerts here. SSH rules still block. To act on visitors, log their real address in your web server." };
    default:
      return { p: { cls: "neutral", text: "Notice" }, title: `${name}: ${a.type}`, text: "" };
  }
}

const URGENCY = ["danger", "warn", "neutral"];
const byUrgency = (a, b) => URGENCY.indexOf(attentionContent(a, 0).p.cls) - URGENCY.indexOf(attentionContent(b, 0).p.cls);

function attentionRow(a, now) {
  const c = attentionContent(a, now);
  const body = h("div", "", h("div", "what", c.title), h("div", "meta", c.text), c.command ? h("code", "cmdline", c.command) : null);
  const link = c.link ? linkButton(c.link[0], c.link[1], { ghost: c.link[1] !== "#/watch", label: `${c.link[0]}: ${a.name || a.node_id}` }) : null;
  return h("li", "row attention", pill(c.p), body, h("div", "acts", link));
}

export function eventRow(row, ctx, action) {
  const d = describeRow(row);
  const detail = h("div", "stack", h("div", "what", d.what), h("div", "meta", h("span", "who", d.who), d.code ? " " : null, d.code ? h("span", "code", d.code) : null), d.evidence ? h("div", "ev", d.evidence) : null);
  const end = h("div", "stack row-end", pill(d.pill), action ?? null);
  return h("li", "row events", h("span", "meta", clock(row.ts, ctx.now())), h("span", "meta", ctx.name(d.node)), detail, end);
}

function serverNote(s, now) {
  if (s.status === "never") return "Waiting for its first check-in";
  if (s.status === "offline") return `Last seen ${duration(now - s.last_seen)} ago`;
  if (s.reported_mode === "observe" && s.first_seen) {
    const day = Math.floor((now - s.first_seen) / 86400) + 1;
    return day <= 7 ? `Day ${day} of 7` : `Checked in ${duration(now - s.last_seen)} ago`;
  }
  return `Checked in ${duration(now - s.last_seen)} ago`;
}

export function serverCell(s, now) {
  const a = h("a", "server", h("b", "", serverName(s)), pill(modeState(s)), h("span", "meta", serverNote(s, now)));
  a.href = `#/servers/${encodeURIComponent(s.node_id)}`;
  return a;
}

function headline({ total, blocking, offline }) {
  if (!total) return "No servers yet.";
  const verb = total === 1 ? "server is" : "servers are";
  const first = `${blocking} of ${total} ${verb} blocking attacks.`;
  return offline ? `${first} ${offline} ${offline === 1 ? "is" : "are"} offline.` : first;
}

export default {
  title: "Overview",
  nav: "overview",
  load: (_params, ctx) => ctx.overview,
  render(data, _params, ctx) {
    const needs = new Set(data.attention.map((a) => a.node_id)).size;
    if (!data.protection.total) {
      return [
        h("div", "state", h("h1", "", headline(data.protection)), h("p", "lede", "Add your first server. It starts by watching and blocks nothing until you approve it.")),
        h("div", "", linkButton("Add a server", "#/servers")),
      ];
    }
    const state = h(
      "div",
      "state",
      h("h1", "", headline(data.protection)),
      facts([
        [data.blocked_24h, data.blocked_24h === 1 ? "attack blocked in 24 h" : "attacks blocked in 24 h"],
        [data.rate_limited_24h, data.rate_limited_24h === 1 ? "rate limit in 24 h" : "rate limits in 24 h"],
        [data.active.blocked, data.active.blocked === 1 ? "active block" : "active blocks"],
        [data.active.slowed, data.active.slowed === 1 ? "active limit" : "active limits"],
        [needs, needs === 1 ? "server needs you" : "servers need you"],
      ]),
    );
    const out = [state, section("Servers", null, h("div", "list servers", ...data.servers.map((s) => serverCell(s, ctx.now()))))];
    out.push(section("Needs you", null, list([...data.attention].sort(byUrgency).map((a) => attentionRow(a, ctx.now())), "Nothing needs you right now.")));
    out.push(section("Recent events", null, list(data.recent.map((r) => eventRow(r, ctx)), "No events yet. They appear here as your servers report them.")));
    return out;
  },
};
