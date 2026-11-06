import { api } from "./api.js";
import { customerButton, removeButton } from "./actions.js";
import { blockAddress, blockScope, ruleName } from "./wording.js";
import { duration, h, list, pill, plural, section } from "./ui.js";

function blockRow(block, ctx) {
  const left = duration(block.until - ctx.now());
  const limited = block.kind === "rate_limit";
  const who = h("div", "stack", h("div", "who", blockAddress(block)), h("div", "meta", ctx.name(block.node_id)));
  const detail = h(
    "div",
    "stack",
    h("div", "what", ruleName(block.rule)),
    h("div", "meta", blockScope(block, left), " ", h("span", "code", block.rule)),
    h("div", "ev", block.evidence || "No log line is kept for this block."),
  );
  const state = h("div", "stack", pill(limited ? { cls: "warn", text: "Slowed" } : { cls: "danger", text: "Blocked" }), h("span", "meta", `${left} left`));
  const acts = h("div", "acts", removeButton(block, ctx), customerButton(block, ctx, `block:${block.node_id}:${block.kind}`));
  return h("li", "row blocks", who, detail, state, acts);
}

function headline(blocked, slowed) {
  if (!blocked && !slowed) return "Nothing is blocked right now.";
  const parts = [];
  if (blocked) parts.push(`${plural(blocked, "address", "addresses")} ${blocked === 1 ? "is" : "are"} blocked`);
  if (slowed) parts.push(`${plural(slowed, "address", "addresses")} ${slowed === 1 ? "is" : "are"} slowed`);
  return `${parts.join(" and ")} right now.`;
}

export default {
  title: "Blocks",
  nav: "blocks",
  load: () => api.blocks(),
  render(data, _params, ctx) {
    const blocked = data.blocks.filter((b) => b.kind !== "rate_limit");
    const slowed = data.blocks.filter((b) => b.kind === "rate_limit");
    return [
      h(
        "div",
        "state",
        h("h1", "", headline(blocked.length, slowed.length)),
        h("p", "lede", "Blocks end by themselves. Removing one reaches the server at its next check-in. What watching servers would do is under Watch."),
      ),
      section("Blocked", null, list(blocked.map((b) => blockRow(b, ctx)), "New blocks appear here with the log line that caused them.")),
      section("Slowed", "Rate limits, which never cut anyone off", list(slowed.map((b) => blockRow(b, ctx)), "No address is rate limited right now.")),
    ];
  },
};
