import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const BASE = "http://127.0.0.1:8000";
const PASS = process.env.PANEL_PASS;
const IS_XSS = PASS === "xss";
const PUBLIC_URL = process.env.PANEL_PUBLIC_URL;
const OUT = `/out/${PASS}`;
const SERVER_WITH_BLOCKS = IS_XSS ? "xss-host" : "web-1";
const PAGES = [
  ["overview", "#/"],
  ["servers", "#/servers"],
  ["server-detail", `#/servers/${SERVER_WITH_BLOCKS}`],
  ["blocks", "#/blocks"],
  ["watch", "#/watch"],
  ["events", "#/events"],
  ["settings", "#/settings"],
];

test.use({
  httpCredentials: { username: "admin", password: "panel-test" },
  baseURL: BASE,
  viewport: { width: 1360, height: 900 },
});

function watchConsole(page, allow = () => false) {
  const problems = [];
  page.on("console", (m) => { if (m.type() === "error" && !allow(m.text())) problems.push(m.text()); });
  page.on("pageerror", (e) => problems.push(String(e)));
  return problems;
}

const settled = (page) => expect(page.getByText("Loading…")).toHaveCount(0);

async function open(page, hash) {
  await page.goto(`/${hash}`);
  await settled(page);
  await expect(page.locator("#view h1").first()).toBeVisible();
}

async function noAxeViolations(page) {
  const { violations } = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" | ")}`)).toEqual([]);
}

async function noPageScroll(page) {
  const { scroll, client } = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
  expect(scroll).toBeLessThanOrEqual(client);
}

for (const [name, hash] of PAGES) {
  test(`${name}: desktop, no console errors, axe clean`, async ({ page }) => {
    const problems = watchConsole(page);
    await open(page, hash);
    await page.waitForTimeout(300);
    await noAxeViolations(page);
    await page.screenshot({ path: `${OUT}/${name}-desktop.png`, fullPage: true });
    expect(problems).toEqual([]);
  });

  test(`${name}: 375 px, no page scroll, axe clean`, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 800 });
    const problems = watchConsole(page);
    await open(page, hash);
    await page.waitForTimeout(300);
    await noPageScroll(page);
    await noAxeViolations(page);
    await page.screenshot({ path: `${OUT}/${name}-375.png`, fullPage: true });
    expect(problems).toEqual([]);
  });

  test(`${name}: survives a poll without losing the page`, async ({ page }) => {
    const problems = watchConsole(page);
    await open(page, hash);
    const before = await page.locator("#view h1").first().textContent();
    await page.waitForTimeout(5600);
    await expect(page.locator("#view h1").first()).toHaveText(before);
    await noPageScroll(page);
    expect(problems).toEqual([]);
  });
}

test("no request leaves the panel's own origin", async ({ page }) => {
  const foreign = [];
  page.on("request", (r) => { if (!r.url().startsWith(BASE)) foreign.push(r.url()); });
  for (const [, hash] of PAGES) await open(page, hash);
  expect(foreign).toEqual([]);
});

test("Archivo is served from the panel", async ({ page }) => {
  await open(page, "#/");
  expect(await page.evaluate(async () => { await document.fonts.ready; return document.fonts.check('600 15px "Archivo"'); })).toBe(true);
});

test("polling stops while the tab is hidden and resumes when visible", async ({ page }) => {
  await open(page, "#/");
  let calls = 0;
  page.on("request", (r) => { if (r.url().includes("/api/overview")) calls++; });
  const setHidden = (hidden) => page.evaluate((value) => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => value });
    document.dispatchEvent(new Event("visibilitychange"));
  }, hidden);
  await setHidden(true);
  await page.waitForTimeout(300);
  calls = 0;
  await page.waitForTimeout(6000);
  expect(calls).toBe(0);
  await setHidden(false);
  await expect.poll(() => calls, { timeout: 2000 }).toBeGreaterThan(0);
});

test("a server error keeps the page and says so", async ({ page }) => {
  await open(page, "#/blocks");
  await page.route("**/api/blocks*", (r) => r.fulfill({ status: 500, json: {} }));
  await expect(page.locator("#stale")).toContainText("Could not refresh", { timeout: 8000 });
  await expect(page.locator("#view h1")).toBeVisible();
  await page.unroute("**/api/blocks*");
  await expect(page.locator("#stale")).toBeHidden({ timeout: 8000 });
});

test("a first load that fails offers a retry", async ({ page }) => {
  await page.route("**/api/overview", (r) => r.fulfill({ status: 500, json: {} }));
  await page.goto("/#/");
  await expect(page.getByRole("heading", { name: "This page could not load" })).toBeVisible();
  await page.unroute("**/api/overview");
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(page.locator("#view h1")).toContainText("servers");
});

test("an unknown server and an unknown page say so", async ({ page }) => {
  await page.goto("/#/servers/nope");
  await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
  await page.goto("/#/constructor");
  await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
});

test("empty states are designed", async ({ page }) => {
  await page.route("**/api/blocks*", (r) => r.fulfill({ json: { blocks: [] } }));
  await open(page, "#/blocks");
  await expect(page.locator("#view h1")).toHaveText("Nothing is blocked right now.");
  await page.route("**/api/watch", (r) => r.fulfill({ json: { servers: [] } }));
  await open(page, "#/watch");
  await expect(page.locator("#view h1")).toHaveText("No server is watching right now.");
});

test("overview reports only what the API backs", async ({ page, request }) => {
  await open(page, "#/");
  const data = await (await request.get("/api/overview")).json();
  const { protection: p } = data;
  await expect(page.locator("#view h1")).toContainText(`${p.blocking} of ${p.total} servers are blocking attacks.`);
  await expect(page.locator(".facts")).toContainText(`${data.blocked_24h} attacks blocked in 24 h`);
  await expect(page.locator(".facts")).toContainText(`${data.rate_limited_24h} rate limit`);
  await expect(page.getByText("sudo journalctl -u nexus-agent -n 50").first()).toBeVisible();
  await expect(page.getByText("finished 7 days of watching")).toBeVisible();
  await expect(page.getByText("is behind a CDN")).toBeVisible();
  await expect(page.getByText("Blocking paused for safety on")).toBeVisible();
  await expect(page.getByText("could not lift its blocks yet")).toBeVisible();
  await expect(page.getByText("could not start blocking")).toBeVisible();
});

test("simulated blocks stay in Watch and out of Blocks", async ({ page }) => {
  await open(page, "#/blocks");
  await expect(page.locator(".row.blocks", { hasText: "198.51.100.61" })).toHaveCount(0);
  await open(page, "#/watch");
  await expect(page.locator(".row.watch", { hasText: "198.51.100.61" })).toBeVisible();
});

test("blocks show kind, ports, /64 and All ports", async ({ page }) => {
  await open(page, "#/blocks");
  await expect(page.locator(".row.blocks", { hasText: "203.0.113.77" })).toContainText("Port 22 only");
  await expect(page.locator(".row.blocks", { hasText: "203.0.113.77" })).toContainText("SSH password guessing");
  await expect(page.locator(".row.blocks", { hasText: "203.0.113.77" })).toContainText("ssh_bruteforce");
  await expect(page.locator(".row.blocks", { hasText: "198.51.100.23" })).toContainText("Ports 80, 443 only");
  await expect(page.locator(".row.blocks", { hasText: "2001:db8:4f::/64" })).toBeVisible();
  await expect(page.locator(".row.blocks", { hasText: "203.0.113.41" })).toContainText(/All ports, \d+ min left/);
  await expect(page.locator(".row.blocks", { hasText: "203.0.113.140" })).toContainText("Slowed");
  await expect(page.locator(".row.blocks", { hasText: "203.0.113.140" })).toContainText("New connections limited");
});

test("server-wide alerts name no address and offer no action", async ({ page }) => {
  await open(page, "#/events");
  const row = page.locator(".row.events", { hasText: "Flood from many addresses" }).first();
  await expect(row).toContainText("Server-wide");
  await expect(row).not.toContainText("0.0.0.0");
  await expect(row.getByRole("button")).toHaveCount(0);
  await expect(page.locator("#view").getByText("0.0.0.0")).toHaveCount(0);
});

test("events filter by server, type and rule, and keep the choice through a poll", async ({ page }) => {
  await open(page, "#/events");
  await page.selectOption("#f-type", "watching");
  await expect(page.locator(".row.events").first()).toContainText("Would");
  await expect(page.locator(".row.events", { hasText: "Failed password for root from 203.0.113.77" })).toHaveCount(0);
  await page.selectOption("#f-rule", { label: "Too many connections" });
  await expect(page.locator(".row.events")).toHaveCount(1);
  await page.waitForTimeout(5600);
  await expect(page.locator("#f-rule option:checked")).toHaveText("Too many connections");
  await page.selectOption("#f-type", "unusual");
  await expect(page.getByText("No events match these filters.")).toBeVisible();
  await page.selectOption("#f-rule", "");
  await expect(page.locator(".row.events").first()).toContainText("Unusual load, no block");
  await page.selectOption("#f-type", "");
});

test("removing a block by keyboard shows pending, then the row leaves", async ({ page }) => {
  const problems = watchConsole(page);
  await open(page, "#/blocks");
  const row = page.locator(".row.blocks", { hasText: "198.51.100.23" });
  const button = row.getByRole("button", { name: /^Remove 198/ });
  await button.focus();
  await expect(button).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(row).toContainText("Removal sent, applies at next check-in");
  await expect(page.locator("#toast")).toContainText("applies at next check-in");
  await expect(row).toHaveCount(0, { timeout: 15000 });
  expect(problems).toEqual([]);
});

test("focus stays on the same control through a poll", async ({ page }) => {
  await open(page, "#/blocks");
  const button = page.getByRole("button", { name: /^Remove 203\.0\.113\.77/ });
  await button.focus();
  await page.waitForTimeout(5600);
  await expect(page.getByRole("button", { name: /^Remove 203\.0\.113\.77/ })).toBeFocused();
});

test("a poll does not wipe text the operator is selecting", async ({ page }) => {
  await open(page, "#/blocks");
  const row = page.locator(".row.blocks", { hasText: "203.0.113.77" }).locator(".who");
  await row.selectText();
  const selected = await page.evaluate(() => getSelection().toString());
  expect(selected).toContain("203.0.113.77");
  await page.waitForTimeout(5600);
  expect(await page.evaluate(() => getSelection().toString())).toBe(selected);
});

test("a server that never checked in is not listed as watching", async ({ page }) => {
  await open(page, "#/watch");
  await expect(page.getByRole("heading", { name: /new-1/ })).toHaveCount(0);
});

test("the mode row does not overlap its text", async ({ page }) => {
  await open(page, "#/settings");
  const row = page.locator(".row.modes-row", { hasText: "web-3" });
  const left = await row.locator(".pill").boundingBox();
  const right = await row.locator(".modes").boundingBox();
  expect(left.x + left.width).toBeLessThanOrEqual(right.x);
});

test("a customer is sent to every live server, with pending state and a merged allowlist", async ({ page, request }) => {
  await open(page, "#/watch");
  const row = page.locator(".row.watch", { hasText: "203.0.113.18" });
  await row.getByRole("button", { name: /is a customer/ }).click();
  await expect(page.locator("#toast")).toContainText(/sent to \d+ servers, applies at next check-in/);
  await expect(row).toContainText("Customer sent, applies at next check-in");
  const { agents } = await (await request.get("/api/agents")).json();
  const web2 = agents.find((a) => a.node_id === "web-2");
  expect(web2.allowlist).toEqual(["192.0.2.0/24", "203.0.113.18/32"]);
  for (const a of agents) {
    if (a.status === "revoked") expect(a.allowlist).toEqual([]);
    else expect(a.allowlist).toContain("203.0.113.18/32");
  }
  await expect(row).toHaveCount(0, { timeout: 15000 });
});

test("enforce dialog shows the real summary, closes by Escape, and approves only by the button", async ({ page, request }) => {
  const problems = watchConsole(page);
  await open(page, "#/watch");
  const review = page.getByRole("button", { name: "Review and start blocking on web-2" });
  await review.focus();
  await page.keyboard.press("Enter");
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("Start blocking on web-2?");
  const summary = await (await request.get("/api/watch/web-2")).json();
  await expect(dialog).toContainText(`${summary.would_block} blocks on ${summary.addresses} addresses`);
  await expect(dialog).toContainText("Most common: SSH password guessing");
  await noAxeViolations(page);
  await page.screenshot({ path: `${OUT}/dialog-enforce-desktop.png` });
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(review).toBeFocused();
  const after = await (await request.get("/api/agents")).json();
  expect(after.agents.find((a) => a.node_id === "web-2").pending.filter((c) => c.type === "mode")).toEqual([]);

  await page.getByRole("button", { name: "Review and start blocking on web-2" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Keep watching" }).click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("a capped server cannot be switched and says why", async ({ page }) => {
  await open(page, "#/settings");
  const row = page.locator(".row.modes-row", { hasText: "web-3" });
  await expect(row.getByRole("button", { name: "Blocking" })).toBeDisabled();
  await expect(row).toContainText("capped at Watching");
  await expect(row).toContainText("NEXUS_MAX_MODE=enforce");
  await open(page, "#/watch");
  await expect(page.getByRole("button", { name: "Review and start blocking on web-3" })).toBeDisabled();
});

test("switching down warns that blocks lift; Off is confirmed and sent", async ({ page }) => {
  await open(page, "#/settings");
  const row = page.locator(".row.modes-row", { hasText: "web-4" });
  await expect(row.getByRole("button", { name: "Blocking" })).toHaveAttribute("aria-pressed", "true");
  await row.getByRole("button", { name: "Off" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("All blocks on web-4 are lifted");
  await noAxeViolations(page);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(row.getByRole("button", { name: "Blocking" })).toHaveAttribute("aria-pressed", "true");
  await row.getByRole("button", { name: "Watching" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Switch to Watching" }).click();
  await expect(page.locator("#toast")).toContainText("next check-in");
  await expect(row).toContainText("Switching to Watching, applies at next check-in");
  await expect(row.getByRole("button", { name: "Watching" })).toHaveAttribute("aria-pressed", "true", { timeout: 15000 });
});

test("approving enforce sends it and the button follows what the agent reports", async ({ page }) => {
  await open(page, "#/settings");
  const row = page.locator(".row.modes-row", { hasText: "web-4" });
  await row.getByRole("button", { name: "Blocking" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("Start blocking on web-4?");
  await dialog.getByRole("button", { name: "Start blocking" }).click();
  await expect(row).toContainText("Switching to Blocking");
  await expect(row.getByRole("button", { name: "Blocking" })).toHaveAttribute("aria-pressed", "true", { timeout: 15000 });
});

test("allowlist edits merge, survive a poll, and refuse bad input", async ({ page, request }) => {
  await open(page, "#/settings");
  const beforeAll = await (await request.get("/api/agents")).json();
  const existing = beforeAll.agents.find((a) => a.node_id === "web-2").allowlist;
  expect(existing).toContain("192.0.2.0/24");
  await page.fill("#allow-ip", "not an address");
  await page.selectOption("#allow-target", "web-2");
  await page.getByRole("button", { name: "Add to allowlist" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "invalid IP" })).toBeVisible();
  await page.waitForTimeout(5600);
  await expect(page.locator("#allow-ip")).toHaveValue("not an address");
  await page.fill("#allow-ip", "198.18.0.0/24");
  await page.getByRole("button", { name: "Add to allowlist" }).click();
  await expect(page.locator("#toast")).toContainText("applies at next check-in");
  const added = (await (await request.get("/api/agents")).json()).agents.find((a) => a.node_id === "web-2").allowlist;
  expect(added).toEqual([...existing, "198.18.0.0/24"]);
  await page.getByRole("button", { name: "Remove 198.18.0.0/24 from web-2" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Remove" }).click();
  await expect(page.locator("#toast")).toContainText("Removal of 198.18.0.0/24");
  const removed = (await (await request.get("/api/agents")).json()).agents.find((a) => a.node_id === "web-2").allowlist;
  expect(removed).toEqual(existing);
});

test("add server shows the one-time command once", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: BASE });
  const problems = watchConsole(page);
  await open(page, "#/servers");
  await page.getByRole("button", { name: "Add server" }).click();
  let dialog = page.locator("dialog[open]");
  await expect(dialog.getByRole("textbox")).toBeFocused();
  await noAxeViolations(page);
  await dialog.getByRole("textbox").fill("<b>fresh</b>");
  await dialog.getByRole("button", { name: "Create install command" }).click();
  dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("Install the agent on <b>fresh</b>");
  const command = await dialog.locator(".cmd").textContent();
  if (PUBLIC_URL) {
    expect(command).toMatch(new RegExp(`^curl -fsSL ${PUBLIC_URL}/install-agent\\.sh \\| sudo NEXUS_ENROLL_TOKEN=[\\w-]+ bash$`));
    await expect(dialog).not.toContainText("PUBLIC_URL");
  } else {
    expect(command).toMatch(new RegExp(`^curl -fsSL ${BASE}/install-agent\\.sh \\| sudo NEXUS_ENROLL_TOKEN=[\\w-]+ bash -s -- --url ${BASE}$`));
    await expect(dialog).toContainText("Only agents on this machine can reach it");
  }
  await noAxeViolations(page);
  await page.screenshot({ path: `${OUT}/dialog-command-desktop.png` });
  await dialog.getByRole("button", { name: "Copy command" }).click();
  await expect(dialog.getByRole("button", { name: "Copied" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(command);
  await dialog.getByRole("button", { name: "Done" }).click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.locator("#dialog")).toBeEmpty();
  await expect(page.getByRole("button", { name: "Add server" })).toBeFocused();
  expect(problems).toEqual([]);
});

test("the server page shows charts, thresholds and capabilities read-only", async ({ page }) => {
  const problems = watchConsole(page);
  await open(page, `#/servers/${SERVER_WITH_BLOCKS}`);
  for (const title of ["CPU", "RAM", "Network", "Latency", "Anomaly score"]) {
    await expect(page.locator(".chart", { hasText: title }).locator("canvas")).toBeVisible();
    await expect(page.locator(".chart", { hasText: title })).toContainText("Peak");
  }
  const canvas = page.locator('[data-metric="cpu_pct"] canvas');
  const handle = await canvas.elementHandle();
  await page.waitForTimeout(5600);
  expect(await handle.evaluate((c) => c.isConnected)).toBe(true);
  await expect(page.locator(".kv", { hasText: "SSH failed logins before a block" })).toContainText("10");
  await expect(page.getByText("Can block with nftables")).toBeVisible();
  await page.selectOption("#range", "1440");
  await page.waitForTimeout(500);
  await expect(page.locator("#range")).toHaveValue("1440");
  await expect(page.locator("#view input")).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("revoke asks first and states what happens to kernel blocks", async ({ page, request }) => {
  await open(page, "#/servers/api-1");
  await page.getByRole("button", { name: "Revoke" }).click();
  const dialog = page.locator("dialog[open]");
  await expect(dialog).toContainText("stops being able to report");
  await expect(dialog).toContainText("Blocks already in the kernel expire on their own");
  await noAxeViolations(page);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  const after = (await (await request.get("/api/agents")).json()).agents.find((a) => a.node_id === "api-1");
  expect(after.status).not.toBe("revoked");
});

test("Content-Security-Policy is live and blocks injected script", async ({ page }) => {
  const response = await page.goto("/");
  const csp = response.headers()["content-security-policy"];
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("frame-ancestors 'none'");
  page.on("console", () => {});
  const ran = await page.evaluate(() => new Promise((resolve) => {
    window.__csp = false;
    const s = document.createElement("script");
    s.textContent = "window.__csp = true";
    document.head.append(s);
    setTimeout(() => resolve(window.__csp), 100);
  }));
  expect(ran).toBe(false);
});

if (IS_XSS) {
  const stripCsp = (page) => page.route("**/*", async (route) => {
    const response = await route.fetch();
    const headers = { ...response.headers() };
    delete headers["content-security-policy"];
    await route.fulfill({ response, headers });
  });

  for (const [name, hash] of PAGES) {
    test(`${name}: attacker text in evidence, ip and rule stays text, even with the CSP removed`, async ({ page }) => {
      await stripCsp(page);
      const problems = watchConsole(page);
      await open(page, hash);
      await page.waitForTimeout(800);
      expect(await page.evaluate(() => window.__xss)).toBeUndefined();
      expect(await page.locator("#view img, #view b:not(.server b):not(.facts b)").count()).toBe(0);
      expect(problems).toEqual([]);
    });
  }

  test("attacker text is shown literally where it lands", async ({ page }) => {
    for (const hash of ["#/blocks", "#/watch", "#/events", "#/"]) {
      await open(page, hash);
      await expect(page.locator("#view li, #view a").getByText("<img src=x onerror=__xss=1>").first()).toBeVisible();
      expect(await page.locator("#view img").count()).toBe(0);
    }
  });

  test("rule names that collide with object members show as raw codes", async ({ page }) => {
    await open(page, "#/events");
    await expect(page.locator(".row.events", { hasText: "203.0.113.91" })).toContainText("Blocked constructor");
    await expect(page.locator("#view")).not.toContainText("function Object");
    await expect(page.locator(".row.events", { hasText: "203.0.113.92" })).toContainText("__proto__");
  });

  test("a bad address on a block is refused with a message, not sent", async ({ page }) => {
    await open(page, "#/blocks");
    const row = page.locator(".row.blocks", { hasText: "<img src=x onerror=__xss=1>" }).filter({ hasText: "All ports" }).first();
    await row.getByRole("button", { name: /^Remove/ }).click();
    await expect(page.locator("#toast")).toContainText(/invalid IP/);
  });
} else {
  test("README screenshot", async ({ page }) => {
    await open(page, "#/");
    await page.waitForTimeout(300);
    await page.screenshot({ path: "/out/nexus_dashboard.png", fullPage: true });
  });
}
