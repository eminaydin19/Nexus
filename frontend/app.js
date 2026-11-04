import { api } from "./js/api.js";
import blocks from "./js/blocks.js";
import events from "./js/events.js";
import overview from "./js/overview.js";
import { serverDetail, serverList } from "./js/servers.js";
import settings from "./js/settings.js";
import { btn, clock, h, swapView } from "./js/ui.js";
import watch from "./js/watch.js";
import { serverName } from "./js/wording.js";

const POLL_MS = 5000;
const ROUTES = [
  [/^#?\/?$/, overview],
  [/^#\/servers$/, serverList],
  [/^#\/servers\/([^/]+)$/, serverDetail],
  [/^#\/blocks$/, blocks],
  [/^#\/watch$/, watch],
  [/^#\/events$/, events],
  [/^#\/settings$/, settings],
];
const NOT_FOUND = { title: "Not found", nav: null };

const view = document.getElementById("view");
const main = document.getElementById("main");
const stale = document.getElementById("stale");

let current = { page: overview, params: {} };
let hasData = false;
let seq = 0;
let timer;
let clockOffset = 0;

const ctx = {
  overview: null,
  now: () => Date.now() / 1000 + clockOffset,
  name(nodeId) {
    const server = ctx.overview?.servers.find((s) => s.node_id === nodeId);
    return server ? serverName(server) : nodeId;
  },
  refresh: () => refresh(),
};

function resolve() {
  for (const [pattern, page] of ROUTES) {
    const match = pattern.exec(location.hash);
    if (!match) continue;
    try {
      return { page, params: match[1] ? { id: decodeURIComponent(match[1]) } : {} };
    } catch {
      break;
    }
  }
  return { page: NOT_FOUND, params: {} };
}

function setMessage(...children) {
  view.replaceChildren(h("div", "message", ...children));
}

function showError(err) {
  const notFound = err.status === 404;
  setMessage(
    h("h1", "", notFound ? "Not found" : "This page could not load"),
    h("p", "lede", err.message),
    notFound ? null : btn("Try again", { onClick: refresh }),
  );
}

function setCounts() {
  const { active, watch_items: watching } = ctx.overview;
  document.getElementById("nBlocks").textContent = active.blocked + active.slowed || "";
  document.getElementById("nWatch").textContent = watching || "";
}

/* Redrawing under an operator's text selection would wipe what they are copying. */
function selectingInPage() {
  const selection = getSelection();
  return selection && !selection.isCollapsed && main.contains(selection.anchorNode);
}

async function refresh() {
  clearTimeout(timer);
  const token = ++seq;
  const { page, params } = current;
  try {
    const summary = await api.overview();
    const data = await page.load(params, { ...ctx, overview: summary });
    if (token !== seq) return;
    ctx.overview = summary;
    clockOffset = summary.server_time - Date.now() / 1000;
    setCounts();
    stale.hidden = true;
    if (!hasData || !selectingInPage()) {
      swapView(view, page.render(data, params, ctx));
      page.after?.(view, data, params);
    }
    hasData = true;
  } catch (err) {
    if (token !== seq) return;
    if (hasData) {
      stale.textContent = `Could not refresh at ${clock(Date.now() / 1000)}. Showing the last data. ${err.message}`;
      stale.hidden = false;
    } else {
      showError(err);
    }
  }
  if (token === seq && !document.hidden) timer = setTimeout(refresh, POLL_MS);
}

function navigate(moveFocus) {
  current.page.leave?.();
  current = resolve();
  hasData = false;
  stale.hidden = true;
  document.title = current.page === overview ? "Nexus" : `${current.page.title} · Nexus`;
  for (const link of document.querySelectorAll("[data-nav]")) {
    if (link.dataset.nav === current.page.nav) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (current.page === NOT_FOUND) {
    clearTimeout(timer);
    seq++;
    setMessage(h("h1", "", "Not found"), h("p", "lede", "This page does not exist in the panel."));
  } else {
    const loading = h("p", "lede", "Loading…");
    loading.setAttribute("role", "status");
    setMessage(loading);
    refresh();
  }
  if (moveFocus) {
    main.focus({ preventScroll: true });
    scrollTo(0, 0);
  }
}

addEventListener("hashchange", () => navigate(true));
document.addEventListener("visibilitychange", () => {
  if (document.hidden) clearTimeout(timer);
  else if (current.page !== NOT_FOUND) refresh();
});
document.getElementById("skip").addEventListener("click", (e) => {
  e.preventDefault();
  main.focus();
});

navigate(false);
