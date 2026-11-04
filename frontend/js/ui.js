export function h(tag, cls, ...children) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  el.append(...children.filter((c) => c != null && c !== false));
  return el;
}

export const pill = ({ cls, text }) => h("span", `pill ${cls}`, text);

export function btn(text, { ghost = false, danger = false, key, onClick, disabled = false, label } = {}) {
  const b = h("button", ghost ? "ghost" : danger ? "danger" : "", text);
  b.type = "button";
  b.disabled = disabled;
  if (key) b.dataset.key = key;
  if (label) b.setAttribute("aria-label", label);
  if (onClick) {
    // A busy flag, not b.disabled: disabling the focused button would drop keyboard focus to the top of the page.
    let busy = false;
    b.addEventListener("click", async () => {
      if (busy) return;
      busy = true;
      try {
        await onClick();
      } catch (err) {
        toast(err.message);
      } finally {
        busy = false;
      }
    });
  }
  return b;
}

export function linkButton(text, href, { ghost = false, label } = {}) {
  const a = h("a", ghost ? "button ghost" : "button", text);
  a.href = href;
  if (label) a.setAttribute("aria-label", label);
  return a;
}

export function section(title, sub, ...body) {
  const header = h("header", "", h("h2", "", title), sub ? h("span", "sub", sub) : null);
  return h("section", "section", header, ...body);
}

export const list = (rows, emptyText) => h("ul", "list", ...(rows.length ? rows : [h("li", "empty", emptyText)]));

export const facts = (pairs) =>
  h("ul", "facts", ...pairs.map(([value, text]) => h("li", "", h("b", "", String(value)), " ", h("span", "", text))));

export function keyValues(pairs) {
  return h("dl", "kv list", ...pairs.map(([k, v]) => h("div", "", h("dt", "", k), h("dd", "", v))));
}

let toastTimer;
export function toast(message) {
  const t = document.getElementById("toast");
  t.textContent = message;
  t.classList.add("on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("on"), 6000);
}

const main = () => document.getElementById("main");

function focusedKey() {
  return document.activeElement?.closest?.("[data-key]")?.dataset.key ?? null;
}

function restoreFocus(key) {
  const target = key && [...document.querySelectorAll("[data-key]")].find((el) => el.dataset.key === key);
  (target || main()).focus({ preventScroll: true });
}

/*
 * Polling redraws the page every few seconds. Nodes marked data-keep (top-level only) stay in place untouched, so an
 * open select, half-typed form or chart survives. Everything else is replaced, and focus follows data-key so a keyboard
 * user is not thrown to the top, and never lands on a different row's button.
 */
export function swapView(view, next) {
  const key = view.contains(document.activeElement) ? focusedKey() : null;
  const kept = new Map([...view.children].filter((c) => c.dataset.keep).map((c) => [c.dataset.keep, c]));
  const wanted = new Set(next.map((n) => n.dataset?.keep).filter(Boolean));
  for (const child of [...view.children]) {
    if (!wanted.has(child.dataset.keep)) child.remove();
  }
  let cursor = view.firstChild;
  for (const node of next) {
    const el = kept.get(node.dataset?.keep) ?? node;
    if (el === cursor) cursor = cursor.nextSibling;
    else view.insertBefore(el, cursor);
  }
  if (key && !view.contains(document.activeElement)) restoreFocus(key);
}

/* Resolves with the value of the button that closed it, or "" for Escape. */
export function showDialog(form) {
  const dialog = document.getElementById("dialog");
  const opener = focusedKey();
  dialog.replaceChildren(form);
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener(
      "close",
      () => {
        const value = dialog.returnValue;
        dialog.replaceChildren();
        restoreFocus(opener);
        resolve(value);
      },
      { once: true },
    );
  });
}

export function dialogForm(title, ...body) {
  const heading = h("h2", "", title);
  heading.id = "dialog-title";
  const form = h("form", "", heading, ...body);
  form.method = "dialog";
  return form;
}

export function dialogButton(text, value, { ghost = false, danger = false, autofocus = false } = {}) {
  const b = h("button", ghost ? "ghost" : danger ? "danger" : "", text);
  b.value = value;
  b.autofocus = autofocus;
  return b;
}

export async function confirmDialog({ title, body, yes, no = "Cancel", danger = false }) {
  const form = dialogForm(
    title,
    ...body,
    h("div", "acts", dialogButton(no, "no", { ghost: true, autofocus: true }), dialogButton(yes, "yes", { danger })),
  );
  return (await showDialog(form)) === "yes";
}

const pad = (n) => String(n).padStart(2, "0");

export function clock(ts, now = Date.now() / 1000) {
  const d = new Date(ts * 1000);
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (new Date(now * 1000).toDateString() === d.toDateString()) return time;
  return `${d.toLocaleDateString("en-GB", { day: "numeric", month: "short" })}, ${time}`;
}

export function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const hours = Math.floor(m / 60);
  if (hours < 48) return m % 60 ? `${hours} h ${m % 60} min` : `${hours} h`;
  return `${Math.floor(hours / 24)} days`;
}

export const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
