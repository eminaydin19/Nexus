export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function explain(status, detail) {
  if (status === 401) return "Your sign-in has expired. Reload the page to sign in again.";
  if (status === 403) return "The server refused this request because of its origin. Open the panel at its own address.";
  if (status === 429) return "Too many requests. Wait a minute and try again.";
  if (typeof detail === "string" && status < 500) return detail;
  return `The server had a problem (status ${status}). Try again.`;
}

const REQUEST_TIMEOUT_MS = 20000;

async function request(path, options = {}) {
  let res;
  try {
    // A hung request would otherwise keep the page's action guard held until reload.
    res = await fetch(path, { ...options, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch {
    throw new ApiError(0, "Could not reach the Nexus server. Check your connection and try again.");
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, explain(res.status, body?.detail));
  return body;
}

const send = (method, path, body) =>
  request(path, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

const agent = (id) => encodeURIComponent(id);

function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    for (const item of [v].flat()) if (item !== undefined && item !== "") q.append(k, item);
  }
  return q.toString();
}

export const api = {
  overview: () => request("/api/overview"),
  agents: () => request("/api/agents"),
  blocks: () => request("/api/blocks?simulated=false"),
  watchAll: () => request("/api/watch"),
  watchOne: (id) => request(`/api/watch/${agent(id)}`),
  events: (params) => request(`/api/events?${query(params)}`),
  anomalies: (params) => request(`/api/anomalies?${query(params)}`),
  metrics: (id, minutes) => request(`/api/metrics/${agent(id)}?${query({ minutes, points: 300 })}`),
  health: () => request("/api/health"),
  createToken: (name) => send("POST", "/api/agents/tokens", { name }),
  revoke: (id) => send("DELETE", `/api/agents/${agent(id)}`),
  unblock: (id, ip) => send("POST", `/api/agents/${agent(id)}/unblock`, { ip }),
  setAllowlist: (id, entries) => send("PUT", `/api/agents/${agent(id)}/allowlist`, entries),
  setMode: (id, mode) => send("PUT", `/api/agents/${agent(id)}/mode`, { mode }),
  markCustomer: (ip) => send("POST", "/api/customers", { ip }),
  removeCustomer: (entry) => send("POST", "/api/customers/remove", { entry }),
};
