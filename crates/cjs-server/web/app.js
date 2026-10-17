// ClawdJumpServer web console. Plain JavaScript, no dependencies.
// All server data is rendered with textContent (never innerHTML).
"use strict";

const state = { user: null, csrf: "", view: "", flash: null };

// ---------------------------------------------------------------- helpers

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 4000);
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") opts.headers["X-CSRF-Token"] = state.csrf;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch("/api/v1" + path, opts);
  const type = r.headers.get("content-type") || "";
  const data = type.includes("json") ? await r.json() : await r.text();
  if (!r.ok) {
    if (r.status === 401 && path !== "/login") showLogin();
    const e = (data && data.error) || { code: "error", message: String(r.status) };
    throw new Error(e.code + ": " + e.message);
  }
  return data;
}

function has(role) { return state.user && state.user.roles.includes(role); }
function ts(t) { return t ? new Date(t * (t > 1e12 ? 1 : 1000)).toLocaleString() : ""; }
function pill(text, kind) { return el("span", { class: "pill " + (kind || "") }, text); }
function status(s) { return pill(s, s === "active" || s === "approved" || s === "success" ? "ok" : s === "pending" ? "warn" : "bad"); }

function table(cols, rows, empty) {
  if (!rows.length) return el("p", { class: "muted" }, empty || "Nothing here.");
  return el("table", {},
    el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c[0])))),
    el("tbody", {}, rows.map((r) => el("tr", {}, cols.map((c) => {
      const v = c[1](r);
      return el("td", c[2] ? { class: c[2] } : {}, v);
    })))));
}

function btn(label, fn, cls) {
  return el("button", { type: "button", class: cls === undefined ? "secondary" : cls, onclick: async (ev) => {
    ev.target.disabled = true;
    try { await fn(); } catch (e) { toast(e.message); } finally { ev.target.disabled = false; }
  } }, label);
}

function card(title, ...body) { return el("section", { class: "card" }, el("h2", {}, title), ...body); }

function formValues(form) {
  const out = {};
  for (const [k, v] of new FormData(form).entries()) out[k] = v;
  return out;
}

function secretBox(title, obj) {
  return el("div", { class: "secret" },
    el("strong", {}, title), el("p", { class: "muted" }, "Shown once. Hand it over through a secure channel."),
    el("pre", { class: "json" }, JSON.stringify(obj, null, 2)));
}

// ----------------------------------------------------------------- views

const views = {
  overview: { label: "Overview", roles: null, render: overview },
  devices: { label: "Devices", roles: null, render: devices },
  agents: { label: "Agents", roles: null, render: agents },
  tokens: { label: "Enrollment", roles: null, render: tokens },
  users: { label: "Users", roles: ["sysadmin"], render: users },
  groups: { label: "Groups", roles: null, render: groups },
  grants: { label: "Grants", roles: ["secadmin", "auditor"], render: grants },
  full: { label: "Full access", roles: null, render: fullAccess },
  audit: { label: "Audit", roles: ["auditor"], render: audit },
  account: { label: "Account", roles: null, render: account },
};

async function overview(v) {
  v.append(card("Signed in", el("p", {}, `${state.user.display_name || state.user.name} — roles: ${state.user.roles.join(", ") || "none"}`)));
  if (has("secadmin") || has("auditor")) {
    const [conns, streams] = await Promise.all([api("GET", "/live/connections"), api("GET", "/live/streams")]);
    v.append(card("Connected clients", table([
      ["Role", (c) => c.role], ["Name", (c) => c.name], ["Host", (c) => `${c.hostname} (${c.os}/${c.arch})`],
      ["Transport", (c) => c.transport], ["From", (c) => c.peer || ""], ["Since", (c) => ts(c.since)],
      ["", (c) => has("secadmin") ? btn("Disconnect", async () => { await api("POST", `/live/connections/${c.id}/kick`); go("overview"); }, "danger") : "", "actions"],
    ], conns, "No clients connected.")));
    v.append(card("Open sessions", table([
      ["Session", (s) => s.session], ["Kind", (s) => s.kind], ["Agent", (s) => s.principal],
      ["Target", (s) => s.target], ["Started", (s) => ts(s.started)],
      ["", (s) => s.full_access ? pill("FULL ACCESS", "bad") : ""],
      ["", (s) => has("secadmin") ? btn("Terminate", async () => { await api("POST", `/live/sessions/${s.session}/kill`); go("overview"); }, "danger") : "", "actions"],
    ], streams, "No open sessions.")));
  }
}

async function devices(v) {
  const list = await api("GET", "/devices");
  v.append(card("Devices", table([
    ["Name", (d) => d.name], ["Id", (d) => el("code", {}, d.id)],
    ["State", (d) => [status(d.status), " ", d.online ? pill("online", "ok") : pill("offline")]],
    ["Host", (d) => d.info && d.info.hostname ? `${d.info.hostname} (${d.info.os}/${d.info.arch})` : ""],
    ["Groups", (d) => d.groups.join(", ")], ["Last seen", (d) => ts(d.last_seen)],
    ["", (d) => has("sysadmin") ? [
      btn(d.status === "active" ? "Disable" : "Enable", async () => { await api("PATCH", `/devices/${d.id}`, { status: d.status === "active" ? "disabled" : "active" }); go("devices"); }),
      btn("Delete", async () => { if (confirm(`Delete device ${d.name}?`)) { await api("DELETE", `/devices/${d.id}`); go("devices"); } }, "danger"),
    ] : "", "actions"],
  ], list, "No devices enrolled yet.")));
}

async function agents(v) {
  const list = await api("GET", "/agents");
  v.append(card(has("sysadmin") ? "Agents" : "My agents", table([
    ["Name", (a) => a.name], ["Id", (a) => el("code", {}, a.id)], ["Owner", (a) => a.owner_id],
    ["State", (a) => [status(a.status), " ", a.online ? pill("online", "ok") : ""]],
    ["Host", (a) => a.info && a.info.hostname ? a.info.hostname : ""], ["Last seen", (a) => ts(a.last_seen)],
    ["", (a) => [
      (has("sysadmin") || a.status === "active") ? btn(a.status === "active" ? "Disable" : "Enable", async () => { await api("PATCH", `/agents/${a.id}`, { status: a.status === "active" ? "disabled" : "active" }); go("agents"); }) : "",
      btn("Delete", async () => { if (confirm(`Delete agent ${a.name}?`)) { await api("DELETE", `/agents/${a.id}`); go("agents"); } }, "danger"),
    ], "actions"],
  ], list, "No agents.")));
}

async function tokens(v) {
  const out = el("div");
  const form = el("form", { class: "row", onsubmit: async (ev) => {
    ev.preventDefault();
    const f = formValues(form);
    try {
      const r = await api("POST", "/tokens", { kind: f.kind, name: f.name, owner: f.owner || undefined, ttl_secs: Number(f.ttl) });
      state.flash = secretBox("Enrollment token", { token: r.token, command: f.kind === "device"
        ? `cjs-device enroll --server ${location.origin} --token ${r.token}`
        : `cjs enroll --server ${location.origin} --token ${r.token}` });
      go("tokens", true);
    } catch (e) { toast(e.message); }
  } },
    el("label", {}, "Kind", el("select", { name: "kind" },
      el("option", { value: "agent" }, "agent"), has("sysadmin") ? el("option", { value: "device" }, "device") : null)),
    el("label", {}, "Name", el("input", { name: "name", required: true, pattern: "[A-Za-z0-9._-]{1,64}" })),
    has("sysadmin") ? el("label", {}, "Owner (agents)", el("input", { name: "owner", placeholder: "default: you" })) : null,
    el("label", {}, "Valid for (s)", el("input", { name: "ttl", type: "number", value: "86400", min: "60" })),
    el("button", { type: "submit" }, "Create token"));
  v.append(card("New enrollment token", form, out));
  const list = await api("GET", "/tokens");
  v.append(card("Tokens", table([
    ["Kind", (t) => t.kind], ["Name", (t) => t.name], ["Created", (t) => ts(t.created_at)],
    ["Expires", (t) => ts(t.expires_at)], ["Used", (t) => t.used_at ? `${ts(t.used_at)} by ${t.used_by}` : pill("unused", "warn")],
  ], list)));
}

async function users(v) {
  const out = el("div");
  const form = el("form", { class: "row", onsubmit: async (ev) => {
    ev.preventDefault();
    const f = formValues(form);
    const roles = ["sysadmin", "secadmin", "auditor"].filter((r) => form.elements["r_" + r].checked);
    try {
      const r = await api("POST", "/users", { name: f.name, display_name: f.display_name || undefined, roles });
      state.flash = secretBox("Initial credentials", { user: r.user.name, password: r.password, totp_secret: r.totp_secret, otpauth_url: r.otpauth_url });
      go("users", true);
    } catch (e) { toast(e.message); }
  } },
    el("label", {}, "User name", el("input", { name: "name", required: true })),
    el("label", {}, "Display name", el("input", { name: "display_name" })),
    ...["sysadmin", "secadmin", "auditor"].map((r) => el("label", {}, el("input", { type: "checkbox", name: "r_" + r }), r)),
    el("button", { type: "submit" }, "Create user"));
  v.append(card("New user", el("p", { class: "muted" }, "secadmin and auditor cannot be combined (separation of duties)."), form, out));
  const list = await api("GET", "/users");
  v.append(card("Users", table([
    ["Name", (u) => u.name], ["Roles", (u) => u.roles.join(", ")], ["State", (u) => [status(u.status), u.locked_until && u.locked_until * 1000 > Date.now() ? pill("locked", "bad") : ""]],
    ["Last login", (u) => u.last_login ? `${ts(u.last_login)} from ${u.last_ip || "?"}` : ""],
    ["", (u) => u.id === state.user.id ? el("span", { class: "muted" }, "you") : [
      btn(u.status === "active" ? "Disable" : "Enable", async () => { await api("PATCH", `/users/${u.id}`, { status: u.status === "active" ? "disabled" : "active" }); go("users"); }),
      btn("Roles…", async () => {
        const r = prompt("Roles (comma separated: sysadmin, secadmin, auditor)", u.roles.join(","));
        if (r === null) return;
        await api("PATCH", `/users/${u.id}`, { roles: r.split(",").map((x) => x.trim()).filter(Boolean) }); go("users");
      }),
      btn("Unlock", async () => { await api("POST", `/users/${u.id}/unlock`); toast("unlocked"); }),
      btn("Reset", async () => {
        if (!confirm(`Reset password and authenticator of ${u.name}?`)) return;
        const r = await api("POST", `/users/${u.id}/reset`);
        out.replaceChildren(secretBox("New credentials", { user: u.name, password: r.password, totp_secret: r.totp_secret, otpauth_url: r.otpauth_url }));
      }, "danger"),
    ], "actions"],
  ], list)));
}

async function groups(v) {
  if (has("sysadmin")) {
    const form = el("form", { class: "row", onsubmit: async (ev) => {
      ev.preventDefault();
      const f = formValues(form);
      try { await api("POST", "/groups", f); go("groups"); } catch (e) { toast(e.message); }
    } },
      el("label", {}, "Name", el("input", { name: "name", required: true })),
      el("label", {}, "Kind", el("select", { name: "kind" }, ["agent", "device", "user"].map((k) => el("option", { value: k }, k)))),
      el("label", {}, "Description", el("input", { name: "description" })),
      el("button", { type: "submit" }, "Create group"));
    v.append(card("New group", form));
  }
  const list = await api("GET", "/groups");
  v.append(card("Groups", table([
    ["Name", (g) => g.name], ["Kind", (g) => g.kind], ["Id", (g) => el("code", {}, g.id)],
    ["Members", (g) => g.members.join(", ")],
    ["", (g) => has("sysadmin") ? [
      btn("Add…", async () => { const m = prompt(`Add ${g.kind} (name or id) to ${g.name}`); if (m) { await api("PUT", `/groups/${g.id}/members/${encodeURIComponent(m)}`); go("groups"); } }),
      btn("Remove…", async () => { const m = prompt(`Remove member (id) from ${g.name}`); if (m) { await api("DELETE", `/groups/${g.id}/members/${encodeURIComponent(m)}`); go("groups"); } }),
      btn("Delete", async () => { if (confirm(`Delete group ${g.name}?`)) { await api("DELETE", `/groups/${g.id}`); go("groups"); } }, "danger"),
    ] : "", "actions"],
  ], list)));
}

const GRANT_TEMPLATE = {
  name: "build agents on build boxes",
  subject: { type: "principal", id: "AGENT-NAME-OR-ID" },
  target: { type: "device", id: "DEVICE-NAME-OR-ID" },
  actions: ["shell", "exec", "file_read", "file_write"],
  project_roots: ["/srv/projects/example"],
  schedule: null, not_before: null, expires_at: null,
  forward_targets: [], remote_ports: [], egress: [], max_sessions: 4, enabled: true,
};

async function grants(v) {
  if (has("secadmin")) {
    const id = el("input", { name: "id", required: true, pattern: "[A-Za-z0-9._-]{1,64}", placeholder: "grant id" });
    const body = el("textarea", { spellcheck: "false" });
    body.value = JSON.stringify(GRANT_TEMPLATE, null, 2);
    v.append(card("Create or replace a grant",
      el("p", { class: "muted" }, "Actions: shell, exec, file_read, file_write, forward_local, forward_remote, egress. Subject type: principal | group; target type: device | device_group | server."),
      el("label", {}, "Id", id), el("label", {}, "Grant (JSON)", body),
      btn("Save grant", async () => {
        const g = JSON.parse(body.value);
        await api("PUT", `/grants/${encodeURIComponent(id.value)}`, g);
        toast("grant saved"); go("grants");
      }, "")));
    v.edit = (g) => { id.value = g.id; const c = Object.assign({}, g); delete c.id; delete c.created_by; delete c.created_at; delete c.updated_at; body.value = JSON.stringify(c, null, 2); window.scrollTo(0, 0); };
  }
  const list = await api("GET", "/grants");
  v.append(card("Grants", table([
    ["Id", (g) => g.id], ["Subject", (g) => `${g.subject.type}:${g.subject.id}`], ["Target", (g) => g.target.type === "server" ? "server" : `${g.target.type}:${g.target.id}`],
    ["Actions", (g) => g.actions.join(", ")], ["Roots", (g) => g.project_roots.join(", ")],
    ["State", (g) => g.enabled ? pill("enabled", "ok") : pill("disabled", "bad")],
    ["Expires", (g) => ts(g.expires_at)],
    ["", (g) => has("secadmin") ? [
      btn("Edit", async () => v.edit(g)),
      btn("Delete", async () => { if (confirm(`Delete grant ${g.id}? Live sessions it covers are cut.`)) { await api("DELETE", `/grants/${g.id}`); go("grants"); } }, "danger"),
    ] : "", "actions"],
  ], list, "No grants: every request is denied.")));
}

async function fullAccess(v) {
  const form = el("form", { class: "row", onsubmit: async (ev) => {
    ev.preventDefault();
    const f = formValues(form);
    try { await api("POST", "/full-access", { agent: f.agent, device: f.device, reason: f.reason, duration_secs: Number(f.duration) * 60 }); go("full"); } catch (e) { toast(e.message); }
  } },
    el("label", {}, "Agent", el("input", { name: "agent", required: true })),
    el("label", {}, "Device", el("input", { name: "device", required: true })),
    el("label", {}, "Reason", el("input", { name: "reason", required: true, minlength: "5" })),
    el("label", {}, "Minutes (max 480)", el("input", { name: "duration", type: "number", value: "60", min: "1", max: "480" })),
    el("button", { type: "submit" }, "Request"));
  v.append(card("Request full access", el("p", { class: "muted" }, "Lifts the project-root jail and the sandbox. Needs approval by a different secadmin and always expires."), form));
  const list = await api("GET", "/full-access");
  v.append(card("Requests", table([
    ["Agent", (f) => f.principal], ["Device", (f) => f.device], ["Reason", (f) => f.reason],
    ["Requested by", (f) => f.requested_by], ["State", (f) => status(f.status)],
    ["Approved by", (f) => f.approved_by || ""], ["Expires", (f) => ts(f.expires_at)],
    ["", (f) => has("secadmin") ? [
      f.status === "pending" ? btn("Approve", async () => { await api("POST", `/full-access/${f.id}/approve`); go("full"); }, "") : "",
      f.status === "pending" ? btn("Reject", async () => { await api("POST", `/full-access/${f.id}/reject`); go("full"); }) : "",
      f.status === "approved" ? btn("Revoke", async () => { await api("POST", `/full-access/${f.id}/revoke`); go("full"); }, "danger") : "",
    ] : "", "actions"],
  ], list)));
}

function stripAnsi(s) {
  // CSI, OSC and other escape sequences, then remaining control chars (keep \n, \t).
  return s.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b[@-_]/g, "")
    .replace(/\r\n/g, "\n").replace(/\r/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

async function playRecording(session) {
  const r = await fetch(`/api/v1/recordings/${encodeURIComponent(session)}`, { credentials: "same-origin" });
  if (!r.ok) throw new Error("recording not available");
  const lines = (await r.text()).split("\n").filter(Boolean);
  const header = JSON.parse(lines[0]);
  const events = lines.slice(1).map((l) => JSON.parse(l));
  const term = el("pre", { class: "term" });
  const showInput = el("input", { type: "checkbox" });
  const render = (upto) => {
    let text = "";
    for (const [t, code, data] of events) {
      if (t > upto) break;
      if (code === "o") text += data;
      else if (code === "i" && showInput.checked) text += `␛[in:${JSON.stringify(data)}]`;
    }
    term.textContent = stripAnsi(text);
    term.scrollTop = term.scrollHeight;
  };
  const end = events.length ? events[events.length - 1][0] : 0;
  let timer = null;
  const play = () => {
    clearInterval(timer);
    const start = performance.now();
    timer = setInterval(() => {
      const t = (performance.now() - start) / 1000;
      render(t);
      if (t >= end) clearInterval(timer);
    }, 100);
  };
  const dlg = card(`Recording ${session}`,
    el("p", { class: "muted" }, `${header.title || ""} — ${header.width}x${header.height}, ${end.toFixed(1)}s`),
    el("div", { class: "row" }, btn("Play", async () => play(), ""), btn("Show all", async () => { clearInterval(timer); render(Infinity); }),
      el("label", {}, showInput, " show keystrokes")),
    term);
  render(Infinity);
  return dlg;
}

async function audit(v) {
  const result = el("div");
  const player = el("div");
  const verifyOut = el("div");
  const form = el("form", { class: "row", onsubmit: (ev) => { ev.preventDefault(); load(); } },
    el("label", {}, "Kind", el("input", { name: "kind", placeholder: "e.g. session.* or authz.decision" })),
    el("label", {}, "Actor", el("input", { name: "actor" })),
    el("label", {}, "Session", el("input", { name: "session" })),
    el("label", {}, "Outcome", el("select", { name: "outcome" }, ["", "success", "denied", "failure", "info"].map((o) => el("option", { value: o }, o || "any")))),
    el("label", {}, "Text", el("input", { name: "text" })),
    el("label", {}, el("input", { type: "checkbox", name: "highlight", value: "true" }), " highlighted only"),
    el("button", { type: "submit" }, "Search"));
  async function load() {
    const q = new URLSearchParams();
    for (const [k, val] of Object.entries(formValues(form))) if (val) q.set(k, val);
    q.set("limit", "300");
    try {
      const rows = await api("GET", "/audit?" + q.toString());
      result.replaceChildren(table([
        ["#", (r) => r.seq], ["Time", (r) => ts(r.ts)], ["Kind", (r) => r.highlight ? [pill("!", "bad"), " ", r.kind] : r.kind],
        ["Actor", (r) => r.actor], ["Target", (r) => r.target], ["Outcome", (r) => status(r.outcome)],
        ["From", (r) => r.ip || ""],
        ["Session", (r) => r.session ? el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); form.elements.session.value = r.session; load(); } }, r.session) : ""],
        ["Details", (r) => el("pre", { class: "json" }, JSON.stringify(r.data, null, 1))],
        ["", (r) => r.kind === "session.end" && r.data && r.data.recording ? btn("Play", async () => { player.replaceChildren(await playRecording(r.session)); window.scrollTo(0, 0); }, "") : "", "actions"],
      ], rows, "No matching events."));
    } catch (e) { toast(e.message); }
  }
  v.append(card("Integrity",
    el("div", { class: "row" },
      btn("Verify chain", async () => {
        const r = await api("GET", "/audit/verify");
        verifyOut.replaceChildren(r.ok ? pill(`OK — ${r.events} events, ${r.checkpoints} signed checkpoints, ${r.unsigned_tail} after the last checkpoint`, "ok") : pill(`FAILED: ${r.error}`, "bad"),
          el("p", { class: "muted" }, "head: ", el("code", {}, r.head)));
      }, ""),
      btn("Sign checkpoint", async () => { const r = await api("POST", "/audit/checkpoint"); toast(`checkpoint at #${r.seq}`); }),
      el("a", { href: "/api/v1/audit/export", download: "cjs-audit.jsonl" }, "Export (JSON lines)")),
    verifyOut));
  v.append(player);
  v.append(card("Events", form, result));
  load();
}

async function account(v) {
  const form = el("form", { onsubmit: async (ev) => {
    ev.preventDefault();
    const f = formValues(form);
    if (f.new !== f.again) { toast("passwords differ"); return; }
    try { await api("POST", "/me/password", { old: f.old, new: f.new, totp: f.totp }); form.reset(); toast("password changed"); } catch (e) { toast(e.message); }
  } },
    el("label", {}, "Current password", el("input", { name: "old", type: "password", required: true, autocomplete: "current-password" })),
    el("label", {}, "New password (12+ characters)", el("input", { name: "new", type: "password", required: true, minlength: "12", autocomplete: "new-password" })),
    el("label", {}, "Repeat", el("input", { name: "again", type: "password", required: true, autocomplete: "new-password" })),
    el("label", {}, "Authenticator code", el("input", { name: "totp", required: true, inputmode: "numeric" })),
    el("button", { type: "submit" }, "Change password"));
  v.append(el("section", { class: "card narrow" }, el("h2", {}, "Change password"), form));
  const info = await api("GET", "/info");
  v.append(card("Server", el("pre", { class: "json" }, JSON.stringify(info, null, 2))));
}

// ------------------------------------------------------------ navigation

function nav() {
  const n = document.getElementById("nav");
  n.replaceChildren(...Object.entries(views)
    .filter(([, d]) => !d.roles || d.roles.some(has))
    .map(([k, d]) => el("a", { href: "#" + k, class: state.view === k ? "active" : "" }, d.label)));
}

async function go(name, keepScroll) {
  const d = views[name] && (!views[name].roles || views[name].roles.some(has)) ? views[name] : views.overview;
  state.view = Object.keys(views).find((k) => views[k] === d);
  if (location.hash !== "#" + state.view) history.replaceState(null, "", "#" + state.view);
  nav();
  const v = el("section", { id: "view" });
  document.getElementById("view").replaceWith(v);
  // One-time secrets survive exactly one re-render.
  if (state.flash) {
    v.append(el("section", { class: "card" }, state.flash));
    state.flash = null;
  }
  try { await d.render(v); } catch (e) { v.append(card("Error", el("p", { class: "error" }, e.message))); }
  if (!keepScroll) window.scrollTo(0, 0);
}

function showLogin() {
  state.user = null;
  document.getElementById("top").hidden = true;
  document.getElementById("view").replaceChildren();
  document.getElementById("login").hidden = false;
}

function showApp() {
  document.getElementById("login").hidden = true;
  document.getElementById("top").hidden = false;
  document.getElementById("who").textContent = `${state.user.name} (${state.user.roles.join(", ") || "user"})`;
  go((location.hash || "#overview").slice(1));
}

document.getElementById("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = document.getElementById("login-error");
  err.textContent = "";
  const f = formValues(ev.target);
  try {
    const r = await api("POST", "/login", f);
    state.user = r.user;
    state.csrf = r.csrf;
    ev.target.reset();
    showApp();
  } catch (e) { err.textContent = e.message; }
});

document.getElementById("logout").addEventListener("click", async () => {
  try { await api("POST", "/logout"); } catch (e) { /* session may already be gone */ }
  showLogin();
});

window.addEventListener("hashchange", () => { if (state.user) go(location.hash.slice(1)); });

(async () => {
  try {
    const r = await api("GET", "/me");
    state.user = r.user;
    state.csrf = r.csrf;
    showApp();
  } catch (e) { showLogin(); }
})();
