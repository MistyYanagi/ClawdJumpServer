// ClawdJumpServer web console. Plain JavaScript, no dependencies.
// All server data is rendered with textContent (never innerHTML).
"use strict";

// gen: bumped on every navigation so pollers of the previous view stop.
const state = { user: null, csrf: "", view: "", flash: null, gen: 0, aborts: [], focus: null, watch: null, chain: null };

// ---------------------------------------------------------------- helpers

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

// kind: "ok" | "error" | undefined (neutral).
function toast(msg, kind) {
  const box = document.getElementById("toasts");
  const t = el("div", { class: "toast " + (kind || "") }, el("span", {}, msg));
  box.append(t);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(() => { t.classList.add("hide"); setTimeout(() => t.remove(), 250); }, kind === "error" ? 6000 : 3500);
}

async function api(method, path, body, signal) {
  const opts = { method, credentials: "same-origin", headers: {}, signal };
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
function mono(s) { return el("code", {}, s); }

// key(row) sets data-key on each row so the palette can focus it.
function table(cols, rows, empty, key) {
  if (!rows.length) return el("p", { class: "muted" }, empty || "Nothing here.");
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c[0])))),
    el("tbody", {}, rows.map((r) => el("tr", key ? { "data-key": key(r) } : {}, cols.map((c) => {
      const v = c[1](r);
      return el("td", c[2] ? { class: c[2] } : {}, v);
    }))))));
}

function btn(label, fn, cls) {
  return el("button", { type: "button", class: cls === undefined ? "secondary" : cls, onclick: async (ev) => {
    const b = ev.currentTarget;
    b.disabled = true;
    try { await fn(); } catch (e) { toast(e.message, "error"); } finally { b.disabled = false; }
  } }, label);
}

function card(title, ...body) { return el("section", { class: "card" }, el("h2", {}, title), ...body); }
function cardHead(title, ...extra) { return el("div", { class: "card-head" }, el("h2", {}, title), ...extra); }
function skeleton() { return el("div", { class: "card skeleton", "aria-busy": "true", "aria-label": "Loading" }, el("div"), el("div"), el("div"), el("div")); }

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

// A modal dialog. Resolves true when confirmed, false on cancel / Esc.
function modal(title, body, confirmLabel, confirmClass) {
  return new Promise((resolve) => {
    const prev = document.activeElement;
    const done = (v) => { ov.remove(); document.removeEventListener("keydown", onKey, true); if (prev) prev.focus(); resolve(v); };
    const ok = el("button", { type: "button", class: confirmClass || "", onclick: () => done(true) }, confirmLabel || "Confirm");
    const cancel = el("button", { type: "button", class: "secondary", onclick: () => done(false) }, "Cancel");
    const titleId = "dlg-title-" + Date.now();
    const ov = el("div", { class: "overlay", onclick: (ev) => { if (ev.target === ov) done(false); } },
      el("div", { class: "dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
        el("div", { class: "dialog-body" }, el("h2", { id: titleId }, title), body),
        el("div", { class: "dialog-foot" }, cancel, ok)));
    const onKey = (ev) => {
      if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); done(false); }
      else if (ev.key === "Tab") { // keep focus inside the dialog
        const f = [...ov.querySelectorAll("button, input, select, textarea, [tabindex]")];
        const i = f.indexOf(document.activeElement);
        if (ev.shiftKey && i <= 0) { ev.preventDefault(); f[f.length - 1].focus(); }
        else if (!ev.shiftKey && i === f.length - 1) { ev.preventDefault(); f[0].focus(); }
      }
    };
    document.addEventListener("keydown", onKey, true);
    document.body.append(ov);
    ok.focus();
  });
}

// ------------------------------------------------------------------ theme

const THEME_KEY = "cjs-theme";
const THEMES = { system: "System", light: "Light", dark: "Dark" };

function getTheme() {
  try { const t = localStorage.getItem(THEME_KEY); return THEMES[t] ? t : "system"; } catch (e) { return "system"; }
}

function applyTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  else document.documentElement.removeAttribute("data-theme");
  const b = document.getElementById("theme");
  if (b) {
    b.textContent = "Theme: " + THEMES[t];
    b.setAttribute("aria-label", `Theme: ${t}. Change theme`);
    b.title = "Theme (system → light → dark)";
  }
  document.querySelectorAll("[data-theme-choice]").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.themeChoice === t)));
}

function setTheme(t) {
  try { if (t === "system") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, t); } catch (e) { /* storage blocked */ }
  applyTheme(t);
}

function cycleTheme() {
  const order = Object.keys(THEMES);
  setTheme(order[(order.indexOf(getTheme()) + 1) % order.length]);
}

function themeChooser() {
  return el("div", { class: "seg", role: "group", "aria-label": "Theme" }, Object.entries(THEMES).map(([k, label]) =>
    el("button", { type: "button", "data-theme-choice": k, "aria-pressed": String(getTheme() === k), onclick: () => setTheme(k) }, label)));
}

applyTheme(getTheme());

// ----------------------------------------------------------------- views

const views = {
  overview: { label: "Overview", roles: null, render: overview },
  sessions: { label: "Sessions", roles: ["secadmin", "auditor"], render: sessions },
  devices: { label: "Devices", roles: null, render: devices },
  agents: { label: "Agents", roles: null, render: agents },
  tokens: { label: "Enrollment", roles: null, render: tokens },
  users: { label: "Users", roles: ["sysadmin"], render: users },
  groups: { label: "Groups", roles: null, render: groups },
  grants: { label: "Access", roles: ["secadmin", "auditor"], render: grants },
  full: { label: "Approvals", roles: null, render: fullAccess },
  audit: { label: "Audit", roles: ["auditor"], render: audit },
  settings: { label: "Settings", roles: null, render: settings },
};
// Old links.
const aliases = { account: "settings" };

function sessionCols(after) {
  return [
    ["Session", (s) => mono(s.session)], ["Kind", (s) => s.kind], ["Agent", (s) => s.principal],
    ["Target", (s) => s.target], ["Started", (s) => ts(s.started)],
    ["", (s) => s.full_access ? pill("FULL ACCESS", "bad solid") : ""],
    ["", (s) => [
      s.kind === "pty" ? btn("Watch", async () => after(s), "") : "",
      has("secadmin") ? btn("Terminate", async () => {
        if (!(await modal("Terminate session?", el("p", {}, "The session ", mono(s.session), " is cut immediately. This is audited."), "Terminate", "danger"))) return;
        await api("POST", `/live/sessions/${s.session}/kill`);
        toast("session terminated", "ok");
        go(state.view, true);
      }, "danger") : "",
    ], "actions"],
  ];
}

async function overview(v) {
  v.append(el("div", { class: "page-title" }, el("h1", {}, "Overview"),
    el("span", { class: "muted" }, `${state.user.display_name || state.user.name} — ${state.user.roles.join(", ") || "no admin roles"}`)));
  const [devs, ags] = await Promise.all([api("GET", "/devices"), api("GET", "/agents")]);
  const stat = (label, n, sub, view) => el("a", { class: "card stat", href: "#" + view },
    el("div", { class: "muted small" }, label), el("div", { class: "big" }, String(n)), el("div", { class: "muted small" }, sub));
  const tiles = el("div", { class: "grid stats" },
    stat("Devices", devs.length, `${devs.filter((d) => d.online).length} online`, "devices"),
    stat("Agents", ags.length, `${ags.filter((a) => a.online).length} online`, "agents"));
  v.append(tiles);
  if (has("secadmin") || has("auditor")) {
    const [conns, streams] = await Promise.all([api("GET", "/live/connections"), api("GET", "/live/streams")]);
    tiles.append(stat("Open sessions", streams.length, `${streams.filter((s) => s.full_access).length} with full access`, "sessions"));
    v.append(card("Connected clients", table([
      ["Role", (c) => c.role], ["Name", (c) => c.name], ["Host", (c) => `${c.hostname} (${c.os}/${c.arch})`],
      ["Transport", (c) => c.transport], ["From", (c) => c.peer ? mono(c.peer) : ""], ["Since", (c) => ts(c.since)],
      ["", (c) => has("secadmin") ? btn("Disconnect", async () => { await api("POST", `/live/connections/${c.id}/kick`); toast("disconnected", "ok"); go("overview"); }, "danger") : "", "actions"],
    ], conns, "No clients connected.")));
    v.append(card("Open sessions", table(sessionCols((s) => { state.watch = s.session; go("sessions"); }), streams, "No open sessions.")));
  }
}

// ---------------------------------------------------------- live sessions

function stripAnsi(s) {
  // CSI, OSC and other escape sequences, then remaining control chars (keep \n, \t).
  return s.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b[@-_]/g, "")
    .replace(/\r\n/g, "\n").replace(/\r/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

// Keep the terminal pinned to the bottom unless the reader scrolled up.
function setTerm(term, text) {
  const pinned = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
  term.textContent = stripAnsi(text);
  if (pinned) term.scrollTop = term.scrollHeight;
}

const LIVE_KEEP = 400000; // characters of output kept in the live view

// Read-only live view of a terminal session (long-polls the recording).
function watchSession(session, player) {
  const gen = state.gen;
  const term = el("pre", { class: "term", tabindex: "0", "aria-label": `Live output of ${session}` });
  const badge = el("span", {}, pill("connecting", "warn"));
  const meta = el("p", { class: "muted" }, "Read-only. Keystrokes are not shown; this view is audited as session.watch.");
  let stopped = false;
  let ctl = null;
  const stop = () => { stopped = true; if (ctl) ctl.abort(); };
  player.replaceChildren(el("section", { class: "card", id: "player" },
    cardHead(["Watching ", mono(session)], badge,
      btn("Stop", async () => { stop(); player.replaceChildren(); }),
      has("secadmin") ? btn("Terminate", async () => {
        if (!(await modal("Terminate session?", el("p", {}, "The session ", mono(session), " is cut immediately. This is audited."), "Terminate", "danger"))) return;
        await api("POST", `/live/sessions/${session}/kill`);
        toast("session terminated", "ok");
      }, "danger") : ""),
    meta, term));
  player.scrollIntoView({ block: "start" });
  (async () => {
    let text = "";
    let offset = 0;
    while (!stopped && state.gen === gen) {
      ctl = new AbortController();
      state.aborts.push(ctl);
      let r;
      try {
        r = await api("GET", `/sessions/${encodeURIComponent(session)}/live?after=${offset}&wait=20`, undefined, ctl.signal);
      } catch (e) {
        if (e.name === "AbortError" || stopped || state.gen !== gen) return;
        badge.replaceChildren(pill("error", "bad"));
        toast(e.message, "error");
        return;
      } finally {
        state.aborts = state.aborts.filter((c) => c !== ctl);
      }
      if (r.header && r.header.version) meta.textContent = `${r.header.title || ""} — ${r.header.width}x${r.header.height}. Read-only; keystrokes are not shown; audited as session.watch.`;
      for (const [, code, data] of r.events) {
        if (code === "o") text += data;
      }
      if (text.length > LIVE_KEEP) text = text.slice(text.length - LIVE_KEEP);
      setTerm(term, text);
      badge.replaceChildren(r.live ? pill("live", "ok live") : pill("ended", ""));
      if (!r.live && r.offset === offset) return;
      offset = r.offset;
    }
  })();
}

async function sessions(v) {
  const list = el("div");
  const player = el("div");
  const updated = el("span", { class: "muted small" });
  v.append(el("div", { class: "page-title" }, el("h1", {}, "Sessions"), el("span", { class: "muted" }, "Open sessions, refreshed every 5 s")));
  v.append(el("section", { class: "card" }, cardHead("Open sessions", updated), list), player);
  const gen = state.gen;
  const refresh = async () => {
    const streams = await api("GET", "/live/streams");
    list.replaceChildren(table(sessionCols((s) => watchSession(s.session, player)), streams, "No open sessions.", (s) => s.session));
    updated.textContent = "updated " + new Date().toLocaleTimeString();
  };
  await refresh();
  const t = setInterval(() => {
    if (state.gen !== gen) { clearInterval(t); return; }
    refresh().catch(() => {});
  }, 5000);
  if (state.watch) { const s = state.watch; state.watch = null; watchSession(s, player); }
}

// --------------------------------------------------------------- inventory

async function devices(v) {
  const list = await api("GET", "/devices");
  v.append(card("Devices", table([
    ["Name", (d) => d.name], ["Id", (d) => mono(d.id)],
    ["State", (d) => [status(d.status), " ", d.online ? pill("online", "ok") : pill("offline")]],
    ["Host", (d) => d.info && d.info.hostname ? `${d.info.hostname} (${d.info.os}/${d.info.arch})` : ""],
    ["Groups", (d) => d.groups.join(", ")], ["Last seen", (d) => ts(d.last_seen)],
    ["", (d) => has("sysadmin") ? [
      btn(d.status === "active" ? "Disable" : "Enable", async () => { await api("PATCH", `/devices/${d.id}`, { status: d.status === "active" ? "disabled" : "active" }); go("devices"); }),
      btn("Delete", async () => { if (await modal(`Delete device ${d.name}?`, el("p", {}, "Its enrollment is removed; it must enroll again."), "Delete", "danger")) { await api("DELETE", `/devices/${d.id}`); go("devices"); } }, "danger"),
    ] : "", "actions"],
  ], list, "No devices enrolled yet.", (d) => d.id)));
}

async function agents(v) {
  const list = await api("GET", "/agents");
  v.append(card(has("sysadmin") ? "Agents" : "My agents", table([
    ["Name", (a) => a.name], ["Id", (a) => mono(a.id)], ["Owner", (a) => mono(a.owner_id)],
    ["State", (a) => [status(a.status), " ", a.online ? pill("online", "ok") : ""]],
    ["Host", (a) => a.info && a.info.hostname ? a.info.hostname : ""], ["Last seen", (a) => ts(a.last_seen)],
    ["", (a) => [
      (has("sysadmin") || a.status === "active") ? btn(a.status === "active" ? "Disable" : "Enable", async () => { await api("PATCH", `/agents/${a.id}`, { status: a.status === "active" ? "disabled" : "active" }); go("agents"); }) : "",
      (has("sysadmin") || a.status === "active") && btn("Delete", async () => { if (await modal(`Delete agent ${a.name}?`, el("p", {}, "Its key is revoked; it must enroll again."), "Delete", "danger")) { await api("DELETE", `/agents/${a.id}`); go("agents"); } }, "danger"),
    ], "actions"],
  ], list, "No agents.", (a) => a.id)));
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
    } catch (e) { toast(e.message, "error"); }
  } },
    el("label", {}, "Kind", el("select", { name: "kind" },
      el("option", { value: "agent" }, "agent"), has("sysadmin") ? el("option", { value: "device" }, "device") : null)),
    el("label", {}, "Name", el("input", { name: "name", required: true, pattern: "[A-Za-z0-9._\\-]{1,64}" })),
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
      state.flash = secretBox("Initial credentials", { user: r.user.name, password: r.password, totp_secret: r.totp_secret, otpauth_url: r.otpauth_url,
        pending_roles: r.pending_role_change ? r.pending_role_change.roles.join(", ") + " (waits for approval by another secadmin)" : undefined });
      go("users", true);
    } catch (e) { toast(e.message, "error"); }
  } },
    el("label", {}, "User name", el("input", { name: "name", required: true })),
    el("label", {}, "Display name", el("input", { name: "display_name" })),
    ...["sysadmin", "secadmin", "auditor"].map((r) => el("label", {}, el("input", { type: "checkbox", name: "r_" + r }), r)),
    el("button", { type: "submit" }, "Create user"));
  v.append(card("New user", el("p", { class: "muted" }, "secadmin and auditor cannot be combined (separation of duties). Roles take effect only after another secadmin approves them (Approvals)."), form, out));
  const list = await api("GET", "/users");
  v.append(card("Users", table([
    ["Name", (u) => u.name], ["Roles", (u) => u.roles.join(", ")], ["State", (u) => [status(u.status), u.locked_until && u.locked_until * 1000 > Date.now() ? pill("locked", "bad") : ""]],
    ["Last login", (u) => u.last_login ? `${ts(u.last_login)} from ${u.last_ip || "?"}` : ""],
    ["", (u) => u.id === state.user.id ? el("span", { class: "muted" }, "you") : [
      btn(u.status === "active" ? "Disable" : "Enable", async () => { await api("PATCH", `/users/${u.id}`, { status: u.status === "active" ? "disabled" : "active" }); go("users"); }),
      btn("Roles…", async () => {
        const r = prompt("Roles (comma separated: sysadmin, secadmin, auditor)", u.roles.join(","));
        if (r === null) return;
        const res = await api("PATCH", `/users/${u.id}`, { roles: r.split(",").map((x) => x.trim()).filter(Boolean) });
        if (res.pending_role_change) toast("role change requested: needs approval by another secadmin");
        go("users");
      }),
      btn("Unlock", async () => { await api("POST", `/users/${u.id}/unlock`); toast("unlocked", "ok"); }),
      u.roles.length ? "" : btn("Reset", async () => {
        if (!(await modal(`Reset ${u.name}?`, el("p", {}, "Their password and authenticator are replaced."), "Reset", "danger"))) return;
        const r = await api("POST", `/users/${u.id}/reset`);
        out.replaceChildren(secretBox("New credentials", { user: u.name, password: r.password, totp_secret: r.totp_secret, otpauth_url: r.otpauth_url }));
      }, "danger"),
    ], "actions"],
  ], list, null, (u) => u.id)));
  v.append(out);
}

async function groups(v) {
  if (has("sysadmin")) {
    const form = el("form", { class: "row", onsubmit: async (ev) => {
      ev.preventDefault();
      const f = formValues(form);
      try { await api("POST", "/groups", f); go("groups"); } catch (e) { toast(e.message, "error"); }
    } },
      el("label", {}, "Name", el("input", { name: "name", required: true })),
      el("label", {}, "Kind", el("select", { name: "kind" }, ["agent", "device", "user"].map((k) => el("option", { value: k }, k)))),
      el("label", {}, "Description", el("input", { name: "description" })),
      el("button", { type: "submit" }, "Create group"));
    v.append(card("New group", form));
  }
  const list = await api("GET", "/groups");
  v.append(card("Groups", table([
    ["Name", (g) => g.name], ["Kind", (g) => g.kind], ["Id", (g) => mono(g.id)],
    ["Members", (g) => g.members.join(", ")],
    ["", (g) => has("sysadmin") ? [
      btn("Add…", async () => { const m = prompt(`Add ${g.kind} (name or id) to ${g.name}`); if (m) { await api("PUT", `/groups/${g.id}/members/${encodeURIComponent(m)}`); go("groups"); } }),
      btn("Remove…", async () => { const m = prompt(`Remove member (id) from ${g.name}`); if (m) { await api("DELETE", `/groups/${g.id}/members/${encodeURIComponent(m)}`); go("groups"); } }),
      btn("Delete", async () => { if (await modal(`Delete group ${g.name}?`, el("p", {}, "Grants naming this group stop matching."), "Delete", "danger")) { await api("DELETE", `/groups/${g.id}`); go("groups"); } }, "danger"),
    ] : "", "actions"],
  ], list, null, (g) => g.id)));
}

// ------------------------------------------------------------------ access

const GRANT_TEMPLATE = {
  name: "build agents on build boxes",
  subject: { type: "principal", id: "AGENT-NAME-OR-ID" },
  target: { type: "device", id: "DEVICE-NAME-OR-ID" },
  actions: ["shell", "exec", "file_read", "file_write"],
  project_roots: ["/srv/projects/example"],
  schedule: null, not_before: null, expires_at: null,
  forward_targets: [], remote_ports: [], egress: [], max_sessions: 4, enabled: true,
};
const GRANT_META = ["id", "created_by", "created_at", "updated_at"];

function grantFields(g) {
  const c = Object.assign({}, g);
  for (const k of GRANT_META) delete c[k];
  return c;
}

// Field-by-field comparison of two grants (old may be null for a new grant).
function grantDiff(old, neu) {
  const keys = [...Object.keys(GRANT_TEMPLATE)];
  for (const k of [...Object.keys(old || {}), ...Object.keys(neu)]) if (!keys.includes(k) && !GRANT_META.includes(k)) keys.push(k);
  const show = (o, k) => (o && k in o) ? JSON.stringify(o[k], null, 1) : "—";
  return keys.filter((k) => (old && k in old) || k in neu).map((k) => {
    const a = show(old, k), b = show(neu, k);
    return { field: k, old: a, new: b, changed: a !== b };
  });
}

function diffView(id, rows, isNew) {
  const n = rows.filter((r) => r.changed).length;
  return el("div", {},
    el("p", {}, isNew ? ["New grant ", mono(id), ` with ${rows.length} fields.`] : ["Grant ", mono(id), `: ${n} of ${rows.length} fields change.`]),
    el("div", { class: "table-wrap" }, el("table", { class: "diff" },
      el("thead", {}, el("tr", {}, el("th", {}, "Field"), el("th", {}, isNew ? "" : "Current"), el("th", {}, isNew ? "Value" : "New"))),
      el("tbody", {}, rows.map((r) => el("tr", { class: r.changed ? "changed" : "same" },
        el("td", {}, r.changed ? "● " + r.field : r.field), el("td", { class: "old" }, isNew ? "" : r.old), el("td", { class: "new" }, r.new)))))),
    el("p", { class: "muted small" }, "Saving cuts live sessions this grant no longer covers. The change is audited."));
}

async function grants(v) {
  let list = [];
  if (has("secadmin")) {
    const id = el("input", { name: "id", required: true, pattern: "[A-Za-z0-9._\\-]{1,64}", placeholder: "grant id" });
    const body = el("textarea", { spellcheck: "false", "aria-label": "Grant JSON" });
    body.value = JSON.stringify(GRANT_TEMPLATE, null, 2);
    v.append(card("Create or edit a grant",
      el("p", { class: "muted" }, "Actions: shell, exec, file_read, file_write, forward_local, forward_remote, egress. Subject type: principal | group; target type: device | device_group | server."),
      el("label", {}, "Id", id), el("label", {}, "Grant (JSON)", body),
      btn("Review & save…", async () => {
        if (!id.checkValidity()) { toast("grant id: letters, digits, . _ - (1–64)", "error"); id.focus(); return; }
        let g;
        try { g = JSON.parse(body.value); } catch (e) { toast("invalid JSON: " + e.message, "error"); body.focus(); return; }
        if (!g || typeof g !== "object" || Array.isArray(g)) { toast("the grant must be a JSON object", "error"); return; }
        const cur = list.find((x) => x.id === id.value);
        const rows = grantDiff(cur ? grantFields(cur) : null, grantFields(g));
        if (cur && !rows.some((r) => r.changed)) { toast("nothing changed"); return; }
        if (!(await modal(cur ? "Review changes" : "Review new grant", diffView(id.value, rows, !cur), cur ? "Save changes" : "Create grant"))) return;
        await api("PUT", `/grants/${encodeURIComponent(id.value)}`, g);
        toast("grant saved", "ok"); go("grants");
      }, "")));
    v.edit = (g) => { id.value = g.id; body.value = JSON.stringify(grantFields(g), null, 2); window.scrollTo(0, 0); body.focus(); };
  }
  list = await api("GET", "/grants");
  v.append(card("Grants", table([
    ["Id", (g) => mono(g.id)], ["Subject", (g) => `${g.subject.type}:${g.subject.id}`], ["Target", (g) => g.target.type === "server" ? "server" : `${g.target.type}:${g.target.id}`],
    ["Actions", (g) => g.actions.join(", ")], ["Roots", (g) => g.project_roots.join(", ")],
    ["State", (g) => g.enabled ? pill("enabled", "ok") : pill("disabled", "bad")],
    ["Expires", (g) => ts(g.expires_at)],
    ["", (g) => has("secadmin") ? [
      btn("Edit", async () => v.edit(g)),
      btn("Delete", async () => { if (await modal(`Delete grant ${g.id}?`, el("p", {}, "Live sessions it covers are cut."), "Delete", "danger")) { await api("DELETE", `/grants/${g.id}`); go("grants"); } }, "danger"),
    ] : "", "actions"],
  ], list, "No grants: every request is denied.", (g) => g.id)));
}

async function fullAccess(v) {
  const form = el("form", { class: "row", onsubmit: async (ev) => {
    ev.preventDefault();
    const f = formValues(form);
    try { await api("POST", "/full-access", { agent: f.agent, device: f.device, reason: f.reason, duration_secs: Number(f.duration) * 60 }); go("full"); } catch (e) { toast(e.message, "error"); }
  } },
    el("label", {}, "Agent", el("input", { name: "agent", required: true })),
    el("label", {}, "Device", el("input", { name: "device", required: true })),
    el("label", {}, "Reason", el("input", { name: "reason", required: true, minlength: "5" })),
    el("label", {}, "Minutes (max 480)", el("input", { name: "duration", type: "number", value: "60", min: "1", max: "480" })),
    el("button", { type: "submit" }, "Request"));
  v.append(card("Request full access", el("p", { class: "muted" }, "Lifts the project-root jail and the sandbox. Needs approval by a different secadmin and always expires."), form));
  if (has("sysadmin") || has("secadmin") || has("auditor")) {
    const rcs = await api("GET", "/role-changes");
    v.append(card("Role changes", el("p", { class: "muted" }, "Granting a role needs a secadmin other than the requester and the user concerned."), table([
      ["User", (r) => r.user_name], ["From", (r) => r.from_roles.join(", ") || "none"], ["To", (r) => r.roles.join(", ") || "none"],
      ["Requested by", (r) => r.requested_by], ["Requested", (r) => ts(r.created_at)], ["State", (r) => status(r.status)],
      ["Decided by", (r) => r.decided_by || ""],
      ["", (r) => r.status !== "pending" ? "" : [
        has("secadmin") && r.requested_by !== state.user.id && r.user_id !== state.user.id ? btn("Approve", async () => { await api("POST", `/role-changes/${r.id}/approve`); go("full"); }, "") : "",
        has("secadmin") || r.requested_by === state.user.id ? btn(r.requested_by === state.user.id ? "Withdraw" : "Reject", async () => { await api("POST", `/role-changes/${r.id}/reject`); go("full"); }) : "",
      ], "actions"],
    ], rcs, "No role changes.")));
  }
  const list = await api("GET", "/full-access");
  v.append(card("Full-access requests", table([
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

// ------------------------------------------------------------------- audit

async function playRecording(session) {
  const r = await fetch(`/api/v1/recordings/${encodeURIComponent(session)}`, { credentials: "same-origin" });
  if (!r.ok) throw new Error("recording not available");
  const lines = (await r.text()).split("\n").filter(Boolean);
  const header = JSON.parse(lines[0]);
  const events = lines.slice(1).map((l) => JSON.parse(l));
  const term = el("pre", { class: "term", tabindex: "0" });
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
  const dlg = el("section", { class: "card", id: "player" }, cardHead(["Recording ", mono(session)]),
    el("p", { class: "muted" }, `${header.title || ""} — ${header.width}x${header.height}, ${end.toFixed(1)}s`),
    el("div", { class: "row" }, btn("Play", async () => play(), ""), btn("Show all", async () => { clearInterval(timer); render(Infinity); }),
      el("label", {}, showInput, " show keystrokes")),
    term);
  render(Infinity);
  return dlg;
}

function chainPill(r) {
  if (!r) return pill("chain unchecked", "warn");
  return r.ok ? pill(r.unsigned_tail ? `chain ok · ${r.unsigned_tail} unsigned` : "chain ok", "ok") : pill("chain BROKEN", "bad solid");
}

function updateChainBadge() {
  const b = document.getElementById("chain-badge");
  b.replaceChildren();
  if (!has("auditor") || !state.chain) return;
  b.append(el("a", { href: "#audit", title: state.chain.ok ? "Audit hash chain verified" : "Audit hash chain verification failed" }, chainPill(state.chain)));
}

async function verifyChain() {
  state.chain = await api("GET", "/audit/verify");
  state.chain.at = Date.now();
  updateChainBadge();
  return state.chain;
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
        ["Actor", (r) => mono(r.actor)], ["Target", (r) => r.target], ["Outcome", (r) => status(r.outcome)],
        ["From", (r) => r.ip ? mono(r.ip) : ""],
        ["Session", (r) => r.session ? el("a", { href: "#", class: "mono", onclick: (ev) => { ev.preventDefault(); form.elements.session.value = r.session; load(); } }, r.session) : ""],
        ["Details", (r) => el("pre", { class: "json" }, JSON.stringify(r.data, null, 1))],
        ["", (r) => r.kind === "session.end" && r.data && r.data.recording ? btn("Play", async () => { player.replaceChildren(await playRecording(r.session)); player.scrollIntoView(); }, "") : "", "actions"],
      ], rows, "No matching events."));
    } catch (e) { toast(e.message, "error"); }
  }
  const showVerify = (r) => {
    verifyOut.replaceChildren(el("dl", { class: "kv" },
      el("dt", {}, "Status"), el("dd", {}, r.ok ? pill("hash chain intact", "ok") : pill("BROKEN: " + (r.error || "verification failed"), "bad solid")),
      el("dt", {}, "Events"), el("dd", {}, String(r.events)),
      el("dt", {}, "Signed checkpoints"), el("dd", {}, String(r.checkpoints)),
      el("dt", {}, "After last checkpoint"), el("dd", {}, r.unsigned_tail ? pill(`${r.unsigned_tail} unsigned events`, "warn") : "none"),
      el("dt", {}, "Head"), el("dd", {}, mono(r.head || "")),
      el("dt", {}, "Verified"), el("dd", {}, new Date(r.at).toLocaleString())));
  };
  const badge = el("span", {}, chainPill(state.chain));
  const verify = async () => { const r = await verifyChain(); badge.replaceChildren(chainPill(r)); showVerify(r); };
  v.append(el("div", { class: "page-title" }, el("h1", {}, "Audit"), badge));
  v.append(el("section", { class: "card" },
    cardHead("Integrity",
      btn("Verify again", verify),
      btn("Sign checkpoint", async () => { const r = await api("POST", "/audit/checkpoint"); toast(`checkpoint at #${r.seq}`, "ok"); await verify(); }),
      el("a", { href: "/api/v1/audit/export", download: "cjs-audit.jsonl" }, "Export (JSON lines)")),
    verifyOut));
  v.append(player);
  v.append(card("Events", form, result));
  verifyOut.append(el("div", { class: "skeleton" }, el("div"), el("div")));
  try { await verify(); } catch (e) { verifyOut.replaceChildren(el("p", { class: "error" }, e.message)); }
  load();
}

// ---------------------------------------------------------------- settings

async function settings(v) {
  const u = state.user;
  v.append(el("div", { class: "page-title" }, el("h1", {}, "Settings")));
  const grid = el("div", { class: "grid" });
  v.append(grid);
  grid.append(card("Account", el("dl", { class: "kv" },
    el("dt", {}, "User"), el("dd", {}, u.name),
    el("dt", {}, "Display name"), el("dd", {}, u.display_name || "—"),
    el("dt", {}, "Id"), el("dd", {}, mono(u.id)),
    el("dt", {}, "Roles"), el("dd", {}, u.roles.length ? u.roles.map((r) => [pill(r), " "]) : "none (agent owner)"),
    el("dt", {}, "Groups"), el("dd", {}, (u.groups || []).join(", ") || "—"),
    el("dt", {}, "Last sign-in"), el("dd", {}, u.last_login ? `${ts(u.last_login)} from ${u.last_ip || "?"}` : "—"),
    el("dt", {}, "Account expires"), el("dd", {}, u.expires_at ? ts(u.expires_at) : "never")),
    has("sysadmin") ? el("p", {}, el("a", { href: "#users" }, "Manage users and roles →"), " · ", el("a", { href: "#full" }, "Role approvals →"))
      : el("p", { class: "muted" }, "Users and roles are managed by a sysadmin; role grants need approval by a secadmin (", el("a", { href: "#full" }, "Approvals"), ").")));

  const form = el("form", { onsubmit: async (ev) => {
    ev.preventDefault();
    const f = formValues(form);
    if (f.new !== f.again) { toast("passwords differ", "error"); return; }
    try { await api("POST", "/me/password", { old: f.old, new: f.new, totp: f.totp }); form.reset(); toast("password changed", "ok"); } catch (e) { toast(e.message, "error"); }
  } },
    el("label", {}, "Current password", el("input", { name: "old", type: "password", required: true, autocomplete: "current-password" })),
    el("label", {}, "New password (12+ characters)", el("input", { name: "new", type: "password", required: true, minlength: "12", autocomplete: "new-password" })),
    el("label", {}, "Repeat", el("input", { name: "again", type: "password", required: true, autocomplete: "new-password" })),
    el("label", {}, "Authenticator code", el("input", { name: "totp", required: true, inputmode: "numeric", pattern: "[0-9]{6}", autocomplete: "one-time-code" })),
    el("button", { type: "submit" }, "Change password"));
  grid.append(card("Change password", el("p", { class: "muted" }, "Other signed-in browsers of this account are signed out."), form));

  grid.append(card("Two-factor authentication",
    el("p", {}, pill("required", "ok"), " An authenticator code (TOTP, 6 digits, 30 s) is needed at every sign-in and for a password change."),
    el("p", { class: "muted" }, "Each code works once. The secret is shown only when the account is created or reset; it cannot be displayed again. Lost your authenticator? Ask a sysadmin to reset your credentials (accounts with admin roles are reset by the host operator: cjs-server reset-user)."),
    el("p", { class: "muted" }, "After repeated failed sign-ins the account is locked for a while; a sysadmin can unlock it.")));

  grid.append(card("Appearance", el("p", { class: "muted" }, "Stored in this browser only."), themeChooser(),
    el("p", { class: "muted small" }, "Press ", el("kbd", {}, isMac() ? "⌘ K" : "Ctrl K"), " anywhere to search and run commands.")));

  if (has("sysadmin") || has("secadmin") || has("auditor")) {
    const egress = card("Egress defaults");
    grid.append(egress);
    egress.append(el("p", {}, pill("deny by default", "ok"), " Outbound connections through the server need an ", el("code", {}, "egress"), " action and a matching rule in a grant."),
      el("p", { class: "muted" }, "Every resolved address is checked against the rules; private, loopback, link-local and cloud metadata addresses are blocked unless a rule names them by IP (SSRF guard). Connections go to the checked address, so DNS rebinding cannot bypass the check."));
    if (has("secadmin") || has("auditor")) {
      const gs = await api("GET", "/grants");
      const rows = gs.filter((g) => g.actions.includes("egress") || (g.egress && g.egress.length));
      egress.append(el("h2", {}, "Egress rules in grants"), table([
        ["Grant", (g) => has("secadmin") ? el("a", { href: "#grants" }, g.id) : mono(g.id)],
        ["Subject", (g) => `${g.subject.type}:${g.subject.id}`],
        ["Rules", (g) => (g.egress || []).length ? el("pre", { class: "json" }, (g.egress || []).map((r) => `${r.allow === false ? "deny " : "allow"} ${r.host}${r.ports && r.ports.length ? " ports " + r.ports.join(",") : " any port"}`).join("\n")) : el("span", { class: "muted" }, "none")],
        ["State", (g) => g.enabled ? pill("enabled", "ok") : pill("disabled", "bad")],
      ], rows, "No grant allows egress."));
    } else {
      egress.append(el("p", { class: "muted" }, "Egress rules are part of grants, which secadmins manage."));
    }
  }

  const info = await api("GET", "/info");
  grid.append(card("Server", el("dl", { class: "kv" },
    el("dt", {}, "Version"), el("dd", {}, info.version),
    el("dt", {}, "Fingerprint"), el("dd", {}, mono(info.fingerprint)),
    el("dt", {}, "Server key"), el("dd", {}, mono(info.server_key)),
    el("dt", {}, "Capability key"), el("dd", {}, mono(info.capability_key)),
    el("dt", {}, "Audit key"), el("dd", {}, mono(info.audit_key))),
    el("p", {}, el("a", { href: "/api/v1/openapi.json" }, "API reference (OpenAPI)"))));
}

// --------------------------------------------------------- command palette

function isMac() { return /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent); }

const palette = { open: false, items: [], cache: null, cacheAt: 0 };

// Subsequence match: consecutive characters and word starts score higher.
// Returns null (no match) or { score, hits } with matched positions.
function fuzzy(q, text) {
  if (!q) return { score: 0, hits: [] };
  const t = text.toLowerCase();
  let score = 0, ti = 0, prev = -2;
  const hits = [];
  for (const ch of q.toLowerCase()) {
    if (ch === " ") continue;
    const i = t.indexOf(ch, ti);
    if (i < 0) return null;
    score += 1 + (i === prev + 1 ? 5 : 0) + (i === 0 || /[\s:._/-]/.test(t[i - 1]) ? 3 : 0) - Math.min(i - ti, 10) * 0.1;
    hits.push(i);
    prev = i;
    ti = i + 1;
  }
  if (t.startsWith(q.toLowerCase())) score += 10;
  return { score, hits };
}

function highlight(text, hits) {
  const set = new Set(hits);
  const out = [];
  let run = "", inMark = false;
  const flush = () => { if (run) out.push(inMark ? el("mark", {}, run) : run); run = ""; };
  for (let i = 0; i < text.length; i++) {
    const m = set.has(i);
    if (m !== inMark) { flush(); inMark = m; }
    run += text[i];
  }
  flush();
  return out;
}

function focusRow(view, key) {
  state.focus = { view, key };
  if (state.view === view) applyFocus(); else go(view);
}

function applyFocus() {
  const f = state.focus;
  if (!f || f.view !== state.view) return;
  state.focus = null;
  const row = document.querySelector(`tr[data-key="${CSS.escape(f.key)}"]`);
  if (row) { row.classList.add("focus"); row.scrollIntoView({ block: "center" }); }
}

function staticCommands() {
  const cmds = [];
  for (const [k, d] of Object.entries(views)) {
    if (!d.roles || d.roles.some(has)) cmds.push({ kind: "page", label: `Go to ${d.label}`, run: () => go(k) });
  }
  const act = (label, run, hint) => cmds.push({ kind: "action", label, hint, run });
  act("New enrollment token", () => go("tokens"), "Enrollment");
  if (has("sysadmin")) { act("Create user", () => go("users"), "Users"); act("Create group", () => go("groups"), "Groups"); }
  if (has("secadmin")) act("Create or edit grant", () => go("grants"), "Access");
  act("Request full access", () => go("full"), "Approvals");
  if (has("auditor")) {
    act("Verify audit chain", async () => { const r = await verifyChain(); toast(r.ok ? "audit chain intact" : "audit chain BROKEN", r.ok ? "ok" : "error"); }, "Audit");
    act("Sign audit checkpoint", async () => { const r = await api("POST", "/audit/checkpoint"); toast(`checkpoint at #${r.seq}`, "ok"); }, "Audit");
    act("Export audit log", () => { location.href = "/api/v1/audit/export"; }, "Audit");
  }
  act("Change password", () => go("settings"), "Settings");
  for (const [t, label] of Object.entries(THEMES)) act(`Theme: ${label}`, () => setTheme(t), "Appearance");
  act("Log out", logout);
  return cmds;
}

// Inventory and live sessions, fetched when the palette opens (30 s cache).
async function dataCommands() {
  if (palette.cache && Date.now() - palette.cacheAt < 30000) return palette.cache;
  const live = has("secadmin") || has("auditor");
  const [devs, ags, streams] = await Promise.all([
    api("GET", "/devices").catch(() => []), api("GET", "/agents").catch(() => []),
    live ? api("GET", "/live/streams").catch(() => []) : [],
  ]);
  const out = [];
  for (const s of streams) {
    out.push({ kind: "session", label: `${s.principal} → ${s.target}`, hint: `${s.kind} · ${s.session}`, search: s.session,
      run: () => { if (s.kind === "pty") { state.watch = s.session; go("sessions"); } else focusRow("sessions", s.session); } });
  }
  for (const d of devs) out.push({ kind: "device", label: d.name, hint: `${d.online ? "online" : "offline"} · ${d.id}`, search: d.id, run: () => focusRow("devices", d.id) });
  for (const a of ags) out.push({ kind: "agent", label: a.name, hint: `${a.online ? "online" : "offline"} · ${a.id}`, search: a.id, run: () => focusRow("agents", a.id) });
  palette.cache = out;
  palette.cacheAt = Date.now();
  return out;
}

function openPalette() {
  if (palette.open || !state.user) return;
  palette.open = true;
  const prev = document.activeElement;
  const input = el("input", { type: "text", role: "combobox", "aria-expanded": "true", "aria-controls": "pal-list", "aria-autocomplete": "list",
    "aria-label": "Search devices, agents, sessions and commands", placeholder: "Search devices, agents, sessions, pages, actions…", autocomplete: "off", spellcheck: "false" });
  const list = el("ul", { id: "pal-list", role: "listbox", "aria-label": "Results" });
  const ov = el("div", { class: "overlay", onclick: (ev) => { if (ev.target === ov) close(); } },
    el("div", { class: "dialog palette", role: "dialog", "aria-modal": "true", "aria-label": "Command palette" }, input, list,
      el("div", { class: "palette-foot", "aria-hidden": "true" }, el("span", {}, el("kbd", {}, "↑"), " ", el("kbd", {}, "↓"), " navigate"),
        el("span", {}, el("kbd", {}, "↵"), " open"), el("span", {}, el("kbd", {}, "esc"), " close"))));
  let all = staticCommands();
  let shown = [];
  let sel = 0;
  const close = () => { palette.open = false; ov.remove(); if (prev && prev.focus) prev.focus(); };
  const choose = async (it) => {
    close();
    try { await it.run(); } catch (e) { toast(e.message, "error"); }
  };
  const mark = () => {
    list.querySelectorAll("[role=option]").forEach((o) => o.setAttribute("aria-selected", String(Number(o.dataset.i) === sel)));
    const cur = document.getElementById("pal-opt-" + sel);
    if (cur) { input.setAttribute("aria-activedescendant", cur.id); cur.scrollIntoView({ block: "nearest" }); } else input.removeAttribute("aria-activedescendant");
  };
  const order = ["session", "device", "agent", "page", "action"];
  const groupName = { session: "Live sessions", device: "Devices", agent: "Agents", page: "Pages", action: "Actions" };
  const render = () => {
    const q = input.value.trim();
    const scored = [];
    for (const it of all) {
      const m = fuzzy(q, it.label) || (it.search && fuzzy(q, it.search) ? { score: fuzzy(q, it.search).score - 2, hits: [] } : null);
      if (m) scored.push({ it, m });
    }
    if (q) scored.sort((a, b) => b.m.score - a.m.score);
    else scored.sort((a, b) => order.indexOf(a.it.kind) - order.indexOf(b.it.kind));
    shown = scored.slice(0, 50);
    sel = 0;
    const nodes = [];
    let lastGroup = null;
    shown.forEach(({ it, m }, i) => {
      if (!q && it.kind !== lastGroup) { nodes.push(el("li", { class: "group", role: "presentation" }, groupName[it.kind])); lastGroup = it.kind; }
      nodes.push(el("li", { id: "pal-opt-" + i, role: "option", "data-i": String(i), "aria-selected": "false",
        onmousemove: () => { if (sel !== i) { sel = i; mark(); } }, onclick: () => choose(it) },
      el("span", { class: "kind" }, it.kind), el("span", { class: "label" }, highlight(it.label, m.hits)),
      it.hint ? el("span", { class: "hint mono" }, it.hint) : null));
    });
    list.replaceChildren(...(nodes.length ? nodes : [el("li", { class: "empty", role: "presentation" }, "No results")]));
    mark();
  };
  input.addEventListener("input", render);
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown") { ev.preventDefault(); if (shown.length) { sel = (sel + 1) % shown.length; mark(); } }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); if (shown.length) { sel = (sel - 1 + shown.length) % shown.length; mark(); } }
    else if (ev.key === "Home" && ev.ctrlKey) { ev.preventDefault(); sel = 0; mark(); }
    else if (ev.key === "Enter") { ev.preventDefault(); if (shown[sel]) choose(shown[sel].it); }
    else if (ev.key === "Escape") { ev.preventDefault(); close(); }
    else if (ev.key === "Tab") ev.preventDefault();
  });
  document.body.append(ov);
  input.focus();
  render();
  dataCommands().then((data) => {
    if (!palette.open) return;
    const keep = shown[sel] && shown[sel].it;
    all = [...data, ...staticCommands()];
    render();
    if (keep && input.value.trim()) { const i = shown.findIndex((s) => s.it.label === keep.label); if (i >= 0) { sel = i; mark(); } }
  });
}

document.addEventListener("keydown", (ev) => {
  if ((ev.metaKey || ev.ctrlKey) && !ev.altKey && ev.key.toLowerCase() === "k") {
    if (!state.user) return;
    ev.preventDefault();
    openPalette();
  }
});

// ------------------------------------------------------------ navigation

function nav() {
  const n = document.getElementById("nav");
  n.replaceChildren(...Object.entries(views)
    .filter(([, d]) => !d.roles || d.roles.some(has))
    .map(([k, d]) => el("a", { href: "#" + k, class: state.view === k ? "active" : "", "aria-current": state.view === k ? "page" : null }, d.label)));
}

async function go(name, keepScroll) {
  name = aliases[name] || name;
  const d = views[name] && (!views[name].roles || views[name].roles.some(has)) ? views[name] : views.overview;
  state.view = Object.keys(views).find((k) => views[k] === d);
  state.gen++;
  for (const c of state.aborts) c.abort();
  state.aborts = [];
  if (location.hash !== "#" + state.view) history.replaceState(null, "", "#" + state.view);
  nav();
  const v = el("section", { id: "view" });
  document.getElementById("view").replaceWith(v);
  // One-time secrets survive exactly one re-render.
  if (state.flash) {
    v.append(el("section", { class: "card" }, state.flash));
    state.flash = null;
  }
  const skel = skeleton();
  v.append(skel);
  const gen = state.gen;
  try { await d.render(v); } catch (e) { if (gen === state.gen) v.append(card("Error", el("p", { class: "error" }, e.message))); }
  skel.remove();
  if (!keepScroll) window.scrollTo(0, 0);
  applyFocus();
}

function showLogin() {
  state.user = null;
  state.chain = null;
  state.gen++;
  for (const c of state.aborts) c.abort();
  state.aborts = [];
  palette.cache = null;
  document.getElementById("top").hidden = true;
  document.getElementById("view").replaceChildren();
  document.getElementById("login").hidden = false;
  updateChainBadge();
}

function showApp() {
  document.getElementById("login").hidden = true;
  document.getElementById("top").hidden = false;
  document.getElementById("who").textContent = `${state.user.name} (${state.user.roles.join(", ") || "user"})`;
  document.getElementById("palette-kbd").textContent = isMac() ? "⌘K" : "Ctrl K";
  applyTheme(getTheme());
  go((location.hash || "#overview").slice(1));
  // Auditors see the hash-chain state in the top bar on every page.
  if (has("auditor") && state.view !== "audit") verifyChain().catch(() => {});
}

async function logout() {
  try { await api("POST", "/logout"); } catch (e) { /* session may already be gone */ }
  showLogin();
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

document.getElementById("logout").addEventListener("click", logout);
document.getElementById("theme").addEventListener("click", cycleTheme);
document.getElementById("palette-btn").addEventListener("click", openPalette);

window.addEventListener("hashchange", () => { if (state.user) go(location.hash.slice(1)); });

(async () => {
  try {
    const r = await api("GET", "/me");
    state.user = r.user;
    state.csrf = r.csrf;
    showApp();
  } catch (e) { showLogin(); }
})();
