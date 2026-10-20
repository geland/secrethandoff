"use strict";
// Agent-supplied text is shown only through textContent, never as HTML.
(() => {
  const $ = (id) => document.getElementById(id);
  // The Claude desktop app's browser pane: the agent can read and drive it,
  // so this page never shows a form there (threat model T-54). The server
  // refuses this browser too. Stop before the token is read or stored.
  if (/\bClaude\/\d/.test(navigator.userAgent) && /\bChrome\//.test(navigator.userAgent)) {
    history.replaceState(null, "", location.pathname);
    $("title").textContent = "Open Secret Handoff in your own browser";
    $("status").textContent = "This page is open in a browser that your AI agent can read and control, so it does not show the form here. "
      + "Secret Handoff opens requests in your default browser by itself. If your agent opened this page here, do not continue: ask it why.";
    return;
  }
  // Keep the token for this tab only, so a reload still works (as the
  // receipt page does). It never goes into durable storage.
  const token = location.hash.slice(1) || sessionStorage.getItem("sh_token") || "";
  if (location.hash) sessionStorage.setItem("sh_token", token);
  history.replaceState(null, "", location.pathname);
  // A new request link in the same tab changes only the fragment, which
  // does not reload the page. Reload so the new token is used.
  window.addEventListener("hashchange", () => location.reload());
  let current = null;
  let timer = null;
  let groupSignature = "";
  let groupFields = [];

  const call = async (path, body) => {
    const res = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? { "X-Secrethandoff-Token": token } : { "X-Secrethandoff-Token": token, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!res.ok) throw new Error((await res.text()).trim() || "Request failed");
    return res.json();
  };

  const setStatus = (text) => { $("status").textContent = text; };

  const finalText = {
    filled: ["Secret given", "The agent can now use the secret by name. You can close this tab."],
    filled_phone: ["Secret given from another device", "The agent can now use the secret by name. If you did not fill it on your phone, select This was not me."],
    declined: ["Declined", "The agent did not get a secret. You can close this tab."],
    approved: ["Command approved", "The command runs once. You can close this tab."],
    denied: ["Command denied", "The command did not run. You can close this tab."],
    rejected: ["Cancelled", "The request was cancelled and any value was discarded."],
    expired: ["Expired", "This request expired. Ask the agent to try again if you still need it."],
  };

  const renderFields = (fields) => {
    const signature = JSON.stringify(fields);
    $("single-fields").hidden = fields.length > 0;
    $("group-fields").hidden = fields.length === 0;
    if (signature === groupSignature) return;
    groupSignature = signature;
    groupFields = [];
    $("group-fields").replaceChildren();
    fields.forEach((field, index) => {
      const section = document.createElement("div");
      section.className = "group-field";
      const label = document.createElement("label");
      label.className = "label";
      label.htmlFor = "field-" + index;
      label.textContent = field.label || field.name;
      const name = document.createElement("span");
      name.className = "hint";
      name.textContent = field.name;
      name.hidden = field.label === field.name;
      label.append(name);
      const input = document.createElement("input");
      input.id = label.htmlFor;
      input.type = "password";
      input.autocomplete = "off";
      input.spellcheck = false;
      input.autocapitalize = "off";
      const textarea = document.createElement("textarea");
      textarea.id = "field-multi-" + index;
      textarea.rows = 3;
      textarea.autocomplete = "off";
      textarea.spellcheck = false;
      textarea.hidden = true;
      textarea.setAttribute("aria-label", (field.label || field.name) + " (multiple lines)");
      const row = document.createElement("div");
      row.className = "row";
      const multiLabel = document.createElement("label");
      multiLabel.className = "check";
      const multi = document.createElement("input");
      multi.type = "checkbox";
      multiLabel.append(multi, document.createTextNode(" Multiple lines (shown as you type)"));
      const reveal = document.createElement("button");
      reveal.type = "button";
      reveal.className = "link";
      reveal.textContent = "Show";
      reveal.setAttribute("aria-label", "Show " + (field.label || field.name));
      reveal.addEventListener("click", () => { input.type = input.type === "password" ? "text" : "password"; reveal.textContent = input.type === "password" ? "Show" : "Hide"; reveal.setAttribute("aria-label", reveal.textContent + " " + (field.label || field.name)); });
      multi.addEventListener("change", () => { input.hidden = multi.checked; textarea.hidden = !multi.checked; reveal.hidden = multi.checked; });
      row.append(multiLabel, reveal);
      section.append(label, input, textarea, row);
      $("group-fields").append(section);
      groupFields.push({ name: field.name, input, textarea, multi });
    });
  };
  const clearValues = () => {
    $("value").value = "";
    $("value-multi").value = "";
    groupFields.forEach(f => { f.input.value = ""; f.textarea.value = ""; });
  };

  const render = (v) => {
    current = v;
    const pending = v.state === "pending";
    const about = v.about || {};
    $("agent").textContent = about.client || "An AI agent (it did not give its name)";
    $("served").textContent = "secrethandoff " + (about.version || "") + " at " + location.host + (about.isolated ? " · separate window, no extensions" : "");
    $("isolated").hidden = !about.isolated;
    $("origin").hidden = false;
    $("eyebrow").textContent = v.kind === "approve" ? "Local command approval" : "Local secret request";
    $("fill").hidden = !(pending && v.kind === "fill" && v.claimed_here);
    $("approve").hidden = !(pending && v.kind === "approve" && v.claimed_here);
    if (v.kind === "fill") {
      const fields = v.fields || [];
      renderFields(fields);
      $("title").textContent = fields.length ? "Give " + fields.length + " secrets together" : "Your agent asks for " + v.name;
      $("submit").textContent = fields.length ? "Give all secrets to agent →" : "Give secret to agent →";
      $("fill-note").textContent = fields.length ? "All fields are required and submitted together. Combined limit: 32 KiB. Values stay on this computer; the agent receives only their names. Forgetting any member erases the whole group." : "The secret stays on this computer. The agent gets only its name and can use it only as the policy above allows.";
      $("reason").textContent = v.reason || "(no reason given)";
      $("policy-label").textContent = fields.length ? "Where these secrets can go" : "Where the secret can go";
      $("policy").textContent = v.policy;
      $("wildcard").hidden = !v.wildcard;
      $("phone").hidden = !v.phone_fill_available;
      if (v.phone_error) setStatus("Phone fill stopped: " + v.phone_error + " You can still give the secret on this page.");
    } else {
      $("title").textContent = "Approve a command";
      $("command").textContent = (v.command || []).map((a) => (/[\s"'\\]/.test(a) ? JSON.stringify(a) : a)).join(" ");
      $("dir").textContent = v.dir || "(current folder)";
      $("secrets").textContent = (v.secrets || []).join(", ");
    }
    const after = $("after");
    if (pending && v.claimed_elsewhere) {
      after.hidden = false;
      $("after-text").textContent = "This request was opened in another window. If you did not open it, select This was not me.";
      $("notme").hidden = false;
      setStatus("");
    } else if (!pending) {
      clearValues();
      const [title, text] = v.state === "filled" && (v.fields || []).length ? ["Secrets given", "All fields were submitted together. The agent can use each secret by its name. You can close this tab."] : finalText[v.state === "filled" && v.via_phone ? "filled_phone" : v.state] || ["Done", ""];
      $("title").textContent = title;
      $("origin").hidden = true;
      after.hidden = false;
      $("after-text").textContent = text;
      $("notme").hidden = !(v.state === "filled" || v.state === "approved");
      setStatus("");
      if (v.state !== "filled" && v.state !== "approved") stopPolling();
    } else {
      after.hidden = true;
      const left = Math.max(0, Math.round((new Date(v.expires) - Date.now()) / 60000));
      setStatus("Expires in about " + left + " min.");
    }
  };

  const refresh = async () => {
    try { render(await call("/api/request")); }
    catch (e) { setStatus(e.message); stopPolling(); }
  };
  const stopPolling = () => { if (timer) clearInterval(timer); timer = null; };

  const valueField = () => ($("multi").checked ? $("value-multi") : $("value"));
  $("multi").addEventListener("change", () => {
    $("value").hidden = $("multi").checked;
    $("value-multi").hidden = !$("multi").checked;
    $("reveal").hidden = $("multi").checked;
  });
  $("reveal").addEventListener("click", () => {
    const f = $("value");
    f.type = f.type === "password" ? "text" : "password";
    $("reveal").textContent = f.type === "password" ? "Show" : "Hide";
  });

  const act = (path, body) => async () => {
    for (const b of document.querySelectorAll("button")) b.disabled = true;
    try {
      render({ ...current, ...(await call(path, body ? body() : {})) });
    } catch (e) {
      setStatus(e.message);
    } finally {
      for (const b of document.querySelectorAll("button")) b.disabled = false;
      clearValues();
      refresh();
    }
  };
  $("submit").addEventListener("click", () => {
    if (groupFields.length) {
      const values = Object.fromEntries(groupFields.map(f => [f.name, (f.multi.checked ? f.textarea : f.input).value]));
      if (Object.values(values).some(v => !v)) { setStatus("Fill every field first."); return; }
      if (Object.values(values).reduce((n, v) => n + new TextEncoder().encode(v).length, 0) > 32768 || new TextEncoder().encode(JSON.stringify({values})).length > 65536) { setStatus("The group is too large. Use at most 32 KiB combined, within a 64 KiB encoded submission."); return; }
      act("/api/fill", () => ({ values }))();
      return;
    }
    if (!valueField().value) { setStatus("Enter the secret first."); return; }
    act("/api/fill", () => ({ value: valueField().value }))();
  });
  $("decline").addEventListener("click", act("/api/decline"));
  $("allow").addEventListener("click", act("/api/approve"));
  $("deny").addEventListener("click", act("/api/deny"));
  $("notme").addEventListener("click", act("/api/not-me"));
  $("phone-start").addEventListener("click", async () => {
    $("phone-start").disabled = true;
    try {
      const info = await call("/api/relay", {});
      $("pairing").textContent = info.pairing_code;
      // The SVG comes from this program, and the CSP allows data: images.
      $("qr").src = "data:image/svg+xml;base64," + btoa(info.qr_svg);
      $("phone-panel").hidden = false;
      $("phone-start").hidden = true;
    } catch (e) {
      setStatus("Phone fill is not available: " + e.message);
      $("phone-start").disabled = false;
    }
  });

  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) { setStatus("This page link is not valid."); return; }
  refresh();
  timer = setInterval(refresh, 2000);
})();
