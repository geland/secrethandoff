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
      $("title").textContent = "Your agent asks for " + v.name;
      $("reason").textContent = v.reason || "(no reason given)";
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
      const [title, text] = finalText[v.state === "filled" && v.via_phone ? "filled_phone" : v.state] || ["Done", ""];
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
      $("value").value = "";
      $("value-multi").value = "";
      refresh();
    }
  };
  $("submit").addEventListener("click", () => {
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
