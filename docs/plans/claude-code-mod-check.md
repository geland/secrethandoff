# Claude Code mod check (P4-1)

- Date: 2026-10-07
- Claude Code version: 2.1.289
- Source: the plugin API type file that this version supplies to plugin authors (`claude-code.d.ts`)
- Result: **gate GG-15 fails. Phase 4 stops. The mod does not ship.**

## Question

Can a Claude Code mod collect a secret in its own pane, with the same safety as the local fill page? Gate GG-15 needs three checks to pass: T-48, T-49, and T-50 in the [threat model](../security/sealed-request-threat-model.md).

## Results

### T-48: other plugins can read the value. Fail.

- Each change to an `Input` element and each Enter raises the `ui.input` event. The event goes through the hooks of every plugin that hooks it. The element's own `onInput` or `onSubmit` handler runs last.
- The event carries `value`, the whole text of the field. A hook above can read it and can change it.
- Another plugin can select our field by its plugin name and element key, for example `on("ui.input", { plugin: "secrethandoff", element: "<key>" }, ...)`. The API documentation gives this pattern as an example. A hook without a matcher sees the fields of all plugins.
- The `$.plugin` noun describes only the plugin that calls it. The API has no call that lists other plugins or their hooks.

The planned mitigation was to detect another hook and fall back to the local page. Without a list of hooks, the mod cannot detect one. So the mitigation cannot work.

### T-50: the child process channel is not private. Fail.

- `$.process.run` and `$.process.spawn` are in the core API. The type file does not mark them as limited to the CLI.
- Each call raises the `process.run` or `process.spawn` event. The event carries the request, which includes the text for the child's stdin (`init.stdin` for `run`, `input` for `spawn`). Hooks of other plugins see the request before the engine starts the child.
- The API documentation gives an example of a hook "above another plugin's spawn" that reads each piece of output.

So stdin to a child binary is not a private pipe when other plugins are loaded.

### T-49: transcript and debug log. Not tested.

T-48 and T-50 fail, so the mod does not ship. A live test of T-49 adds no decision value.

### Other finding: no masked field

`InputProps` has `key`, `label`, `placeholder`, `value`, `submitLabel`, `autoFocus`, `onInput`, and `onSubmit`. It has no property to hide the typed text. The field shows the secret in clear text. Anyone who sees the screen, or a screen share, sees the value. The local fill page uses a masked input.

## Decision

- Phase 4 stops. P4-2 is not built.
- The local fill page stays the only fill surface on the agent's computer. It runs in the browser, outside the agent client, so other Claude Code plugins cannot see it.
- A mod that only opens the local page and shows request status gives no security gain. It is not planned.

## When to check again

Check again if a later Claude Code version adds one of these:

- An `Input` property that hides the text and keeps the value out of `ui.input` hooks of other plugins.
- A private channel from a plugin to its own child process.
- A call that lists the hooks of other loaded plugins.
