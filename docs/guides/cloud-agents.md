# Secrets for cloud agents

This guide helps you choose how a cloud or headless AI agent gets a secret. A cloud agent runs in a VM without your browser, so local mode (ADR 0009) does not apply.

## Choose

| Situation | Use | Why |
|---|---|---|
| Claude Code cloud sessions on a Pro or Max plan, HTTP APIs, a key that you use often | Claude Code **API credentials** on the cloud environment | Anthropic's agent proxy adds the key to requests for the hosts you list. The key never reaches the session's VM, environment variables, or files. |
| Any cloud agent, a secret that you need during a session, and you want the agent never to hold it | The **Secret Handoff gateway** (`templates/gateway`) | You fill the secret on your phone. The gateway keeps it and gives the agent a scoped proxy token for at most 24 hours. |
| Any agent without a browser, one secret now, and the agent may hold it | **Remote mode** of `secrethandoff` | You fill on your phone and read a confirmation code back to the agent. The value is in the VM, so a command that holds it can leak it. |
| A secret that a setup script needs before the agent starts | The platform's own environment secrets | Codex cloud secrets are available only to the setup script. GitHub Copilot uses the `copilot` Actions environment. Cursor cloud agents load runtime secrets as environment variables. |

## Rules for every choice

- Give the agent a key with the smallest scope and the shortest life that does the task.
- Never paste a secret into the chat. In Claude Code, the Secret Handoff plugin stops a pasted secret before it reaches the model, but the client still saves the message on your computer.
- Check the pairing code before you fill, and give the confirmation code only for a fill that you made.
- Revoke a gateway token, or delete a platform secret, when the task ends.

## Facts behind this guide

- Claude Code cloud environments: API credentials are attached by the agent proxy after a request leaves the VM, and are available on Pro and Max plans, not yet on Team or Enterprise. Source: https://code.claude.com/docs/en/cloud-environments
- Codex cloud: environment secrets are available only during the setup script. Source: https://developers.openai.com/codex/cloud/environments
- Other vendors' behavior comes from their documentation as of October 2026. Check it again before you rely on it.
