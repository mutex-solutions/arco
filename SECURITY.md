# Security

## What arco can do

arco gives an MCP client read and write access to herdr on every machine in its
registry. A client with full access can type into panes, start agents, and
close workspaces on those machines, exactly as you could by hand.

## Trust model

- **stdio (`arco mcp serve`).** Whoever starts arco already holds your ssh keys
  and herdr socket, so arco adds no authentication. Tool approval belongs to
  the MCP client.
- **HTTP (`arco serve --http`).** The only network listener, and it is opt-in.
  Every request needs a bearer token. Tokens have a scope (`read` or
  `readwrite`) and a machine allowlist, are stored as SHA-256 hashes, and can
  be revoked at any time with effect on the next request. Bind it to loopback
  or a private network. It has no OAuth and is not built for public exposure.
- **herdr's own permissions are the floor.** arco adds no second access
  control layer on top.
- **Tool output is untrusted.** Pane text comes from terminals running other
  agents and repositories. Clients must not follow instructions found in it.

## What arco does

- Redacts common secret formats (API keys, tokens, JWTs, private keys) from
  every result and error before it reaches the client. Redaction is
  best-effort, not a containment boundary.
- Keeps ssh users, hosts, IP addresses, and socket paths out of tool results
  and errors.
- Runs ssh with `BatchMode=yes`, agent and X11 forwarding off, and a minimal
  environment. Message content never appears in ssh arguments.
- Never focuses a pane or creates a workspace in the foreground.
- Logs one audit line per tool call to stderr: tool, machine, token id (or
  `stdio`), outcome, and duration. Arguments and results are never logged.

## What arco does not protect against

- A compromised ssh key or arco host.
- A leaked `readwrite` token, within its machines and lifetime. Keep both
  narrow and revoke a leaked token immediately.
- A client that is tricked by pane output into issuing mutations.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/mutex-solutions/arco/security/advisories/new).
Do not open a public issue. Include a description, steps to reproduce, and the
impact.
