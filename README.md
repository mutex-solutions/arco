# arco

[![CI](https://github.com/mutex-solutions/arco/actions/workflows/ci.yml/badge.svg)](https://github.com/mutex-solutions/arco/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mutex-solutions/arco)](https://github.com/mutex-solutions/arco/releases/latest)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

arco is an MCP server for a fleet of [herdr](https://herdr.dev) machines. It lets
an MCP client such as Claude Code list, read, and drive the terminal workspaces
and AI agents that herdr runs on each machine.

```
MCP client ──stdio, or HTTP + token──▶ arco ──unix socket──▶ herdr (this machine)
                                            └──ssh -W──────▶ herdr (remote machines)
```

- **Stateless.** herdr is the source of truth. Each tool call opens a fresh
  connection, sends one request, and returns herdr's answer. Nothing is cached.
- **Machine-scoped.** Every action names one machine from your registry.
- **Scrubbed.** Keys, tokens, and private keys in results are redacted before
  they reach the client.
- **No focus stealing.** Workspaces are created in the background.

## Install

macOS and Linux, amd64 and arm64:

```sh
curl -fsSL https://raw.githubusercontent.com/mutex-solutions/arco/main/install.sh | sh
```

Or with Homebrew:

```sh
brew install mutex-solutions/tap/arco
```

Or from source (Go 1.25 or later):

```sh
go install github.com/mutex-solutions/arco/cmd/arco@latest
```

The installer verifies the release checksum. Set `ARCO_VERSION=v0.1.0` to pin a
version or `ARCO_INSTALL_DIR` to choose the directory.

## Quick start

1. List your machines in `~/.arco/machines.toml`:

   ```toml
   [[machine]]
   id        = "local"
   transport = "unix"
   socket    = "~/.config/herdr/herdr.sock"

   [[machine]]
   id        = "vm0"
   transport = "ssh"
   host      = "vm0"
   user      = "me"
   socket    = "/home/me/.config/herdr/herdr.sock"
   ```

2. Check that each one answers:

   ```sh
   arco machines
   ```

3. Add arco to Claude Code:

   ```sh
   claude mcp add arco -- arco mcp serve
   ```

The full walkthrough, including remote access, is in [SETUP.md](SETUP.md).

## Tools

| Read | Mutate |
|---|---|
| `machines`, `fleet_status`, `workspaces`, `panes`, `agents`, `peek`, `pane_detail`, `wait_for_output`, `wait_agent` | `create_workspace`, `send_text`, `start_agent`, `prompt_agent`, `close_pane`, `close_workspace` |

Read tools are annotated `readOnlyHint`, so clients can auto-approve them and
ask before mutations.

## Remote access

`arco serve` exposes the same tools over Streamable HTTP. Every request needs a
bearer token.

```sh
arco token create --name checks                                          # read-only, all machines
arco token create --name ops --scope readwrite --machines vm0 --ttl 7d   # read-write, one machine
arco serve --http 127.0.0.1:8080
```

- `read` tokens get the 9 read tools. `readwrite` tokens get all 15.
- A token sees only the machines it was created for.
- Only SHA-256 hashes are stored. Revocation applies to the next request.
- Run it on loopback or a private network. It has no OAuth and is not built
  for public exposure.

## Claude Code skill

The `arco` skill teaches an agent how to use the tools and read their errors.
Install it as a plugin:

```
/plugin install arco --marketplace mutex-solutions/arco
```

Or copy it: `cp -r skills/arco ~/.claude/skills/`

## Status

Pre-1.0. The tool surface and token format may change.

## License

[Apache 2.0](LICENSE)
