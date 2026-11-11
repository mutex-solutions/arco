# Setup

This guide takes you from a fresh install to Claude Code driving herdr, first
over stdio and then over HTTP with a scoped token. Each step ends with a check.

## 1. Prerequisites

- herdr 0.9.5 or later (protocol 22) running on every machine. The socket is
  usually `~/.config/herdr/herdr.sock`.
- For remote machines: ssh with key authentication and no prompts. This must
  succeed silently:

  ```sh
  ssh -o BatchMode=yes me@vm0 true
  ```


## 2. Install

```sh
curl -fsSL https://raw.githubusercontent.com/mutex-solutions/arco/main/install.sh | sh
arco version
```

Alternatives: `brew install mutex-solutions/tap/arco`, or
`go install github.com/mutex-solutions/arco/cmd/arco@latest`.

## 3. Register machines

Create `~/.arco/machines.toml` and `chmod 600` it:

```toml
[[machine]]
id        = "local"
transport = "unix"
socket    = "~/.config/herdr/herdr.sock"

[[machine]]
id        = "vm0"
transport = "ssh"
host      = "vm0"                                 # hostname, Tailscale name, or ssh alias
user      = "me"
socket    = "/home/me/.config/herdr/herdr.sock"   # absolute path for ssh machines
timeout   = "10s"                                 # optional, 1s to 5m
```

- `id` is the name you and your agents use: lowercase letters, digits, and `-`, up to 32 characters.
- The file holds no credentials. ssh uses your keys and agent.
- To use another file, pass `--machines <path>` or set `ARCO_MACHINES`.

Check:

```sh
$ arco machines
local  unix  /home/me/.config/herdr/herdr.sock         ok  herdr=0.9.5  protocol=22
vm0    ssh   me@vm0:/home/me/.config/herdr/herdr.sock  ok  herdr=0.9.5  protocol=22
2/2 ok
```

A failing machine shows `err` and the cause. See [Troubleshooting](#troubleshooting).

## 4. Connect Claude Code over stdio

Claude Code starts arco itself. stdio has no token: anyone who can run it
already has your ssh keys, so it has full access.

```sh
claude mcp add arco -- arco mcp serve
claude mcp list            # arco should show as connected
```

Install the skill, inside Claude Code:

```
/plugin install arco --marketplace mutex-solutions/arco
```

Start a new Claude Code session and try:

- "Which machines does arco see, and what agents are running?"
- "Show the last 30 lines of pane w1:p1 on vm0."
- "On vm0, create a workspace in /tmp, run `echo hello`, show the output, then
  close the workspace."

Claude Code asks for approval before each mutating call.

## 5. Connect over HTTP with a token

Use this for clients that cannot start a local process, or to grant less than
full access.

### Create tokens

```sh
arco token create --name checks                                          # read-only, all machines
arco token create --name ops --scope readwrite --machines vm0 --ttl 7d   # read-write, vm0 only
```

The token is printed once. Copy it now.

```
id:       tok_3de8ae816bb4
name:     ops
scope:    readwrite
machines: vm0
expires:  2026-11-18T16:39:46+07:00
token:    arco_rw_...
header:   Authorization: Bearer arco_rw_...
```

| Scope | Tools | Defaults |
|---|---|---|
| `read` | the 7 read tools | all machines, no expiry |
| `readwrite` | all 13 tools | `--machines` required, expires in 30 days, at most 90 |

Tokens are stored as SHA-256 hashes in `~/.arco/tokens.json` (mode 0600). To
use another file, pass `--tokens <path>` or set `ARCO_TOKENS`.

### Start the server

```sh
arco serve --http 127.0.0.1:8080
```

- Bind to loopback or a private address (LAN, Tailscale). arco prints a
  warning for any other address.
- The log shows method, path, status, duration, and token id. Never the token.
- Tokens are reloaded on every request. No restart is needed after create or
  revoke.

Check:

```sh
curl -s http://127.0.0.1:8080/healthz                                         # ok
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/mcp     # 401
```

### Connect a client

```sh
claude mcp add --transport http arco-http http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer arco_rw_..."
```

Any MCP client with Streamable HTTP and custom headers works the same way.

Check in a new session: a `read` token lists 7 tools, a `readwrite` token
lists 13.

### Revoke

```sh
arco token list
arco token revoke ops      # name or id; the next request gets 401
```

## 6. Acceptance checklist

1. `arco machines` reports every machine `ok`.
2. `fleet_status` lists agents per machine. A stopped machine appears with an
   error instead of disappearing.
3. A workspace created through arco does not take focus on the machine.
4. Running `echo sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` in a pane and
   peeking shows `[REDACTED:openai-key]`.
5. A `readwrite` token for `vm0` gets `unknown machine ... known machines: vm0`
   for any other machine.
6. Revoking a token makes the next call from an open session fail with 401.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Permission denied (publickey...)` | Key not loaded or not authorized. Test with `ssh -o BatchMode=yes user@host true`. |
| `open failed ... stdio forwarding failed` | Wrong `socket` path, or herdr is not running. |
| `Could not resolve hostname` | Typo in `host`, or the network (for example Tailscale) is down. |
| `request was sent; outcome unknown` | The connection dropped after sending. Run `peek` before retrying a mutation. |
| First character of a command is missing | The new shell showed its own prompt first (for example the oh-my-zsh update prompt). Set `DISABLE_UPDATE_PROMPT=true` in that machine's `.zshrc`. |
| HTTP 401 | Token is wrong, expired, or revoked. Check `arco token list`. |
| Mutating tools are missing | The token has `read` scope. |
