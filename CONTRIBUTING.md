# Contributing

## Development

Requires Go 1.25 or later.

```sh
git clone https://github.com/mutex-solutions/arco.git
cd arco
go build -o bin/arco ./cmd/arco
go test -race ./...
```

Tests use an in-process fake herdr and a fake ssh binary. They need no real
machines.

## Pull requests

Before opening a pull request:

- `gofmt -l .` prints nothing.
- `go vet ./...` passes.
- `go test -race ./...` passes.

Project rules:

- Register MCP tools only through `internal/mcp/seam.go`. A test enforces this,
  so every response is scrubbed in one place.
- Never send `focus: true` or call `pane.focus`.
- arco stores no herdr state. Every tool call reads live from herdr.
- Put no secrets in tests. Split synthetic keys across string concatenations
  so the secret scanner does not flag them.

## License

Contributions are licensed under the [Apache License 2.0](LICENSE).
