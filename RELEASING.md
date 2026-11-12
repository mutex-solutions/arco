# Releasing

Releases are built by GoReleaser when a version tag is pushed.

## Cut a release

1. Bump `version` in `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`.
   The plugin version is not read from the tag.
2. Validate:

   ```sh
   claude plugin validate .
   goreleaser check
   goreleaser release --snapshot --clean --skip=publish
   ```

3. Tag and push:

   ```sh
   git tag -a v0.1.0 -m "arco v0.1.0"
   git push origin v0.1.0
   ```

`.github/workflows/release.yml` then:

- builds `arco` for linux and darwin, amd64 and arm64,
- publishes `arco_<os>_<arch>.tar.gz` and `checksums.txt` as a GitHub release,
- regenerates `Formula/arco.rb` in `mutex-solutions/homebrew-tap`.

`install.sh` and `brew install mutex-solutions/tap/arco` read from that release.

Windows is not supported: arco needs unix sockets and `flock`.

## Go version

Releases build with the latest stable Go (`go-version: stable`), so binaries
carry current standard library security fixes. `go.mod` states the minimum
Go version for building from source; CI tests both.

## Version

The binary version comes from the tag through `-ldflags -X main.Version`.
Check it after a release:

```sh
arco version
```

## Homebrew tap

The workflow pushes the formula with a write deploy key on
`mutex-solutions/homebrew-tap`, stored in this repository as the secret
`HOMEBREW_TAP_DEPLOY_KEY`. Without the secret the step is skipped and the
release still succeeds.

To update the tap by hand:

```sh
sh scripts/gen-formula.sh 0.1.0 > Formula/arco.rb   # inside a homebrew-tap checkout
```
