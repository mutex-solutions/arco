package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mutex-solutions/arco/internal/auth"
	"github.com/mutex-solutions/arco/internal/herdr"
	"github.com/mutex-solutions/arco/internal/mcp"
	"github.com/mutex-solutions/arco/internal/registry"
)

const tokenUsage = `usage:
  arco token create --name <name> [--scope read|readwrite] [--machines <ids|*>] [--ttl <dur>] [--json]
  arco token list [--json]
  arco token revoke <name|id>
common flags: --tokens <path> (default $ARCO_TOKENS or ~/.arco/tokens.json)
              --registry <path> (machines.toml used to check --machines; default $ARCO_MACHINES or ~/.arco/machines.toml)`

func runToken(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, tokenUsage)
		return 2
	}
	switch args[0] {
	case "create":
		return tokenCreate(args[1:], stdout, stderr)
	case "list", "ls":
		return tokenList(args[1:], stdout, stderr)
	case "revoke", "rm":
		return tokenRevoke(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "arco token: unknown subcommand %q\n%s\n", args[0], tokenUsage)
		return 2
	}
}

func tokenCreate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("arco token create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "token name (lowercase letters, digits, '-', '_')")
	scope := fs.String("scope", auth.ScopeRead, "read or readwrite")
	machines := fs.String("machines", "", `comma-separated machine ids, or "*" for all (required for readwrite)`)
	ttl := fs.String("ttl", "", "lifetime, e.g. 12h or 30d (read: none by default; readwrite: 30d default, 90d max)")
	tokensPath := fs.String("tokens", "", "token file path")
	registryPath := fs.String("registry", "", "machines.toml used to check --machines")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "arco token create: unexpected arguments: %v\n", fs.Args())
		return 2
	}
	if *name == "" {
		_, _ = fmt.Fprintln(stderr, "arco token create: --name is required")
		return 2
	}
	if *machines == "" {
		if *scope == auth.ScopeReadWrite {
			_, _ = fmt.Fprintln(stderr, `arco token create: readwrite tokens need an explicit --machines (ids, or "*" if you really mean every machine)`)
			return 2
		}
		*machines = "*"
	}
	ids := splitList(*machines)
	d, err := parseTTL(*ttl)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token create: %v\n", err)
		return 2
	}

	// Every machine id must exist in the registry the server will use.
	reg, err := registry.Load(*registryPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token create: cannot check machine ids: %s (pass --registry)\n", sanitizeTerm(err.Error()))
		return 1
	}
	for _, id := range ids {
		if id == "*" {
			continue
		}
		if _, err := reg.Resolve(id); err != nil {
			_, _ = fmt.Fprintf(stderr, "arco token create: %s\n", sanitizeTerm(err.Error()))
			return 1
		}
	}

	store, err := auth.Open(*tokensPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token create: %v\n", err)
		return 1
	}
	raw, rec, err := store.Create(auth.CreateOptions{Name: *name, Scope: *scope, Machines: ids, TTL: d})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token create: %v\n", err)
		return 1
	}

	if *asJSON {
		out := struct {
			publicRecord
			Token string `json:"token"`
		}{toPublic(rec), raw}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 0, 1, ' ', 0)
		_, _ = fmt.Fprintf(tw, "id:\t%s\n", rec.ID)
		_, _ = fmt.Fprintf(tw, "name:\t%s\n", rec.Name)
		_, _ = fmt.Fprintf(tw, "scope:\t%s\n", rec.Scope)
		_, _ = fmt.Fprintf(tw, "machines:\t%s\n", auth.MachinesLabel(rec.Machines))
		_, _ = fmt.Fprintf(tw, "expires:\t%s\n", expiresLabel(rec))
		_, _ = fmt.Fprintf(tw, "token:\t%s\n", raw)
		_, _ = fmt.Fprintf(tw, "header:\tAuthorization: Bearer %s\n", raw)
		_ = tw.Flush()
	}
	_, _ = fmt.Fprintf(stderr, "\nStored in %s. The token is shown once and cannot be recovered.\n", store.Path())
	if rec.Scope == auth.ScopeReadWrite {
		_, _ = fmt.Fprintln(stderr, "This is a readwrite token: it can type into panes and start agents on its machines.")
	}
	return 0
}

func tokenList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("arco token list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokensPath := fs.String("tokens", "", "token file path")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "arco token list: unexpected arguments: %v\n", fs.Args())
		return 2
	}
	store, err := auth.Open(*tokensPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token list: %v\n", err)
		return 1
	}
	recs, err := store.List()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token list: %v\n", err)
		return 1
	}
	if *asJSON {
		out := make([]publicRecord, 0, len(recs))
		for _, r := range recs {
			out = append(out, toPublic(r))
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}
	if len(recs) == 0 {
		_, _ = fmt.Fprintf(stderr, "no tokens in %s\n", store.Path())
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tSCOPE\tMACHINES\tEXPIRES\tSTATUS\tPREVIEW")
	now := time.Now()
	for _, r := range recs {
		status := "active"
		if r.Expired(now) {
			status = "expired"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Scope, auth.MachinesLabel(r.Machines), expiresLabel(r), status, r.Preview)
	}
	_ = tw.Flush()
	return 0
}

func tokenRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("arco token revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokensPath := fs.String("tokens", "", "token file path")
	// Accept the name before or after the flags.
	var target string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if target == "" && fs.NArg() == 1 {
		target = fs.Arg(0)
	} else if fs.NArg() != 0 {
		target = ""
	}
	if target == "" {
		_, _ = fmt.Fprintln(stderr, "usage: arco token revoke <name|id> [--tokens <path>]")
		return 2
	}
	store, err := auth.Open(*tokensPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token revoke: %v\n", err)
		return 1
	}
	rec, err := store.Revoke(target)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco token revoke: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "revoked %s (%s)\n", rec.Name, rec.ID)
	return 0
}

// publicRecord is a Record without its hash.
type publicRecord struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Preview   string     `json:"preview"`
	Scope     string     `json:"scope"`
	Machines  []string   `json:"machines"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func toPublic(r auth.Record) publicRecord {
	return publicRecord{r.ID, r.Name, r.Preview, r.Scope, r.Machines, r.CreatedAt, r.ExpiresAt}
}

func expiresLabel(r auth.Record) string {
	if r.ExpiresAt == nil {
		return "never"
	}
	return r.ExpiresAt.Local().Format(time.RFC3339)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTTL accepts Go durations plus a whole-day suffix ("30d").
func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid --ttl %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid --ttl %q (use e.g. 12h or 30d)", s)
	}
	return d, nil
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer, sshDialer herdr.Dialer) int {
	fs := flag.NewFlagSet("arco serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("http", "", "listen address for the HTTP MCP endpoint, e.g. 127.0.0.1:8080 (required)")
	machinesPath := fs.String("machines", "", "path to machines.toml (overrides ARCO_MACHINES)")
	tokensPath := fs.String("tokens", "", "token file path (overrides ARCO_TOKENS)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *addr == "" {
		_, _ = fmt.Fprintln(stderr, "usage: arco serve --http <addr> [--machines <path>] [--tokens <path>]")
		return 2
	}
	reg, err := registry.Load(*machinesPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco serve: %s\n", sanitizeTerm(err.Error()))
		return 1
	}
	store, err := auth.Open(*tokensPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco serve: %v\n", err)
		return 1
	}
	recs, err := store.List()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco serve: %v\n", err)
		return 1
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "arco serve: %v\n", err)
		return 1
	}
	if !isPrivateListener(ln.Addr()) {
		_, _ = fmt.Fprintf(stderr, "warning: %s is not a loopback or private address. arco is meant for private networks; do not expose it to the internet.\n", ln.Addr())
	}
	h := mcp.NewHTTPHandler(mcp.HTTPOptions{
		Registry: reg,
		Client:   herdr.NewClientWithDialers(reg, nil, sshDialer),
		Tokens:   store,
		Version:  currentVersion(),
		Log:      stderr,
	})
	srv := mcp.NewHTTPServer(*addr, h)
	_, _ = fmt.Fprintf(stdout, "arco serve: MCP at http://%s/mcp (%d machines, %d tokens in %s)\n", ln.Addr(), len(reg.Machines()), len(recs), store.Path())
	if len(recs) == 0 {
		_, _ = fmt.Fprintln(stderr, "note: no tokens yet; every request will get 401. Create one with: arco token create --name <name>")
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			_, _ = fmt.Fprintf(stderr, "arco serve: %v\n", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return 0
	}
}

// isPrivateListener reports whether a listener is bound to loopback, a
// private range (RFC 1918, ULA), or Tailscale's CGNAT range. An unspecified
// address (0.0.0.0, ::) listens everywhere and is not private.
func isPrivateListener(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
