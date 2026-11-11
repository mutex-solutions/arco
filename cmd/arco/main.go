package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"unicode"

	"github.com/mutex-solutions/arco/internal/herdr"
	"github.com/mutex-solutions/arco/internal/mcp"
	"github.com/mutex-solutions/arco/internal/redact"
	"github.com/mutex-solutions/arco/internal/registry"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = ""

func currentVersion() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil)
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.ReadCloser, stdout io.WriteCloser, stderr io.Writer, sshDialer herdr.Dialer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "arco %s\n", currentVersion())
		return 0

	case "machines":
		fs := flag.NewFlagSet("arco machines", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var machinesPath string
		fs.StringVar(&machinesPath, "machines", "", "path to machines.toml (overrides ARCO_MACHINES)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			_, _ = fmt.Fprintf(stderr, "arco machines: unexpected arguments: %v\n", fs.Args())
			return 2
		}
		reg, err := registry.Load(machinesPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "arco machines: %s\n", sanitizeTerm(err.Error()))
			return 1
		}
		client := herdr.NewClientWithDialers(reg, nil, sshDialer)
		statuses := client.ProbeMachines(ctx, reg)
		okCount := 0
		for _, st := range statuses {
			if st.OK {
				okCount++
				line := fmt.Sprintf("%s\t%s\t%s\tok\therdr=%s\tprotocol=%d",
					st.ID,
					st.Transport,
					st.Target,
					sanitizeTerm(st.Version),
					st.Protocol,
				)
				if st.Warning != "" {
					line += "\twarn=" + sanitizeTerm(st.Warning)
				}
				_, _ = fmt.Fprintln(stdout, line)
			} else {
				_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\terr\t%s\n",
					st.ID,
					st.Transport,
					st.Target,
					sanitizeTerm(st.CauseDetail),
				)
			}
		}
		_, _ = fmt.Fprintf(stdout, "%d/%d ok\n", okCount, len(statuses))
		if okCount < len(statuses) {
			return 1
		}
		return 0

	case "mcp":
		if len(args) < 2 || args[1] != "serve" {
			_, _ = fmt.Fprintln(stderr, "usage: arco mcp serve [--machines <path>]")
			return 2
		}
		fs := flag.NewFlagSet("arco mcp serve", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var machinesPath string
		fs.StringVar(&machinesPath, "machines", "", "path to machines.toml (overrides ARCO_MACHINES)")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			_, _ = fmt.Fprintf(stderr, "arco mcp serve: unexpected arguments: %v\n", fs.Args())
			return 2
		}
		reg, err := registry.Load(machinesPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "arco mcp serve: %s\n", sanitizeTerm(err.Error()))
			return 1
		}
		client := herdr.NewClientWithDialers(reg, nil, sshDialer)
		srv := mcp.NewMCPServer(reg, client, currentVersion())

		var serveErr error
		if stdin == os.Stdin && stdout == os.Stdout {
			serveErr = mcp.ServeStdio(ctx, srv)
		} else {
			serveErr = mcp.ServeIO(ctx, srv, stdin, stdout)
		}
		if serveErr != nil && !errors.Is(serveErr, context.Canceled) && !errors.Is(serveErr, io.EOF) {
			_, _ = fmt.Fprintf(stderr, "arco mcp serve: %s\n", sanitizeTerm(serveErr.Error()))
			return 1
		}
		return 0

	case "serve":
		return runServe(ctx, args[1:], stdout, stderr, sshDialer)

	case "token":
		return runToken(args[1:], stdout, stderr)

	case "help", "--help", "-h":
		printUsage(stdout)
		return 0

	default:
		_, _ = fmt.Fprintf(stderr, "arco: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  arco mcp serve [--machines <path>]                   Run the stdio MCP server")
	_, _ = fmt.Fprintln(w, "  arco serve --http <addr> [--machines] [--tokens]     Run the token-authenticated HTTP MCP server")
	_, _ = fmt.Fprintln(w, "  arco token create|list|revoke                        Manage scoped HTTP tokens (arco token for help)")
	_, _ = fmt.Fprintln(w, "  arco machines [--machines <path>]                    Probe reachability of registered machines")
	_, _ = fmt.Fprintln(w, "  arco version                                         Print version")
}

// sanitizeTerm scrubs secrets and strips terminal control characters before
// printing untrusted remote strings to an operator's terminal.
func sanitizeTerm(s string) string {
	scrubbed, _ := redact.New().Scrub(s)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, scrubbed)
}
