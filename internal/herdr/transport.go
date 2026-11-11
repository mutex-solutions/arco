package herdr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mutex-solutions/arco/internal/registry"
)

type unixDialer struct{}

func (unixDialer) Dial(ctx context.Context, m *registry.Machine) (io.ReadWriteCloser, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", m.Socket())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// SSHDialer dials a remote machine's herdr unix socket using `ssh -W <socket> -- <host>`.
type SSHDialer struct {
	Path string
}

func NewSSHDialer(path string) *SSHDialer {
	if path == "" {
		path = "ssh"
	}
	return &SSHDialer{Path: path}
}

func (d *SSHDialer) Dial(ctx context.Context, m *registry.Machine) (io.ReadWriteCloser, error) {
	host := m.Host()
	if host == "" {
		return nil, fmt.Errorf("empty ssh host")
	}
	if strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("refusing ssh host %q: leading '-' is ssh option injection", host)
	}
	sshPath := d.Path
	if sshPath == "" {
		sshPath = "ssh"
	}

	connectTimeoutSec := int(m.Timeout().Seconds() / 2)
	if connectTimeoutSec < 1 {
		connectTimeoutSec = 1
	}

	args := buildSSHArgs(m.User(), m.Socket(), host, connectTimeoutSec)
	procCtx, cancel := context.WithCancel(ctx)
	cmd := newCmd(procCtx, sshPath, args...)
	cmd.WaitDelay = 2 * time.Second

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ssh stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = stdin.Close()
		return nil, fmt.Errorf("ssh stdout pipe: %w", err)
	}
	stderr := &tailBuf{max: 16 << 10}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("start ssh: %w", err)
	}

	return &procConn{
		stdin:  stdin,
		stdout: stdout,
		cmd:    cmd,
		cancel: cancel,
		stderr: stderr,
	}, nil
}

func buildSSHArgs(user, socket, host string, connectTimeoutSec int) []string {
	if connectTimeoutSec < 1 {
		connectTimeoutSec = 1
	}
	return []string{
		"-T", "-a", "-x", "-e", "none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=" + strconv.Itoa(connectTimeoutSec),
		"-o", "PermitLocalCommand=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-l", user,
		"-W", socket,
		"--", host,
	}
}

var allowedEnvKeys = map[string]bool{
	"HOME":          true,
	"USER":          true,
	"LOGNAME":       true,
	"PATH":          true,
	"SSH_AUTH_SOCK": true,
}

func newCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = scrubEnv(os.Environ())
	return cmd
}

func scrubEnv(environ []string) []string {
	out := make([]string, 0, len(allowedEnvKeys))
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if ok && allowedEnvKeys[k] {
			out = append(out, kv)
		}
	}
	return out
}

// shellQuote renders s as a single POSIX-shell token. Kept for fallback relay
// paths and tested against the injection corpus from the original vm package.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellJoin shell-quotes each token and space-joins them into one command string.
func shellJoin(tokens []string) string {
	q := make([]string, len(tokens))
	for i, t := range tokens {
		q[i] = shellQuote(t)
	}
	return strings.Join(q, " ")
}

// ExportShellQuote exposes shellQuote for injection-corpus tests.
func ExportShellQuote(s string) string { return shellQuote(s) }

// ExportShellJoin exposes shellJoin for injection-corpus tests.
func ExportShellJoin(tokens []string) string { return shellJoin(tokens) }

type procConn struct {
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	stderr    *tailBuf
	closeOnce sync.Once
	waitErr   error
}

func (p *procConn) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *procConn) Write(b []byte) (int, error) { return p.stdin.Write(b) }

func (p *procConn) Close() error {
	p.closeOnce.Do(func() {
		_ = p.stdin.Close()
		_ = p.stdout.Close()
		p.cancel()
		p.waitErr = p.cmd.Wait()
	})
	return p.waitErr
}

func (p *procConn) Diagnostics() (int, string) {
	_ = p.Close()
	exitCode := 0
	if p.waitErr != nil {
		var ee *exec.ExitError
		if errors.As(p.waitErr, &ee) {
			exitCode = ee.ExitCode()
		}
	}
	tail := strings.TrimSpace(p.stderr.String())
	if exitCode == 255 {
		if tail != "" {
			return 255, fmt.Sprintf("ssh exit 255: %s", tail)
		}
		return 255, "ssh exit 255"
	}
	if exitCode != 0 && tail != "" {
		return exitCode, fmt.Sprintf("ssh exit %d: %s", exitCode, tail)
	}
	return exitCode, tail
}

type tailBuf struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.max <= 0 {
		return len(p), nil
	}
	if len(p) >= t.max {
		t.buf = append(t.buf[:0], p[len(p)-t.max:]...)
		return len(p), nil
	}
	if len(t.buf)+len(p) > t.max {
		drop := len(t.buf) + len(p) - t.max
		t.buf = append(t.buf[:0], t.buf[drop:]...)
	}
	t.buf = append(t.buf, p...)
	return len(p), nil
}

func (t *tailBuf) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
