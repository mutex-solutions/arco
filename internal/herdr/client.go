// Package herdr implements arco's stateless protocol-22 client.
package herdr

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mutex-solutions/arco/internal/registry"
)

const maxFrameBytes = 8 << 20

// Dialer opens one bidirectional NDJSON stream. Every Call uses a fresh stream.
type Dialer interface {
	Dial(ctx context.Context, m *registry.Machine) (io.ReadWriteCloser, error)
}

// RPCError is herdr's structured error body.
type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	if e.Code == "method_not_found" || strings.Contains(strings.ToLower(e.Message), "unknown method") {
		return fmt.Sprintf("%s: %s (possible herdr protocol/version mismatch; expected protocol >= 22)", e.Code, e.Message)
	}
	return e.Code + ": " + e.Message
}

// Error preserves the distinction between an unapplied request and a mutation
// whose result was lost after delivery.
//
// Error() is public text. It names the machine id and never how arco reaches
// it: raw ssh stderr is replaced by a fixed summary, and the socket path, IP
// addresses, user@host pairs, and home directories are masked in the cause.
// Detail() keeps everything, for the operator's own terminal.
type Error struct {
	Machine string
	Method  string
	Stage   string // dial | write | read | remote | protocol
	Sent    bool
	Target  string
	Err     error
	Remote  *RPCError

	public string // cause for Error(); empty means a masked Err
	socket string // masked in Error()
}

func (e *Error) Error() string  { return e.format(false) }
func (e *Error) Detail() string { return e.format(true) }

func (e *Error) format(detail bool) string {
	machine := fmt.Sprintf("machine %q", e.Machine)
	if detail && e.Target != "" {
		machine += " (" + e.Target + ")"
	}
	prefix := fmt.Sprintf("%s: %s: %s", machine, e.Method, e.Stage)
	var cause string
	switch {
	case e.Remote != nil:
		cause = e.Remote.Error()
	case !detail && e.public != "":
		cause = e.public
	case e.Err != nil:
		cause = e.Err.Error()
	default:
		cause = "unknown error"
	}
	if !detail {
		cause = maskCause(cause, e.socket)
	}
	if e.Remote != nil {
		return prefix + ": " + cause
	}
	if e.Sent && isMutation(e.Method) {
		return prefix + ": " + cause + " (request was sent; outcome unknown)"
	}
	if !e.Sent {
		return prefix + ": " + cause + " (request was not sent)"
	}
	return prefix + ": " + cause
}

var (
	userAtHostRe = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_.-]*@[A-Za-z0-9.:\[\]%-]+`)
	connectToRe  = regexp.MustCompile(`connect to host \S+ port \d+`)
	homeDirRe    = regexp.MustCompile(`(?:/home|/Users)/[^/\s:'"]+`)
	ipv4Re       = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Re       = regexp.MustCompile(`\[?\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\]?|\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b`)
)

// maskCause is a backstop for cause text that is not an ssh summary (unix
// dial errors, herdr messages).
func maskCause(s, socket string) string {
	if socket != "" {
		s = strings.ReplaceAll(s, socket, "<socket>")
	}
	s = connectToRe.ReplaceAllString(s, "connect to host <host> port <port>")
	s = userAtHostRe.ReplaceAllString(s, "<user>@<host>")
	s = homeDirRe.ReplaceAllString(s, "<home>")
	s = ipv4Re.ReplaceAllString(s, "<ip>")
	return ipv6Re.ReplaceAllString(s, "<ip>")
}

// sshSummary maps ssh's stderr to a fixed cause. Raw stderr can name the
// resolved hostname, the user, and paths under the operator's home directory,
// so it never reaches Error(); `arco machines` prints it in full.
func sshSummary(code int, diag string) string {
	lower := strings.ToLower(diag)
	has := func(subs ...string) bool {
		for _, sub := range subs {
			if strings.Contains(lower, sub) {
				return true
			}
		}
		return false
	}
	switch {
	case has("could not resolve hostname"):
		return "ssh: could not resolve the host"
	case has("ssh: connect to host") && has("timed out"):
		return "ssh: connection timed out"
	case has("ssh: connect to host") && has("refused"):
		return "ssh: connection refused"
	case has("ssh: connect to host"):
		return "ssh: could not connect"
	case has("host key verification failed", "remote host identification has changed"):
		return "ssh: host key verification failed"
	case has("permission denied ("):
		return "ssh: authentication failed"
	case has("stdio forwarding failed", "channel 0: open failed"):
		return "ssh: could not open the herdr socket (is herdr running?)"
	case has("kex_exchange_identification"):
		return "ssh: connection closed during handshake"
	case has("timeout, server"):
		return "ssh: server stopped responding"
	case has("read from remote host", "client_loop", "shared connection", "broken pipe", "connection reset", "closed by remote host"):
		return "ssh: connection lost"
	case code != 0:
		return fmt.Sprintf("ssh exited with code %d; run `arco machines` for details", code)
	default:
		return "ssh: unexpected output; run `arco machines` for details"
	}
}

func (e *Error) Unwrap() error { return e.Err }

type protocolError struct{ msg string }

func (e *protocolError) Error() string { return e.msg }

var errRequestWritten = errors.New("request written")

// Client owns no herdr state. Its semaphores only bound per-machine concurrency.
type Client struct {
	unix Dialer
	ssh  Dialer
	sem  map[string]chan struct{}
}

func NewClient(reg *registry.Registry) *Client {
	return NewClientWithDialers(reg, unixDialer{}, NewSSHDialer("ssh"))
}

func NewClientWithDialers(reg *registry.Registry, unix, ssh Dialer) *Client {
	if unix == nil {
		unix = unixDialer{}
	}
	if ssh == nil {
		ssh = NewSSHDialer("ssh")
	}
	c := &Client{unix: unix, ssh: ssh, sem: make(map[string]chan struct{})}
	if reg != nil {
		for _, m := range reg.Machines() {
			c.sem[m.ID()] = make(chan struct{}, 4)
		}
	}
	return c
}

// Call performs one request/response on a fresh stream. extra extends the
// machine timeout only for herdr methods that intentionally block server-side.
func (c *Client) Call(ctx context.Context, m *registry.Machine, method string, params any, extra time.Duration) (json.RawMessage, error) {
	sem := c.sem[m.ID()]
	if sem == nil {
		return nil, &Error{
			Machine: m.ID(),
			Method:  method,
			Stage:   "dial",
			Sent:    false,
			Target:  m.Target(),
			socket:  m.Socket(),
			Err:     fmt.Errorf("machine is not in this client registry"),
		}
	}
	limitCtx, cancelLimit := context.WithTimeout(ctx, m.Timeout())
	select {
	case sem <- struct{}{}:
		cancelLimit()
		defer func() { <-sem }()
	case <-limitCtx.Done():
		cancelLimit()
		return nil, &Error{
			Machine: m.ID(),
			Method:  method,
			Stage:   "dial",
			Sent:    false,
			Target:  m.Target(),
			socket:  m.Socket(),
			Err:     fmt.Errorf("waited on per-machine concurrency limit 4: %w", limitCtx.Err()),
		}
	}

	budget := m.Timeout() + extra
	callCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var d Dialer
	switch m.Transport() {
	case "unix":
		d = c.unix
	case "ssh":
		d = c.ssh
	default:
		return nil, &Error{
			Machine: m.ID(),
			Method:  method,
			Stage:   "dial",
			Sent:    false,
			Target:  m.Target(),
			socket:  m.Socket(),
			Err:     fmt.Errorf("unsupported transport %q", m.Transport()),
		}
	}

	conn, err := d.Dial(callCtx, m)
	if err != nil {
		return nil, &Error{
			Machine: m.ID(),
			Method:  method,
			Stage:   "dial",
			Sent:    false,
			Target:  m.Target(),
			socket:  m.Socket(),
			Err:     err,
		}
	}
	defer func() { _ = conn.Close() }()

	stop := context.AfterFunc(callCtx, func() { _ = conn.Close() })
	defer stop()

	if nc, ok := conn.(net.Conn); ok {
		if dl, ok := callCtx.Deadline(); ok {
			_ = nc.SetDeadline(dl)
		}
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64<<10), maxFrameBytes)

	if params == nil {
		params = struct{}{}
	}
	res, sawBytes, err := roundTrip(callCtx, conn, scanner, "arco-1", method, params)
	if err != nil {
		_ = conn.Close()
		return nil, c.classifyError(callCtx, m, method, budget, conn, sawBytes, err)
	}
	return res, nil
}

func (c *Client) classifyError(callCtx context.Context, m *registry.Machine, method string, budget time.Duration, conn io.Closer, sawBytes bool, err error) error {
	sent := errors.Is(err, errRequestWritten)

	var rpc *RPCError
	if errors.As(err, &rpc) {
		return &Error{
			Machine: m.ID(),
			Method:  method,
			Stage:   "remote",
			Sent:    sent,
			Target:  m.Target(),
			socket:  m.Socket(),
			Remote:  rpc,
		}
	}

	var proto *protocolError
	if errors.As(err, &proto) {
		return &Error{
			Machine: m.ID(),
			Method:  method,
			Stage:   "protocol",
			Sent:    sent,
			Target:  m.Target(),
			socket:  m.Socket(),
			Err:     proto,
		}
	}

	// If conn is an ssh procConn, inspect its exit code and stderr tail after Close.
	var sshDiag string
	var sshCode int
	if dc, ok := conn.(diagConn); ok {
		code, diag := dc.Diagnostics()
		// Writing into ssh's stdin pipe does not mean the request reached the
		// remote socket. Only a recognized pre-forward failure (connect, auth,
		// host key, -W setup) proves it did not. Anything else, including an
		// empty stderr under LogLevel QUIET or a keepalive timeout, stays
		// "sent; outcome unknown", because a false "not sent" invites a retry
		// that types the text twice.
		if code == 255 && !sawBytes && isSSHPreForwardFailure(diag) {
			return &Error{
				Machine: m.ID(),
				Method:  method,
				Stage:   "dial",
				Sent:    false,
				Target:  m.Target(),
				socket:  m.Socket(),
				Err:     fmt.Errorf("ssh exit 255 before forwarding the request (%s)", diag),
				public:  sshSummary(code, diag),
			}
		}
		if diag != "" || code != 0 {
			sshDiag, sshCode = diag, code
		}
	}

	stage := "dial"
	if sent {
		stage = "read"
	} else if strings.Contains(err.Error(), "write request") {
		stage = "write"
	}

	// The socket deadline and the context share one instant; whichever fires
	// first, report it as the timeout it is.
	switch {
	case errors.Is(callCtx.Err(), context.Canceled):
		err = fmt.Errorf("cancelled: %w", callCtx.Err())
	case callCtx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded):
		err = fmt.Errorf("timed out after %s: %w", budget, context.DeadlineExceeded)
	}

	out := &Error{
		Machine: m.ID(),
		Method:  method,
		Stage:   stage,
		Sent:    sent,
		Target:  m.Target(),
		socket:  m.Socket(),
		Err:     err,
	}
	if sshDiag != "" || sshCode != 0 {
		if sshDiag == "" {
			sshDiag = fmt.Sprintf("ssh exit %d", sshCode)
		}
		out.Err = fmt.Errorf("%w (%s)", err, sshDiag)
		out.public = err.Error() + " (" + sshSummary(sshCode, sshDiag) + ")"
	}
	return out
}

type diagConn interface {
	Diagnostics() (exitCode int, detail string)
}

func encodeRequest(id, method string, params any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params"`
	}{
		ID:     id,
		Method: method,
		Params: params,
	})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return buf.Bytes(), nil
}

func roundTrip(ctx context.Context, w io.Writer, scanner *bufio.Scanner, id, method string, params any) (json.RawMessage, bool, error) {
	frame, err := encodeRequest(id, method, params)
	if err != nil {
		return nil, false, err
	}
	written := 0
	for written < len(frame) {
		n, err := w.Write(frame[written:])
		written += n
		if err != nil {
			if written > 0 {
				return nil, false, fmt.Errorf("%w: write request: %v", errRequestWritten, err)
			}
			return nil, false, fmt.Errorf("write request: %w", err)
		}
	}

	sawBytes := false
	for scanner.Scan() {
		sawBytes = true
		line := scanner.Bytes()
		var f struct {
			ID     *string         `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *RPCError       `json:"error"`
		}
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, sawBytes, fmt.Errorf("%w: %w", errRequestWritten, &protocolError{msg: fmt.Sprintf("malformed response frame: %v", err)})
		}
		if f.ID == nil {
			// Push frame ({event, data}) with no id: skip.
			continue
		}
		if *f.ID != id {
			return nil, sawBytes, fmt.Errorf("%w: %w", errRequestWritten, &protocolError{msg: fmt.Sprintf("unexpected response id %q (wanted %q)", *f.ID, id)})
		}
		if f.Error != nil {
			return nil, sawBytes, fmt.Errorf("%w: %w", errRequestWritten, f.Error)
		}
		if len(f.Result) == 0 || string(f.Result) == "null" {
			return nil, sawBytes, fmt.Errorf("%w: %w", errRequestWritten, &protocolError{msg: "response has neither result nor error"})
		}
		return append(json.RawMessage(nil), f.Result...), sawBytes, nil
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return nil, sawBytes, fmt.Errorf("%w: read response: %v", errRequestWritten, ctx.Err())
		}
		if errors.Is(err, bufio.ErrTooLong) || strings.Contains(err.Error(), "token too long") {
			return nil, sawBytes, fmt.Errorf("%w: %w", errRequestWritten, &protocolError{msg: "response frame exceeded 8 MiB"})
		}
		return nil, sawBytes, fmt.Errorf("%w: read response: %w", errRequestWritten, err)
	}
	return nil, sawBytes, fmt.Errorf("%w: connection closed before response", errRequestWritten)
}

func isMutation(method string) bool {
	switch method {
	case "pane.send_text", "agent.prompt", "workspace.create", "agent.start", "pane.close", "workspace.close":
		return true
	default:
		return false
	}
}

// isSSHPreForwardFailure reports whether ssh's stderr proves it failed before
// the -W forward carried any request bytes to the remote socket. Signatures are
// the connect/auth/channel-open forms only: the bare errno text ("Connection
// timed out", "No route to host") also appears mid-session as "Read from
// remote host …", after the request may have been delivered.
func isSSHPreForwardFailure(diag string) bool {
	lower := strings.ToLower(diag)
	for _, sig := range []string{
		"read from remote host",
		"write failed",
		"client_loop",
		"timeout, server",
		"shared connection",
	} {
		if strings.Contains(lower, sig) {
			return false
		}
	}
	for _, sig := range []string{
		"ssh: connect to host",
		"could not resolve hostname",
		"permission denied (",
		"host key verification failed",
		"kex_exchange_identification",
		"channel 0: open failed",
		"stdio forwarding failed",
	} {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}
