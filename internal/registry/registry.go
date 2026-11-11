// Package registry loads and validates the machines arco may contact.
package registry

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const DefaultTimeout = 10 * time.Second

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// Duration only accepts TOML duration strings. In particular, an integer can
// never decode into time.Duration's underlying int64 and become nanoseconds.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("must be a duration string such as \"10s\": %w", err)
	}
	d.Duration = v
	return nil
}

// Machine is immutable after construction. Use NewMachine rather than a literal.
type Machine struct {
	id        string
	transport string
	host      string
	user      string
	socket    string
	timeout   time.Duration
}

func (m *Machine) ID() string             { return m.id }
func (m *Machine) Transport() string      { return m.transport }
func (m *Machine) Host() string           { return m.host }
func (m *Machine) User() string           { return m.user }
func (m *Machine) Socket() string         { return m.socket }
func (m *Machine) Timeout() time.Duration { return m.timeout }

// Target describes the endpoint for honest, human-readable errors.
func (m *Machine) Target() string {
	if m.transport == "ssh" {
		return m.user + "@" + m.host + ":" + m.socket
	}
	return m.socket
}

// NewMachine validates every field that can reach a socket path or ssh argv.
func NewMachine(id, transport, host, user, socket string, timeout time.Duration) (*Machine, error) {
	if !idPattern.MatchString(id) {
		return nil, fmt.Errorf("invalid id %q: must match %s", id, idPattern)
	}
	if transport != "unix" && transport != "ssh" {
		return nil, fmt.Errorf("machine %q: transport must be unix or ssh, got %q", id, transport)
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return nil, fmt.Errorf("machine %q: timeout must be between 1s and 5m, got %s", id, timeout)
	}
	if socket == "" {
		return nil, fmt.Errorf("machine %q: socket is required", id)
	}
	if transport == "unix" {
		if host != "" || user != "" {
			return nil, fmt.Errorf("machine %q: host and user are only valid for ssh transport", id)
		}
		var err error
		socket, err = expandHome(socket)
		if err != nil {
			return nil, fmt.Errorf("machine %q: %w", id, err)
		}
	} else {
		if host == "" || user == "" {
			return nil, fmt.Errorf("machine %q: ssh requires host and user", id)
		}
		if strings.HasPrefix(host, "-") || (!hostPattern.MatchString(host) && !isIP(host)) {
			return nil, fmt.Errorf("machine %q: invalid ssh host %q", id, host)
		}
		if !userPattern.MatchString(user) {
			return nil, fmt.Errorf("machine %q: invalid ssh user %q", id, user)
		}
		if strings.Contains(socket, "~") {
			return nil, fmt.Errorf("machine %q: remote socket must not contain ~", id)
		}
	}
	if !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("machine %q: socket must be absolute after expansion, got %q", id, socket)
	}
	// Leave room for the NUL terminator on platforms with a 104-byte sun_path.
	if len(socket) >= 104 {
		return nil, fmt.Errorf("machine %q: socket path is too long (%d bytes; maximum 103)", id, len(socket))
	}
	return &Machine{id: id, transport: transport, host: host, user: user, socket: socket, timeout: timeout}, nil
}

// isIP accepts literal addresses only. IPv6 zones are rejected: netip allows
// any bytes there, and ssh splits "fe80::1%x@evil" on '@' into a different host.
func isIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Zone() == ""
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand socket home: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~/")), nil
	}
	if strings.Contains(p, "~") {
		return "", fmt.Errorf("socket may only use ~ at the start")
	}
	return p, nil
}

// Registry is an immutable, ordered machine snapshot.
type Registry struct {
	machines []*Machine
	byID     map[string]*Machine
}

func (r *Registry) Machines() []*Machine {
	return append([]*Machine(nil), r.machines...)
}

// ValidID reports whether id is a well-formed machine id.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Filter returns the machines named in allowed, in registry order. "*" alone
// means every machine. Unknown ids are dropped, so an allowlist that names no
// registered machine yields an empty registry; it never widens to "all".
func (r *Registry) Filter(allowed []string) *Registry {
	out := &Registry{byID: make(map[string]*Machine)}
	all := len(allowed) == 1 && allowed[0] == "*"
	want := make(map[string]bool, len(allowed))
	for _, id := range allowed {
		want[id] = true
	}
	for _, m := range r.machines {
		if all || want[m.id] {
			out.machines = append(out.machines, m)
			out.byID[m.id] = m
		}
	}
	return out
}

func (r *Registry) Resolve(id string) (*Machine, error) {
	if m, ok := r.byID[id]; ok {
		return m, nil
	}
	ids := make([]string, len(r.machines))
	for i, m := range r.machines {
		ids[i] = m.id
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("unknown machine %q; no machines are available", id)
	}
	return nil, fmt.Errorf("unknown machine %q; known machines: %s", id, strings.Join(ids, ", "))
}

type rawRegistry struct {
	Machines []rawMachine `toml:"machine"`
	MCP      struct{}     `toml:"mcp"`
}

type rawMachine struct {
	ID        string    `toml:"id"`
	Transport string    `toml:"transport"`
	Host      string    `toml:"host"`
	User      string    `toml:"user"`
	Socket    string    `toml:"socket"`
	Timeout   *Duration `toml:"timeout"`
}

// Load reads path, or ARCO_MACHINES, or ~/.arco/machines.toml when path is empty.
func Load(path string) (*Registry, error) {
	if path == "" {
		path = os.Getenv("ARCO_MACHINES")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find home directory: %w", err)
		}
		path = filepath.Join(home, ".arco", "machines.toml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read registry %s: %w", path, err)
	}
	var raw rawRegistry
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse registry %s: %w", path, err)
	}
	r := &Registry{byID: make(map[string]*Machine, len(raw.Machines))}
	for i, in := range raw.Machines {
		var timeout time.Duration
		if in.Timeout != nil {
			timeout = in.Timeout.Duration
		}
		m, err := NewMachine(in.ID, in.Transport, in.Host, in.User, in.Socket, timeout)
		if err != nil {
			return nil, fmt.Errorf("registry entry %d: %w", i+1, err)
		}
		if previous := r.byID[m.id]; previous != nil {
			return nil, fmt.Errorf("duplicate machine id %q at entry %d", m.id, i+1)
		}
		r.machines = append(r.machines, m)
		r.byID[m.id] = m
	}
	return r, nil
}
