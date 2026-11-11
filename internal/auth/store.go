// Package auth is arco's scoped bearer-token store for the HTTP MCP endpoint.
//
// Raw tokens are shown once and never written: the store keeps a SHA-256 hash,
// a scope, a machine allowlist, and an optional expiry. Records are immutable
// (create and revoke are the only writes), and every write happens under an
// exclusive flock on <file>.lock followed by an atomic rename, so the CLI and a
// running server can share one file. Readers re-stat the file on every
// Authenticate and reload when it changed, so revocation is immediate.
package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mutex-solutions/arco/internal/registry"
)

// Scopes. Read exposes the inspection tools; readwrite adds the mutating ones.
const (
	ScopeRead      = "read"
	ScopeReadWrite = "readwrite"
)

const (
	// DefaultReadWriteTTL applies when a readwrite token is created without a TTL.
	DefaultReadWriteTTL = 30 * 24 * time.Hour
	// MaxReadWriteTTL caps readwrite tokens; read tokens may be open-ended.
	MaxReadWriteTTL = 90 * 24 * time.Hour

	fileVersion = 1
	secretBytes = 32 // 43 base64url characters
)

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	tokenPattern = regexp.MustCompile(`^arco_r[ow]_[A-Za-z0-9_-]{43}$`)
)

// ErrUnauthorized is returned for every authentication failure: unknown,
// malformed, revoked, and expired tokens are indistinguishable to the caller.
var ErrUnauthorized = errors.New("unauthorized")

// Record is one stored token. It never contains the raw token.
type Record struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Preview   string     `json:"preview"`
	Hash      string     `json:"hash"`
	Scope     string     `json:"scope"`
	Machines  []string   `json:"machines"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ReadOnly reports whether the token may only use inspection tools.
func (r Record) ReadOnly() bool { return r.Scope != ScopeReadWrite }

// Expired reports whether the token is past its expiry at now.
func (r Record) Expired(now time.Time) bool {
	return r.ExpiresAt != nil && !now.Before(*r.ExpiresAt)
}

// CreateOptions describes a new token.
type CreateOptions struct {
	Name     string
	Scope    string
	Machines []string      // ["*"] or explicit machine ids; never empty
	TTL      time.Duration // 0: read → no expiry, readwrite → DefaultReadWriteTTL
}

type file struct {
	Version int      `json:"version"`
	Tokens  []Record `json:"tokens"`
}

// Store is a token file. Safe for concurrent use within and across processes.
type Store struct {
	path string
	now  func() time.Time

	mu     sync.Mutex
	stat   os.FileInfo
	tokens []Record
}

// DefaultPath resolves the token file: explicit path, then ARCO_TOKENS, then
// ~/.arco/tokens.json.
func DefaultPath(path string) (string, error) {
	if path == "" {
		path = os.Getenv("ARCO_TOKENS")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find home directory: %w", err)
		}
		path = filepath.Join(home, ".arco", "tokens.json")
	}
	return filepath.Abs(path)
}

// Open returns a Store for path. A missing file is an empty store; it is
// created on the first write.
func Open(path string) (*Store, error) {
	p, err := DefaultPath(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: p, now: time.Now}, nil
}

// Path is the resolved token file path.
func (s *Store) Path() string { return s.path }

// Create stores a new token and returns its raw value, which is not
// recoverable afterwards.
func (s *Store) Create(opts CreateOptions) (string, Record, error) {
	rec, err := s.validate(opts)
	if err != nil {
		return "", Record{}, err
	}
	prefix := "arco_ro_"
	if rec.Scope == ScopeReadWrite {
		prefix = "arco_rw_"
	}
	secret := make([]byte, secretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", Record{}, fmt.Errorf("generate token: %w", err)
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(secret)
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return "", Record{}, fmt.Errorf("generate token id: %w", err)
	}
	rec.ID = "tok_" + hex.EncodeToString(idBytes)
	rec.Hash = hashToken(raw)
	rec.Preview = raw[:len(prefix)+4] + "…" + raw[len(raw)-4:]

	err = s.update(func(f *file) error {
		for _, t := range f.Tokens {
			if t.Name == rec.Name {
				return fmt.Errorf("a token named %q already exists (revoke it first)", rec.Name)
			}
		}
		f.Tokens = append(f.Tokens, rec)
		return nil
	})
	if err != nil {
		return "", Record{}, err
	}
	return raw, rec, nil
}

func (s *Store) validate(opts CreateOptions) (Record, error) {
	if !namePattern.MatchString(opts.Name) {
		return Record{}, fmt.Errorf("invalid token name %q (lowercase letters, digits, '-', '_'; up to 64)", opts.Name)
	}
	if strings.HasPrefix(opts.Name, "tok_") {
		return Record{}, fmt.Errorf("invalid token name %q: the tok_ prefix is reserved for token ids", opts.Name)
	}
	if opts.Scope != ScopeRead && opts.Scope != ScopeReadWrite {
		return Record{}, fmt.Errorf("invalid scope %q (want %q or %q)", opts.Scope, ScopeRead, ScopeReadWrite)
	}
	if len(opts.Machines) == 0 {
		return Record{}, errors.New("a token needs at least one machine (or \"*\" for all)")
	}
	machines := make([]string, 0, len(opts.Machines))
	seen := make(map[string]bool)
	for _, m := range opts.Machines {
		if m == "*" {
			if len(opts.Machines) != 1 {
				return Record{}, errors.New(`"*" cannot be combined with machine ids`)
			}
		} else if !registry.ValidID(m) {
			return Record{}, fmt.Errorf("invalid machine id %q", m)
		}
		if !seen[m] {
			seen[m] = true
			machines = append(machines, m)
		}
	}
	if opts.TTL < 0 {
		return Record{}, errors.New("ttl must be positive")
	}
	ttl := opts.TTL
	if opts.Scope == ScopeReadWrite {
		if ttl == 0 {
			ttl = DefaultReadWriteTTL
		}
		if ttl > MaxReadWriteTTL {
			return Record{}, fmt.Errorf("readwrite tokens expire within %s; got ttl %s", MaxReadWriteTTL, ttl)
		}
	}
	now := s.now().UTC().Truncate(time.Second)
	rec := Record{Name: opts.Name, Scope: opts.Scope, Machines: machines, CreatedAt: now}
	if ttl > 0 {
		exp := now.Add(ttl)
		rec.ExpiresAt = &exp
	}
	return rec, nil
}

// List returns every stored token, including expired ones, in creation order.
func (s *Store) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return nil, err
	}
	return append([]Record(nil), s.tokens...), nil
}

// Revoke deletes the token whose name or id matches. Revoking is immediate:
// the next Authenticate in any process re-reads the file.
func (s *Store) Revoke(nameOrID string) (Record, error) {
	var removed Record
	err := s.update(func(f *file) error {
		for i, t := range f.Tokens {
			if t.Name == nameOrID || t.ID == nameOrID {
				removed = t
				f.Tokens = append(f.Tokens[:i], f.Tokens[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no token named %q", nameOrID)
	})
	return removed, err
}

// Authenticate resolves a raw bearer token to its record. Unknown, malformed,
// expired, and revoked tokens all return ErrUnauthorized.
func (s *Store) Authenticate(raw string) (Record, error) {
	if !tokenPattern.MatchString(raw) {
		return Record{}, ErrUnauthorized
	}
	want, _ := hex.DecodeString(hashToken(raw))
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return Record{}, err
	}
	var found *Record
	for i := range s.tokens {
		got, err := hex.DecodeString(s.tokens[i].Hash)
		if err == nil && subtle.ConstantTimeCompare(got, want) == 1 {
			found = &s.tokens[i]
		}
	}
	if found == nil || found.Expired(s.now()) {
		return Record{}, ErrUnauthorized
	}
	return *found, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// refreshLocked reloads the file when its identity, size, or mtime changed.
// Writers replace the file by rename, so the inode changes on every write.
func (s *Store) refreshLocked() error {
	st, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.stat, s.tokens = nil, nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat token file: %w", err)
	}
	if s.stat != nil && os.SameFile(s.stat, st) && s.stat.Size() == st.Size() && s.stat.ModTime().Equal(st.ModTime()) {
		return nil
	}
	f, err := readFile(s.path)
	if err != nil {
		return err
	}
	s.stat, s.tokens = st, f.Tokens
	return nil
}

func readFile(path string) (*file, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &file{Version: fileVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	var f file
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse token file %s: %w", path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("token file %s: unsupported version %d", path, f.Version)
	}
	return &f, nil
}

// update runs fn on the current file contents under an exclusive cross-process
// lock and atomically replaces the file with the result.
func (s *Store) update(fn func(*file) error) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open token lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock token file: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	f, err := readFile(s.path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	if f.Tokens == nil {
		f.Tokens = []Record{}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tokens-*.json")
	if err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write token file: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace token file: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// MachinesLabel renders an allowlist for display.
func MachinesLabel(machines []string) string { return strings.Join(machines, ",") }
