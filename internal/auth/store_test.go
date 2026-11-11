package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "arco", "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateAuthenticateRevokeAcrossInstances(t *testing.T) {
	cli := newStore(t)
	server, _ := Open(cli.Path()) // a second handle, as a running server would hold

	raw, rec, err := cli.Create(CreateOptions{Name: "hermes", Scope: ScopeReadWrite, Machines: []string{"vm0"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "arco_rw_") || len(raw) != len("arco_rw_")+43 {
		t.Fatalf("raw token shape: %q", raw)
	}
	got, err := server.Authenticate(raw)
	if err != nil || got.ID != rec.ID || got.ReadOnly() || got.Machines[0] != "vm0" {
		t.Fatalf("authenticate: %+v %v", got, err)
	}
	if _, err := cli.Revoke("hermes"); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Authenticate(raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token still authenticates: %v", err)
	}
}

func TestFileHoldsOnlyHashesWithTightPermissions(t *testing.T) {
	s := newStore(t)
	raw, _, err := s.Create(CreateOptions{Name: "ro", Scope: ScopeRead, Machines: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), raw[8:]) {
		t.Fatal("raw token secret written to the token file")
	}
	for path, want := range map[string]os.FileMode{s.Path(): 0o600, filepath.Dir(s.Path()): 0o700} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", path, st.Mode().Perm(), want)
		}
	}
}

func TestAuthenticateRejects(t *testing.T) {
	s := newStore(t)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	raw, _, err := s.Create(CreateOptions{Name: "short", Scope: ScopeRead, Machines: []string{"vm0"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"empty":       "",
		"no prefix":   raw[8:],
		"wrong scope": "arco_rw_" + raw[8:],
		"truncated":   raw[:len(raw)-1],
		"unknown":     "arco_ro_" + strings.Repeat("A", 43),
	} {
		if _, err := s.Authenticate(tok); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := s.Authenticate(raw); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	clock = clock.Add(time.Hour + time.Second)
	if _, err := s.Authenticate(raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token authenticated: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	s := newStore(t)
	for name, opts := range map[string]CreateOptions{
		"bad name":           {Name: "Bad Name", Scope: ScopeRead, Machines: []string{"*"}},
		"bad scope":          {Name: "x", Scope: "admin", Machines: []string{"*"}},
		"no machines":        {Name: "x", Scope: ScopeRead},
		"star mixed":         {Name: "x", Scope: ScopeRead, Machines: []string{"*", "vm0"}},
		"bad machine":        {Name: "x", Scope: ScopeRead, Machines: []string{"-oProxy"}},
		"underscore machine": {Name: "x", Scope: ScopeRead, Machines: []string{"vm_0"}},
		"id-like name":       {Name: "tok_0123456789ab", Scope: ScopeRead, Machines: []string{"*"}},
		"negative ttl":       {Name: "x", Scope: ScopeRead, Machines: []string{"*"}, TTL: -time.Hour},
		"readwrite too old":  {Name: "x", Scope: ScopeReadWrite, Machines: []string{"vm0"}, TTL: MaxReadWriteTTL + time.Hour},
	} {
		if _, _, err := s.Create(opts); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	_, rw, err := s.Create(CreateOptions{Name: "rw", Scope: ScopeReadWrite, Machines: []string{"vm0", "vm0"}})
	if err != nil {
		t.Fatal(err)
	}
	if rw.ExpiresAt == nil || rw.ExpiresAt.Sub(rw.CreatedAt) != DefaultReadWriteTTL || len(rw.Machines) != 1 {
		t.Fatalf("readwrite defaults: %+v", rw)
	}
	_, ro, err := s.Create(CreateOptions{Name: "ro", Scope: ScopeRead, Machines: []string{"*"}})
	if err != nil || ro.ExpiresAt != nil {
		t.Fatalf("read token should not expire by default: %+v %v", ro, err)
	}
	if _, _, err := s.Create(CreateOptions{Name: "ro", Scope: ScopeRead, Machines: []string{"*"}}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err := s.Revoke("nope"); err == nil {
		t.Fatal("revoking an unknown token succeeded")
	}
}

// Separate Store handles (separate lock file descriptors) writing at once
// must not lose records: flock + re-read under the lock serializes them.
func TestConcurrentWritersLoseNothing(t *testing.T) {
	path := newStore(t).Path()
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, _ := Open(path)
			if _, _, err := s.Create(CreateOptions{Name: fmt.Sprintf("t%02d", i), Scope: ScopeRead, Machines: []string{"*"}}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	s, _ := Open(path)
	recs, err := s.List()
	if err != nil || len(recs) != n {
		t.Fatalf("got %d records (%v), want %d", len(recs), err, n)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("ARCO_TOKENS", "/srv/arco/tokens.json")
	if p, _ := DefaultPath(""); p != "/srv/arco/tokens.json" {
		t.Fatalf("env path: %s", p)
	}
	if p, _ := DefaultPath("/x/t.json"); p != "/x/t.json" {
		t.Fatalf("explicit path: %s", p)
	}
}
