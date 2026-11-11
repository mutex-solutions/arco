package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadValidRegistry(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	path := writeRegistry(t, `
[[machine]]
id = "vm0"
transport = "unix"
socket = "~/.config/herdr/herdr.sock"
[[machine]]
id = "laptop"
transport = "ssh"
host = "longs-laptop"
user = "long"
socket = "/run/user/1000/herdr.sock"
timeout = "15s"
[mcp]
`)
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Machines()) != 2 {
		t.Fatalf("got %d machines", len(r.Machines()))
	}
	local, err := r.Resolve("vm0")
	if err != nil {
		t.Fatal(err)
	}
	if local.Socket() != "/home/tester/.config/herdr/herdr.sock" {
		t.Fatalf("socket = %q", local.Socket())
	}
	if local.Timeout() != DefaultTimeout {
		t.Fatalf("timeout = %s", local.Timeout())
	}
	remote, _ := r.Resolve("laptop")
	if remote.Timeout() != 15*time.Second {
		t.Fatalf("timeout = %s", remote.Timeout())
	}
	if remote.Target() != "long@longs-laptop:/run/user/1000/herdr.sock" {
		t.Fatalf("target = %q", remote.Target())
	}
}

func TestLoadEnvironmentOverride(t *testing.T) {
	path := writeRegistry(t, `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/herdr.sock"
`)
	t.Setenv("ARCO_MACHINES", path)
	if _, err := Load(""); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejections(t *testing.T) {
	tests := map[string]string{
		"unknown key": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s"
typo=true
`,
		"duplicate ids": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s"
[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s2"
`,
		"bad id": `[[machine]]
id="-bad"
transport="unix"
socket="/tmp/s"
`,
		"ipv6 zone smuggles a host": `[[machine]]
id="vm0"
transport="ssh"
host="fe80::1%x@evil.example"
user="long"
socket="/tmp/s"
`,
		"bad transport": `[[machine]]
id="vm0"
transport="tcp"
socket="/tmp/s"
`,
		"ssh missing fields": `[[machine]]
id="vm0"
transport="ssh"
socket="/tmp/s"
`,
		"unix with host": `[[machine]]
id="vm0"
transport="unix"
host="localhost"
socket="/tmp/s"
`,
		"host option injection": `[[machine]]
id="vm0"
transport="ssh"
host="-oProxyCommand=id"
user="long"
socket="/tmp/s"
`,
		"bad user": `[[machine]]
id="vm0"
transport="ssh"
host="host"
user="long;id"
socket="/tmp/s"
`,
		"remote tilde": `[[machine]]
id="vm0"
transport="ssh"
host="host"
user="long"
socket="~/herdr.sock"
`,
		"relative socket": `[[machine]]
id="vm0"
transport="unix"
socket="herdr.sock"
`,
		"integer timeout": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s"
timeout=10
`,
		"numeric string timeout": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s"
timeout="10"
`,
		"subsecond timeout": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s"
timeout="500ms"
`,
		"long timeout": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/s"
timeout="6m"
`,
		"long socket": `[[machine]]
id="vm0"
transport="unix"
socket="/tmp/` + strings.Repeat("x", 110) + `"
`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeRegistry(t, input)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestUnknownMachineListsIDsWithoutDial(t *testing.T) {
	r := &Registry{byID: map[string]*Machine{}}
	m, _ := NewMachine("vm0", "unix", "", "", "/tmp/s", 0)
	r.machines = []*Machine{m}
	r.byID[m.id] = m
	_, err := r.Resolve("other")
	if err == nil || !strings.Contains(err.Error(), "vm0") {
		t.Fatalf("error = %v", err)
	}
}

func writeRegistry(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "machines.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFilter(t *testing.T) {
	a, _ := NewMachine("a", "unix", "", "", "/tmp/a.sock", 0)
	b, _ := NewMachine("b", "unix", "", "", "/tmp/b.sock", 0)
	c, _ := NewMachine("c", "unix", "", "", "/tmp/c.sock", 0)
	reg := &Registry{machines: []*Machine{a, b, c}, byID: map[string]*Machine{"a": a, "b": b, "c": c}}
	ids := func(r *Registry) string {
		var out []string
		for _, m := range r.Machines() {
			out = append(out, m.ID())
		}
		return strings.Join(out, ",")
	}
	for name, tc := range map[string]struct {
		allowed []string
		want    string
	}{
		"star":          {[]string{"*"}, "a,b,c"},
		"subset order":  {[]string{"c", "a"}, "a,c"},
		"unknown only":  {[]string{"zzz"}, ""},
		"empty":         {nil, ""},
		"star in list":  {[]string{"a", "*"}, "a"},
		"unknown mixed": {[]string{"b", "zzz"}, "b"},
	} {
		if got := ids(reg.Filter(tc.allowed)); got != tc.want {
			t.Errorf("%s: Filter(%v) = %q, want %q", name, tc.allowed, got, tc.want)
		}
	}
	if _, err := reg.Filter([]string{"a"}).Resolve("b"); err == nil || strings.Contains(err.Error(), "b,") || !strings.Contains(err.Error(), "known machines: a") {
		t.Errorf("filtered Resolve must not reveal other machines: %v", err)
	}
	if _, err := reg.Filter(nil).Resolve("a"); err == nil || !strings.Contains(err.Error(), "no machines are available") {
		t.Errorf("empty Resolve: %v", err)
	}
}
