package herdr

import "testing"

// Messages are verbatim OpenSSH output (the pre-forward set captured live).
func TestIsSSHPreForwardFailure(t *testing.T) {
	for msg, want := range map[string]bool{
		"ssh: Could not resolve hostname no-such-host.invalid: Name or service not known": true,
		"channel 0: open failed: connect failed: open failed\nstdio forwarding failed":    true,
		"nobodyhere@192.168.100.100: Permission denied (publickey,password).":             true,
		"ssh: connect to host 10.255.255.1 port 22: Connection timed out":                 true,
		"ssh: connect to host 127.0.0.1 port 2222: Connection refused":                    true,
		"Host key verification failed.":                                                   true,
		"kex_exchange_identification: Connection closed by remote host":                   true,
		"Read from remote host vm0: Connection timed out":                                 false,
		"Read from remote host vm0: No route to host":                                     false,
		"client_loop: send disconnect: Broken pipe":                                       false,
		"Timeout, server vm0 not responding.":                                             false,
		"Shared connection to vm0 closed.":                                                false,
		"no such identity: /home/u/.ssh/id_ecdsa: No such file or directory":              false,
		"": false,
		"Warning: Permanently added 'vm0' (ED25519) to the list of known hosts.":                false,
		"Warning: Permanently added 'vm0'\nRead from remote host vm0: Connection reset by peer": false,
	} {
		if got := isSSHPreForwardFailure(msg); got != want {
			t.Errorf("isSSHPreForwardFailure(%q) = %v, want %v", msg, got, want)
		}
	}
}
