package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		valid bool
	}{
		{"https", Config{ServerURL: "https://support.example.com", MachineToken: "1234567890123456"}, true},
		{"localhost", Config{ServerURL: "http://127.0.0.1:8080", MachineToken: "1234567890123456"}, true},
		{"remote http", Config{ServerURL: "http://example.com", MachineToken: "1234567890123456"}, false},
		{"short token", Config{ServerURL: "https://example.com", MachineToken: "short"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if (validateConfig(tt.cfg) == nil) != tt.valid {
				t.Fatalf("valid=%v", tt.valid)
			}
		})
	}
}

func TestEmbeddedSSHRequiresTemporaryOperatorKey(t *testing.T) {
	agent := &Agent{configPath: filepath.Join(t.TempDir(), "config.json")}
	if err := agent.ensureEmbeddedSSHServer(); err != nil {
		t.Fatal(err)
	}
	defer agent.sshServer.listener.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicAuthorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKeyFromEd25519(t, public))))
	if err := agent.sshServer.authorize(publicAuthorized, time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{User: "mytail-admin", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 2 * time.Second}
	client, err := ssh.Dial("tcp", "127.0.0.1:22222", config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("printf mytail-ok")
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if string(output) != "mytail-ok" {
		t.Fatalf("unexpected output: %q", output)
	}
	agent.sshServer.revoke()
	raw, err := net.DialTimeout("tcp", "127.0.0.1:22222", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = ssh.NewClientConn(raw, "127.0.0.1:22222", config)
	if err == nil {
		t.Fatal("revoked key was accepted")
	}
}

func publicKeyFromEd25519(t *testing.T, public ed25519.PublicKey) ssh.PublicKey {
	t.Helper()
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
