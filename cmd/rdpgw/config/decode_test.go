package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMalformedSecurityConfigRefusesStartup(t *testing.T) {
	if filename := os.Getenv("RDPGW_TEST_BAD_CONFIG"); filename != "" {
		Load(filename)
		return
	}
	for _, content := range []string{
		"Access:\n  Rules:\n    - Users: [alice]\n      Deny: not-a-bool\n",
		"Caps:\n  TokenAuth: not-a-bool\n",
		"Server:\n  SessionLifetime: not-a-number\n",
		"Server:\n  Authentication: [header]\nCaps:\n  TokenAuth: false\nHeader:\n  UserHeader: X-User\n",
	} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestMalformedSecurityConfigRefusesStartup$")
		cmd.Env = append(os.Environ(), "RDPGW_TEST_BAD_CONFIG="+path)
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("accepted malformed security config:\n%s\n%s", content, output)
		}
	}
}
