package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPersistentCredentialConfiguration(t *testing.T) {
	if path := os.Getenv("RDPGW_TEST_CREDENTIAL_CONFIG"); path != "" {
		Load(path)
		return
	}
	for _, tc := range []struct {
		name, content string
		valid         bool
	}{
		{"default lifetime", "Security:\n  CredentialStore: state/credentials.db\nOpenId:\n  ProviderUrl: https://keycloak.example/realms/test\n  AdminClientId: gateway-reader\n  AdminClientSecret: local-test-only\n", true},
		{"missing live resolver", "Security:\n  CredentialStore: state/credentials.db\n", false},
		{"stateless long lifetime", "Security:\n  PAATokenLifetime: 43200\n", false},
		{"over 30 days", "Security:\n  CredentialStore: state/credentials.db\n  PAATokenLifetime: 43201\nOpenId:\n  ProviderUrl: https://keycloak.example/realms/test\n  AdminClientId: gateway-reader\n  AdminClientSecret: local-test-only\n", false},
		{"other auth", "Server:\n  Authentication: [header]\nSecurity:\n  CredentialStore: state/credentials.db\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPersistentCredentialConfiguration$")
			cmd.Env = append(os.Environ(), "RDPGW_TEST_CREDENTIAL_CONFIG="+path)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v output=%s", tc.valid, err, output)
			}
			if tc.valid {
				c := Load(path)
				if c.Security.PAATokenLifetime != 43200 {
					t.Fatalf("default lifetime %d", c.Security.PAATokenLifetime)
				}
			}
		})
	}
}
