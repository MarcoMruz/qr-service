package main

import (
	"strings"
	"testing"
)

func envFrom(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(envFrom(map[string]string{
		"APP_PASSWORD":   "long-enough-password",
		"SESSION_SECRET": strings.Repeat("s", minSecretLength),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.addr != ":8080" || cfg.trustProxy {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadConfigRefusesUnsafeSetup(t *testing.T) {
	validSecret := strings.Repeat("s", minSecretLength)
	tests := map[string]map[string]string{
		"missing password":       {"SESSION_SECRET": validSecret},
		"short password":         {"APP_PASSWORD": "short", "SESSION_SECRET": validSecret},
		"short Unicode password": {"APP_PASSWORD": "😀😀😀", "SESSION_SECRET": validSecret},
		"invalid UTF-8 password": {"APP_PASSWORD": strings.Repeat("\xff", 12), "SESSION_SECRET": validSecret},
		"short secret":           {"APP_PASSWORD": "long-enough-password", "SESSION_SECRET": "short"},
		"bad trust proxy":        {"APP_PASSWORD": "long-enough-password", "SESSION_SECRET": validSecret, "TRUST_PROXY": "maybe"},
	}
	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfig(envFrom(env)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestLoadConfigAcceptsUnicodePasswordAtMinimum(t *testing.T) {
	if _, err := loadConfig(envFrom(map[string]string{
		"APP_PASSWORD":   strings.Repeat("😀", minPasswordLength),
		"SESSION_SECRET": strings.Repeat("s", minSecretLength),
	})); err != nil {
		t.Fatal(err)
	}
}
