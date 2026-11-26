package cmd

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		Version:    "test",
		Threads:    1,
		Timeout:    time.Second,
		IOTimeout:  time.Second,
		SmbPort:    445,
		WriteCheck: "file",
		Depth:      5,
	}
}

func TestCreateScanner_RejectsBadTimeouts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		flag   string
	}{
		{"zero connect timeout", func(c *Config) { c.Timeout = 0 }, "--timeout"},
		{"negative connect timeout", func(c *Config) { c.Timeout = -time.Second }, "--timeout"},
		{"negative I/O timeout", func(c *Config) { c.IOTimeout = -time.Second }, "--io-timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			_, err := CreateScanner(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.flag) {
				t.Fatalf("CreateScanner error = %v, want one naming %s", err, tt.flag)
			}
		})
	}
}

func TestCreateScanner_AcceptsDisabledIOTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.IOTimeout = 0
	if _, err := CreateScanner(cfg); err != nil {
		t.Fatalf("--io-timeout 0 disables the I/O bound and must be accepted: %v", err)
	}
}
