package main

import "testing"

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
