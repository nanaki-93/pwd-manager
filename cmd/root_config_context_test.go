package cmd

import (
	"context"
	"testing"
)

func TestConfigFromContextRejectsNilConfig(t *testing.T) {
	cfg, ok := ConfigFromContext(WithConfig(context.Background(), nil))
	if ok {
		t.Fatalf("ConfigFromContext ok = true for nil *Config, want false")
	}
	if cfg != nil {
		t.Fatalf("ConfigFromContext cfg = %v, want nil", cfg)
	}
}

func TestConfigFromContextReturnsStoredConfig(t *testing.T) {
	want := NewConfig("")
	got, ok := ConfigFromContext(WithConfig(context.Background(), want))
	if !ok {
		t.Fatalf("ConfigFromContext ok = false, want true")
	}
	if got != want {
		t.Fatalf("ConfigFromContext returned %p, want %p", got, want)
	}
}
