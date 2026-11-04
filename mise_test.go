package main

import (
	"go/version"
	"os"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// Check the committed configuration, not the host Go version: automatic
// toolchain downloads can otherwise conceal an outdated mise pin in CI.
func TestMiseGoPinMeetsModuleMinimum(t *testing.T) {
	data, err := os.ReadFile(".mise.toml")
	if err != nil {
		t.Fatalf("read mise configuration: %v", err)
	}
	var config struct {
		Tools struct {
			Go string `toml:"go"`
		} `toml:"tools"`
	}
	if err := toml.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse mise configuration: %v", err)
	}
	pin := "go" + config.Tools.Go
	if !version.IsValid(pin) {
		t.Fatalf("mise Go pin %q must be a concrete Go version", config.Tools.Go)
	}

	data, err = os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read module configuration: %v", err)
	}
	minimum := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "go" {
			minimum = "go" + fields[1]
			break
		}
	}
	if !version.IsValid(minimum) {
		t.Fatalf("missing or invalid module Go minimum %q", minimum)
	}
	// Equality is sufficient, including the patch version; a newer pin is
	// also compatible, while even one patch below the minimum is not.
	if version.Compare(pin, minimum) < 0 {
		t.Fatalf("mise pins %s below module minimum %s; builds would require automatic toolchain downloads", pin, minimum)
	}
}
