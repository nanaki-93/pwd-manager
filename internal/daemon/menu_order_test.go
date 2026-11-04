package daemon

import (
	"slices"
	"testing"
)

func TestSortedPasswordNames_StableSortedOrder(t *testing.T) {
	saved := map[string]string{
		"github": "a", "Bank": "b", "zeta": "c", "alpha": "d",
		"mail": "e", "work-vpn": "f", "cloud": "g", "x": "h",
	}
	want := []string{"Bank", "alpha", "cloud", "github", "mail", "work-vpn", "x", "zeta"}
	for i := 0; i < 50; i++ {
		if got := sortedPasswordNames(saved); !slices.Equal(got, want) {
			t.Fatalf("run %d: got %v, want %v", i, got, want)
		}
	}
}

func TestSortedPasswordNames_Empty(t *testing.T) {
	if got := sortedPasswordNames(nil); len(got) != 0 {
		t.Fatalf("expected no names, got %v", got)
	}
}
