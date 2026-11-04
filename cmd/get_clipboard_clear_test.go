package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stubGetClearer swaps getClipboardClearer and getClearAfterFlag for the test.
func stubGetClearer(t *testing.T, delay time.Duration, fn func(pwd string, d time.Duration) error) {
	t.Helper()
	origClearer, origDelay := getClipboardClearer, getClearAfterFlag
	t.Cleanup(func() { getClipboardClearer, getClearAfterFlag = origClearer, origDelay })
	getClipboardClearer, getClearAfterFlag = fn, delay
}

// expiredCtx stands in for a timer that has already fired, so the clear runs
// deterministically without waiting for the (hour-long) delay.
func expiredCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestGetCopyClearsPasswordAfterConfiguredDelay(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	var gotDelay time.Duration
	stubGetClearer(t, 3*time.Second, func(pwd string, d time.Duration) error {
		gotDelay = d
		if *content != pwd {
			t.Fatalf("clear must run after copy, clipboard=%q", *content)
		}
		return clearClipboardAfter(expiredCtx(), pwd, time.Hour)
	})

	err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotDelay != 3*time.Second {
		t.Fatalf("expected configured delay 3s, got %v", gotDelay)
	}
	if *content != "" {
		t.Fatalf("expected clipboard cleared after get --copy, still holds %q", *content)
	}
}

func TestGetCopyLeavesClipboardChangedByUser(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	stubGetClearer(t, time.Second, func(pwd string, _ time.Duration) error {
		*content = "user copied this"
		return clearClipboardAfter(expiredCtx(), pwd, time.Hour)
	})

	if err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *content != "user copied this" {
		t.Fatalf("expected clipboard left alone, got %q", *content)
	}
}

func TestGetCopyRejectsNonPositiveDelayBeforeCopy(t *testing.T) {
	content := fakeClipboard(t, nil, nil)
	stubGetClearer(t, 0, func(string, time.Duration) error {
		t.Fatalf("clearer must not run for an invalid delay")
		return nil
	})

	err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	if !errors.Is(err, errInvalidClearAfter) {
		t.Fatalf("expected errInvalidClearAfter, got %v", err)
	}
	if *content != "" {
		t.Fatalf("expected nothing copied, clipboard holds %q", *content)
	}
}

func TestGetCopyReportsClearFailure(t *testing.T) {
	fakeClipboard(t, nil, nil)
	clearErr := errors.New("clear failed")
	stubGetClearer(t, time.Second, func(string, time.Duration) error { return clearErr })

	err := handleGetOutput("github", map[string]string{"github": "s3cr3t"}, true)
	if !errors.Is(err, clearErr) || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("expected wrapped clear error without secret, got %v", err)
	}
}

func TestGetClearAfterFlagRegistered(t *testing.T) {
	f := getCmd.Flags().Lookup("clear-after")
	if f == nil || f.DefValue != addClipboardClearDelay.String() {
		t.Fatalf("expected --clear-after flag defaulting to %v, got %+v", addClipboardClearDelay, f)
	}
}
