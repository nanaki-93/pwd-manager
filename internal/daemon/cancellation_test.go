package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.design/x/hotkey"
)

func TestStartReturnsWhenContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v, want wrapping context.Canceled", err)
	}
}

func TestServeHotkeyStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	keydown := make(chan hotkey.Event)
	pressed := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveHotkey(ctx, keydown, func() { pressed <- struct{}{} })
	}()

	keydown <- hotkey.Event{}
	<-pressed
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveHotkey error = %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHotkey did not return after context cancellation")
	}
}

func TestServeHotkeyStopsWhenEventsClose(t *testing.T) {
	keydown := make(chan hotkey.Event)
	close(keydown)
	if err := serveHotkey(context.Background(), keydown, func() {}); err != nil {
		t.Fatalf("serveHotkey error = %v, want nil", err)
	}
}
