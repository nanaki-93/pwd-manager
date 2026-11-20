package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"golang.design/x/hotkey"
)

// lifecycleApp models the started callback on the event loop: work dispatched
// to that loop cannot run until the callback returns.
type fakeLifecycle = fyne.Lifecycle

type lifecycleApp struct {
	fyne.App
	fakeLifecycle
	onStarted func()
	ready     chan struct{}
	quit      chan struct{}
	once      sync.Once
}

func (a *lifecycleApp) Lifecycle() fyne.Lifecycle { return a }
func (a *lifecycleApp) SetOnStarted(f func())     { a.onStarted = f }
func (a *lifecycleApp) Run() {
	a.onStarted()
	close(a.ready)
	<-a.quit
}
func (a *lifecycleApp) Quit() { a.once.Do(func() { close(a.quit) }) }

func TestRunAppHotkeyLifecycleAndErrors(t *testing.T) {
	registerErr := errors.New("register failed")
	unregisterErr := errors.New("unregister failed")
	for _, tc := range []struct {
		name             string
		regErr, unregErr error
	}{
		{name: "events close"},
		{name: "registration error", regErr: registerErr},
		{name: "unregistration error", unregErr: unregisterErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &lifecycleApp{ready: make(chan struct{}), quit: make(chan struct{})}
			events := make(chan hotkey.Event)
			close(events)
			calls := make(chan string, 2)
			register := func() (<-chan hotkey.Event, func() error, error) {
				// Simulate dispatch_sync to the event loop, including on failure.
				<-a.ready
				calls <- "register"
				if tc.regErr != nil {
					return nil, nil, tc.regErr
				}
				return events, func() error {
					<-a.ready
					calls <- "unregister"
					return tc.unregErr
				}, nil
			}
			done := make(chan error, 1)
			go func() { done <- runApp(context.Background(), a, func() {}, register) }()
			select {
			case err := <-done:
				want := tc.regErr
				if want == nil {
					want = tc.unregErr
				}
				if !errors.Is(err, want) {
					t.Errorf("runApp error = %v, want %v", err, want)
				}
				select {
				case <-a.quit:
				default:
					t.Error("app did not quit")
				}
				if got := <-calls; got != "register" {
					t.Errorf("first call = %q, want register", got)
				}
				if tc.regErr == nil {
					select {
					case got := <-calls:
						if got != "unregister" {
							t.Errorf("second call = %q, want unregister", got)
						}
					default:
						t.Error("unregister was not called")
					}
				} else if len(calls) != 0 {
					t.Error("unregister called after registration failed")
				}
			case <-time.After(5 * time.Second):
				t.Error("runApp blocked before the started callback returned or app quit")
			}
		})
	}
}

func TestRunAppHidesDockBeforeRegisteringHotkey(t *testing.T) {
	old := hideFromDock
	t.Cleanup(func() { hideFromDock = old })
	a := &lifecycleApp{ready: make(chan struct{}), quit: make(chan struct{})}
	hidden := make(chan struct{})
	hideFromDock = func() { close(hidden) }
	register := func() (<-chan hotkey.Event, func() error, error) {
		select {
		case <-hidden:
		default:
			return nil, nil, errors.New("hotkey registered before hiding Dock")
		}
		events := make(chan hotkey.Event)
		close(events)
		return events, func() error { return nil }, nil
	}
	if err := runApp(context.Background(), a, func() {}, register); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hidden:
	default:
		t.Fatal("Dock was not hidden on startup")
	}
}

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
