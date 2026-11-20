package ui

import (
	"errors"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// fakeVault reports bioUnlocked and bioErr from UnlockBiometric.
type fakeVault struct {
	locks       int
	bioUnlocked bool
	bioErr      error
}

func (v *fakeVault) UnlockBiometric() (bool, error) { return v.bioUnlocked, v.bioErr }

func (*fakeVault) Unlock([]byte) error { return nil }

func (*fakeVault) Names() []string { return []string{"site"} }

func (*fakeVault) Copy(string) error { return nil }

func (*fakeVault) Update(string, string, string) error { return nil }

func (*fakeVault) Add(string, string) error { return nil }

func (*fakeVault) Remove(string) error { return nil }

func (v *fakeVault) Lock() { v.locks++ }

type focusWindow struct {
	fyne.Window
	focuses int
	onFocus func()
}

func (w *focusWindow) RequestFocus() {
	w.focuses++
	if w.onFocus != nil {
		w.onFocus()
	}
}

func TestBiometricResultFocusesCurrentSession(t *testing.T) {
	for _, tc := range []struct {
		name           string
		unlocked       bool
		err            error
		stale          bool
		focuses, locks int
		status         string
		listed         bool
	}{
		{name: "success", unlocked: true, focuses: 1, listed: true},
		{name: "failure", err: errors.New("biometric failed"), focuses: 1, status: "biometric failed"},
		{name: "unavailable"},
		{name: "stale success", unlocked: true, stale: true, locks: 1},
		{name: "stale failure", err: errors.New("biometric failed"), stale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := test.NewApp()
			defer a.Quit()
			v := &fakeVault{bioUnlocked: tc.unlocked, bioErr: tc.err}
			w := New(a, v)
			defer w.stopIdleTimer()
			w.session = 1
			w.showUnlock()
			fw := &focusWindow{Window: w.win}
			w.win = fw
			fw.onFocus = func() {
				if w.status.Text != tc.status || (len(w.names) > 0) != tc.listed {
					t.Errorf("focus before result: status=%q names=%v", w.status.Text, w.names)
				}
			}
			session := w.session
			if tc.stale {
				session--
			}
			w.unlockBiometric(session)
			if fw.focuses != tc.focuses || v.locks != tc.locks || w.status.Text != tc.status || (len(w.names) > 0) != tc.listed {
				t.Fatalf("focuses=%d locks=%d status=%q names=%v", fw.focuses, v.locks, w.status.Text, w.names)
			}
		})
	}
}

func TestSearchFiltersNames(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := New(a, &fakeVault{})
	defer w.Hide()
	w.showList("")
	search := w.win.Canvas().Focused().(*widget.Entry)
	search.SetText("  SIT  ")
	if len(w.names) != 1 || w.names[0] != "site" {
		t.Fatalf("matching names: %v", w.names)
	}
	search.SetText("absent")
	if len(w.names) != 0 {
		t.Fatalf("nonmatching names: %v", w.names)
	}
}

func TestAddRequiresConfirmationAndTrimsStatus(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	w := New(a, &fakeVault{})
	defer w.Hide()
	w.showAdd()
	padded := w.win.Content().(*fyne.Container)
	box := padded.Objects[0].(*fyne.Container)
	form := box.Objects[1].(*widget.Form)
	form.Items[0].Widget.(*widget.Entry).SetText(" site ")
	form.Items[1].Widget.(*widget.Entry).SetText("secret")
	form.Items[2].Widget.(*widget.Entry).SetText("different")
	form.OnSubmit()
	if w.status.Text != errAddMismatch {
		t.Fatalf("mismatch status: %q", w.status.Text)
	}
	form.Items[2].Widget.(*widget.Entry).SetText("secret")
	form.OnSubmit()
	if w.status.Text != `Password "site" added.` {
		t.Fatalf("success status: %q", w.status.Text)
	}
}

func TestHideLocksAndClearsList(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	v := &fakeVault{}
	w := New(a, v)
	w.showList("")
	if len(w.names) != 1 {
		t.Fatal("list did not load names")
	}
	w.Hide()
	if v.locks != 1 || len(w.names) != 0 {
		t.Fatalf("after hide: locks=%d names=%v", v.locks, w.names)
	}
}
