package ui

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

type fakeVault struct{ locks int }

func (*fakeVault) UnlockBiometric() (bool, error) { return false, nil }

func (*fakeVault) Unlock([]byte) error { return nil }

func (*fakeVault) Names() []string { return []string{"site"} }

func (*fakeVault) Copy(string) error { return nil }

func (*fakeVault) Update(string, string, string) error { return nil }

func (*fakeVault) Add(string, string) error { return nil }

func (*fakeVault) Remove(string) error { return nil }

func (v *fakeVault) Lock() { v.locks++ }

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
