// Package ui is the desktop window of the password manager: it unlocks the
// vault, lists the saved passwords and copies, edits, adds or deletes them.
package ui

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// Title is the window title.
const Title = "Password Manager"

// Vault is the password store the window works on. Every method may be
// called from any goroutine.
type Vault interface {
	// UnlockBiometric unlocks with Touch ID. It returns false and no error
	// when Touch ID is unavailable, so the master password is asked instead.
	UnlockBiometric() (bool, error)
	// Unlock unlocks with the master password; the caller wipes master.
	Unlock(master []byte) error
	// Names returns the saved password names in a stable order.
	Names() []string
	// Copy copies a saved password to the clipboard.
	Copy(name string) error
	// Update replaces a saved password once confirm matches pwd.
	Update(name, pwd, confirm string) error
	// Add saves a new password.
	Add(name, pwd string) error
	// Remove deletes a saved password.
	Remove(name string) error
	// Lock drops the decrypted store.
	Lock()
}

// Window shows one vault. Its methods run on the Fyne main thread.
type Window struct {
	win    fyne.Window
	vault  Vault
	status *widget.Label
	names  []string
	// session counts Show calls, so a Touch ID result arriving after the
	// window was hidden or reopened is discarded.
	session uint64
	// idle hides the unlocked window after idleTimeout without activity.
	idle        *time.Timer
	idleTimeout time.Duration
}

// idleLockTimeout is how long an unlocked window stays open without
// activity before it hides itself and locks the vault.
const idleLockTimeout = 2 * time.Minute

// errAddMismatch is shown when the Add form's confirmation differs.
const errAddMismatch = "passwords do not match"

// New creates the hidden window for v; closing it hides it.
func New(app fyne.App, v Vault) *Window {
	w := &Window{win: app.NewWindow(Title), vault: v, status: widget.NewLabel(""), idleTimeout: idleLockTimeout}
	w.status.Wrapping = fyne.TextWrapWord
	w.win.SetCloseIntercept(w.Hide)
	w.win.Resize(fyne.NewSize(460, 520))
	return w
}

// Show opens the window on the unlock view and tries Touch ID meanwhile.
func (w *Window) Show() {
	w.session++
	w.showUnlock()
	w.win.Show()
	w.win.RequestFocus()
	go w.unlockBiometric(w.session)
}

// Hide locks the vault, drops the listed names and hides the window.
func (w *Window) Hide() {
	w.stopIdleTimer()
	w.session++
	w.vault.Lock()
	w.names = nil
	w.status.SetText("")
	w.win.SetContent(widget.NewLabel(""))
	w.win.Hide()
}

// unlockBiometric runs Touch ID off the main thread and opens the list when
// it unlocks the vault for the still current session.
func (w *Window) unlockBiometric(session uint64) {
	unlocked, err := w.vault.UnlockBiometric()
	fyne.Do(func() {
		if session != w.session {
			if unlocked {
				w.vault.Lock()
			}
			return
		}
		switch {
		case err != nil:
			w.status.SetText(err.Error())
		case unlocked:
			w.showList("")
		default:
			return
		}
		// The Touch ID and Keychain prompts took focus; bring the window back.
		w.win.RequestFocus()
	})
}

func (w *Window) showUnlock() {
	w.status.SetText("")
	master := widget.NewPasswordEntry()
	master.SetPlaceHolder("Master password")
	unlock := func() {
		secret := []byte(master.Text)
		defer clear(secret)
		master.SetText("")
		if err := w.vault.Unlock(secret); err != nil {
			w.status.SetText(err.Error())
			return
		}
		w.showList("")
	}
	master.OnSubmitted = func(string) { unlock() }
	form := container.NewVBox(
		widget.NewLabel("Enter your master password"),
		master,
		widget.NewButton("Unlock", unlock),
		w.status,
	)
	w.win.SetContent(container.NewPadded(form))
	w.win.Canvas().Focus(master)
}

// showList shows the saved passwords with message in the status line.
func (w *Window) showList(message string) {
	w.resetIdleTimer()
	all := w.vault.Names()
	w.names = all
	w.status.SetText(message)
	if len(w.names) == 0 && message == "" {
		w.status.SetText("No passwords stored.")
	}
	list := widget.NewList(
		func() int { return len(w.names) },
		newPasswordRow,
		w.updatePasswordRow,
	)
	search := widget.NewEntry()
	search.SetPlaceHolder("Search")
	search.OnChanged = func(query string) {
		w.resetIdleTimer()
		w.names = filterNames(all, query)
		list.UnselectAll()
		list.Refresh()
	}
	actions := container.NewHBox(
		widget.NewButton("Add", w.showAdd),
		widget.NewButton("Lock", w.Hide),
	)
	w.win.SetContent(container.NewBorder(search, container.NewVBox(w.status, actions), nil, nil, list))
	w.win.Canvas().Focus(search)
}

// filterNames returns the names containing query, ignoring case.
func filterNames(names []string, query string) []string {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return names
	}
	var matches []string
	for _, name := range names {
		if strings.Contains(strings.ToLower(name), query) {
			matches = append(matches, name)
		}
	}
	return matches
}

// resetIdleTimer restarts the countdown after which an unattended window
// hides itself, which locks the vault and drops the decrypted store.
func (w *Window) resetIdleTimer() {
	w.stopIdleTimer()
	session := w.session
	w.idle = time.AfterFunc(w.idleTimeout, func() {
		fyne.Do(func() {
			if session == w.session {
				w.Hide()
			}
		})
	})
}

func (w *Window) stopIdleTimer() {
	if w.idle != nil {
		w.idle.Stop()
		w.idle = nil
	}
}

// newPasswordRow builds a list row: the name and its Copy, Edit and Delete
// buttons, wired to an entry by updatePasswordRow.
func newPasswordRow() fyne.CanvasObject {
	buttons := container.NewHBox(widget.NewButton("Copy", nil), widget.NewButton("Edit", nil), widget.NewButton("Delete", nil))
	return container.NewBorder(nil, nil, nil, buttons, widget.NewLabel(""))
}

func (w *Window) updatePasswordRow(id widget.ListItemID, item fyne.CanvasObject) {
	if id < 0 || id >= len(w.names) {
		return
	}
	name := w.names[id]
	row := item.(*fyne.Container)
	row.Objects[0].(*widget.Label).SetText(name)
	buttons := row.Objects[1].(*fyne.Container).Objects
	buttons[0].(*widget.Button).OnTapped = func() { w.copyPassword(name) }
	buttons[1].(*widget.Button).OnTapped = func() { w.showEdit(name) }
	buttons[2].(*widget.Button).OnTapped = func() { w.confirmRemove(name) }
}

func (w *Window) copyPassword(name string) {
	w.resetIdleTimer()
	if err := w.vault.Copy(name); err != nil {
		w.status.SetText(err.Error())
		return
	}
	w.status.SetText(fmt.Sprintf("Copied %q; the clipboard is cleared in a few seconds.", name))
}

func (w *Window) showEdit(name string) {
	pwd, confirm := widget.NewPasswordEntry(), widget.NewPasswordEntry()
	save := func() {
		if err := w.vault.Update(name, pwd.Text, confirm.Text); err != nil {
			w.status.SetText(err.Error())
			return
		}
		w.showList(fmt.Sprintf("Password %q updated.", name))
	}
	w.showForm(fmt.Sprintf("Edit %q", name), save,
		widget.NewFormItem("New password", pwd),
		widget.NewFormItem("Confirm", confirm),
	)
}

func (w *Window) showAdd() {
	name, pwd, confirm := widget.NewEntry(), widget.NewPasswordEntry(), widget.NewPasswordEntry()
	save := func() {
		if subtle.ConstantTimeCompare([]byte(pwd.Text), []byte(confirm.Text)) != 1 {
			w.status.SetText(errAddMismatch)
			return
		}
		if err := w.vault.Add(name.Text, pwd.Text); err != nil {
			w.status.SetText(err.Error())
			return
		}
		w.showList(fmt.Sprintf("Password %q added.", strings.TrimSpace(name.Text)))
	}
	w.showForm("Add password", save,
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Password", pwd),
		widget.NewFormItem("Confirm", confirm),
	)
}

// showForm shows a form titled title whose Save button calls save and whose
// Cancel button returns to the list.
func (w *Window) showForm(title string, save func(), items ...*widget.FormItem) {
	w.resetIdleTimer()
	w.status.SetText("")
	form := widget.NewForm(items...)
	form.SubmitText = "Save"
	form.OnSubmit = save
	form.OnCancel = func() { w.showList("") }
	w.win.SetContent(container.NewPadded(container.NewVBox(widget.NewLabel(title), form, w.status)))
}

func (w *Window) confirmRemove(name string) {
	dialog.ShowConfirm("Delete password", fmt.Sprintf("Delete %q?", name), func(ok bool) {
		if !ok {
			return
		}
		if err := w.vault.Remove(name); err != nil {
			w.status.SetText(err.Error())
			return
		}
		w.showList(fmt.Sprintf("Password %q deleted.", name))
	}, w.win)
}
