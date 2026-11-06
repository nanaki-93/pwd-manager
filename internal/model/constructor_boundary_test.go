package model_test

import "github.com/nanaki-93/pwd-manager/internal/model"

// These assignments pin the existing field types.
var _ *string = &new(model.PwdFile).MasterPassword
var _ *map[string]string = &new(model.PwdFile).SavedPasswords
