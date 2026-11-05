package cmd

import "github.com/nanaki-93/pwd-manager/internal/utils"

// setUtilsExit overrides utils.ExitFunc and returns a restore callback.
func setUtilsExit(fn func(int)) func() {
	prev := utils.ExitFunc
	utils.ExitFunc = fn
	return func() { utils.ExitFunc = prev }
}

// setUtilsReadPassword overrides utils.ReadPasswordStdin and returns a restore callback.
func setUtilsReadPassword(fn func() ([]byte, error)) func() {
	prev := utils.ReadPasswordStdin
	utils.ReadPasswordStdin = fn
	return func() { utils.ReadPasswordStdin = prev }
}
