//go:build !unix

package cmd

import (
	"fmt"
	"runtime"
)

// startDetachedProcess fails: detaching the daemon needs Unix sessions.
func startDetachedProcess(args []string, logPath string) (int, error) {
	return 0, fmt.Errorf("--detach is not supported on %s", runtime.GOOS)
}
