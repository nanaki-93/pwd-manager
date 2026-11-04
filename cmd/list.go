/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nanaki-93/pwd-manager/internal/utils"
	"github.com/spf13/cobra"
)

const maskedPasswordPlaceholder = "********"

var (
	listShowFlag bool
	listJSONFlag bool

	listAllowNonTTYFlag bool
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "a list of all your saved passwords",
	Long:  ``,
	Run:   execListCmd,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVarP(&listShowFlag, "show", "s", false, "show saved passwords in plaintext")
	listCmd.Flags().BoolVar(&listJSONFlag, "json", false, "output saved passwords as formatted JSON")
	listCmd.Flags().BoolVar(&listAllowNonTTYFlag, "allow-non-tty", false, "allow --show to print plaintext passwords when stdout is not a terminal")
}

func writeListOutput(w io.Writer, savedPasswords map[string]string, showPlaintext bool) error {
	keys := make([]string, 0, len(savedPasswords))
	for k := range savedPasswords {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Buffer entries so large vaults do not issue one write syscall per entry
	// on an unbuffered stdout. Write errors may surface only at Flush.
	bw := bufio.NewWriter(w)
	for _, k := range keys {
		val := maskedPasswordPlaceholder
		if showPlaintext {
			val = savedPasswords[k]
		}
		if _, err := fmt.Fprintf(bw, "%s: %s\n", escapeListKey(k), sanitizeForTerminal(val)); err != nil {
			return fmt.Errorf("write list output: %w", err)
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write list output: flush: %w", err)
	}
	return nil
}

// listKeyEscaper escapes backslashes and the ": " separator in key names so
// that the first unescaped ": " on a text output line always ends the key.
var listKeyEscaper = strings.NewReplacer(`\`, `\\`, ": ", `\: `)

// escapeListKey renders a stored key for one text output line: the separator
// and backslashes are escaped first, then control characters, so a key can
// neither span lines nor be confused with its value.
func escapeListKey(k string) string {
	return sanitizeForTerminal(listKeyEscaper.Replace(k))
}

// sanitizeForTerminal escapes control characters, non-printable runes and
// invalid UTF-8 bytes so stored names and values cannot inject terminal escape
// sequences. Printable text is returned unchanged.
func sanitizeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}

// writeListJSONOutput streams the vault as an indented JSON object, one entry
// at a time through a bounded buffer, so neither a copy of the map nor the
// whole document is held in memory. The bytes match
// json.MarshalIndent(entries, "", "  ") followed by a newline.
func writeListJSONOutput(w io.Writer, savedPasswords map[string]string, showPlaintext bool) error {
	keys := make([]string, 0, len(savedPasswords))
	for k := range savedPasswords {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	bw := bufio.NewWriter(w)
	if err := writeJSONEntries(bw, keys, savedPasswords, showPlaintext); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write list json output: flush: %w", err)
	}
	return nil
}

func writeJSONEntries(bw *bufio.Writer, keys []string, savedPasswords map[string]string, showPlaintext bool) error {
	if len(keys) == 0 {
		if _, err := bw.WriteString("{}\n"); err != nil {
			return fmt.Errorf("write list json output: %w", err)
		}
		return nil
	}
	masked, err := json.Marshal(maskedPasswordPlaceholder)
	if err != nil {
		return fmt.Errorf("marshal list json output: %w", err)
	}
	sep := "{\n  "
	for _, k := range keys {
		key, err := json.Marshal(k)
		if err != nil {
			return fmt.Errorf("marshal list json output: key: %w", err)
		}
		val := masked
		if showPlaintext {
			if val, err = json.Marshal(savedPasswords[k]); err != nil {
				return fmt.Errorf("marshal list json output: value: %w", err)
			}
		}
		if _, err := fmt.Fprintf(bw, "%s%s: %s", sep, key, val); err != nil {
			return fmt.Errorf("write list json output: %w", err)
		}
		sep = ",\n  "
	}
	if _, err := bw.WriteString("\n}\n"); err != nil {
		return fmt.Errorf("write list json output: %w", err)
	}
	return nil
}

func runListCmd(out, errOut io.Writer, savedPasswords map[string]string, showPlaintext, asJSON bool) error {
	if asJSON {
		if err := writeListJSONOutput(out, savedPasswords, showPlaintext); err != nil {
			if errOut != nil {
				_, _ = fmt.Fprintf(errOut, "Error: %v\n", err)
			}
			return err
		}
		return nil
	}
	return writeListOutput(out, savedPasswords, showPlaintext)
}

// errPlaintextNotTTY is returned when --show would write secrets to a
// non-terminal (file, pipe, CI log) without --allow-non-tty.
var errPlaintextNotTTY = errors.New("refusing to print plaintext passwords: standard output is not a terminal (pass --allow-non-tty to override)")

// isTerminalWriter reports whether w is a character device such as an
// interactive terminal. Any other writer is treated as non-interactive.
var isTerminalWriter = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// checkPlaintextOutputAllowed enforces the plaintext output policy: masked
// output is always allowed; plaintext requires a terminal or an explicit
// allowNonTTY opt-in.
func checkPlaintextOutputAllowed(out io.Writer, showPlaintext, allowNonTTY bool) error {
	if !showPlaintext || allowNonTTY || isTerminalWriter(out) {
		return nil
	}
	return errPlaintextNotTTY
}

func execListCmd(cmd *cobra.Command, args []string) {
	if err := checkPlaintextOutputAllowed(cmd.OutOrStdout(), listShowFlag, listAllowNonTTYFlag); err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
		utils.ManageErrorAndExit(err)
		return
	}
	pwdObj, err := utils.GetPwdObjAfterCheckMaster()
	if err != nil {
		if listJSONFlag {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Error: %v\n", err)
		}
		utils.ManageErrorAndExit(err)
		return
	}
	err = runListCmd(cmd.OutOrStdout(), cmd.ErrOrStderr(), pwdObj.SavedPasswords, listShowFlag, listJSONFlag)
	utils.ManageErrorAndExit(err)
}
