package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/kklash/mnemonikey"
)

const (
	// ANSI escape code
	escapeCode = "\033"

	// deletes the current character under the cursor
	deleteCode = "\177"

	// deletes the previous character behind the cursor
	backspaceCode = "\010" + deleteCode

	// returns to the beginning of the previous line
	previousLine = escapeCode + "[F"

	// Erases the line ahead of the cursor
	eraseLineForward = escapeCode + "[0K"

	// Use both SCO and DEC sequences for compatibility
	saveCursor = escapeCode + "7" + escapeCode + "[s"
	loadCursor = escapeCode + "8" + escapeCode + "[u"
)

const (
	keyCodeLeftArrow byte = 68
	keyCodeControlC  byte = 3
	keyCodeControlD  byte = 4
)

const (
	magentaStart = escapeCode + "[35m"
	colorEnd     = escapeCode + "[39m"
)

// Text formatting
func bold(s string) string      { return escapeCode + "[1m" + s + escapeCode + "[22m" }
func faint(s string) string     { return escapeCode + "[2m" + s + escapeCode + "[22m" }
func underline(s string) string { return escapeCode + "[4m" + s + escapeCode + "[24m" }

// Colors
func red(s string) string     { return escapeCode + "[31m" + s + colorEnd }
func green(s string) string   { return escapeCode + "[32m" + s + colorEnd }
func blue(s string) string    { return escapeCode + "[34m" + s + colorEnd }
func magenta(s string) string { return magentaStart + s + colorEnd }
func cyan(s string) string    { return escapeCode + "[36m" + s + colorEnd }

const (
	defaultWidth               = 75
	defaultHeight              = 30
	flagSetOptionDefaultIndent = 8
)

// Layout
func getTerminalSize() (width, height int) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return defaultWidth, defaultHeight
	}
	return width, height
}

func justifyWidth(indent, width int, text string) string {
	maxWidth := indent + width

	indentString := strings.Repeat(" ", indent)

	words := strings.Split(text, " ")
	lines := make([]string, 0, len(text)/(indent+width)+1)

	for len(words) > 0 {
		line := indentString
		for len(words) > 0 && len(line)+len(words[0])+1 <= maxWidth {
			if line != indentString {
				line += " "
			}
			line += words[0]
			words = words[1:]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func justifyTerminalWidth(indent int, text string) string {
	// Take up at most 80% of the terminal width
	termWidth, _ := getTerminalSize()
	maxWidth := termWidth * 4 / 5
	return justifyWidth(indent, maxWidth, text)
}

func justifyOptionDescription(description string) string {
	// Take up at most 80% of the terminal width
	termWidth, _ := getTerminalSize()
	maxWidth := (termWidth - flagSetOptionDefaultIndent) * 4 / 5
	return justifyWidth(8, maxWidth, description)
}

func printKeyDebugInfo(mnk *mnemonikey.Mnemonikey) {
	info := [][2]string{
		{"Master key Fingerprint", fmt.Sprintf("%X", mnk.FingerprintV4())},
		{"User ID", fmt.Sprintf("%q", mnk.UserID())},
		{"Created at", mnk.CreatedAt().Format(time.RFC3339)},
	}
	if expiry := mnk.Expiry(); !expiry.IsZero() {
		info = append(info, [2]string{"Expires at", expiry.Format(time.RFC3339)})
	}
	for _, subkeyType := range mnk.SubkeyTypes() {
		key := fmt.Sprintf("%s subkey fingerprint", capitalize(subkeyType))
		info = append(info, [2]string{key, fmt.Sprintf("%X", mnk.SubkeyFingerprintV4(subkeyType))})
	}
	printDebugInfo(os.Stderr, info)
}

func capitalize[T ~string](s T) string {
	return strings.ToUpper(string(s[:1])) + string(s[1:])
}

func printDebugInfo(out io.Writer, values [][2]string) {
	maxLen := 0
	for _, pair := range values {
		key := pair[0]
		keyLen := utf8.RuneCountInString(key)
		if keyLen > maxLen {
			maxLen = keyLen
		}
	}

	for _, pair := range values {
		key, value := pair[0], pair[1]
		spacing := strings.Repeat(" ", maxLen-len(key)+1)
		fmt.Fprintln(out, faint(key+":")+spacing+cyan(value))
	}
}
