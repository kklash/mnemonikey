package main

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

// Text formatting
func bold(s string) string      { return escapeCode + "[1m" + s + escapeCode + "[22m" }
func faint(s string) string     { return escapeCode + "[2m" + s + escapeCode + "[22m" }
func underline(s string) string { return escapeCode + "[4m" + s + escapeCode + "[24m" }

// Colors
func red(s string) string     { return escapeCode + "[31m" + s + escapeCode + "[39m" }
func green(s string) string   { return escapeCode + "[32m" + s + escapeCode + "[39m" }
func blue(s string) string    { return escapeCode + "[34m" + s + escapeCode + "[39m" }
func magenta(s string) string { return escapeCode + "[35m" + s + escapeCode + "[39m" }
func cyan(s string) string    { return escapeCode + "[36m" + s + escapeCode + "[39m" }
