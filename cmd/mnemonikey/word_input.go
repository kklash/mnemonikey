package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/kklash/mnemonikey/mnemonic"
)

const (
	inputHeaderMessage = "Enter the words of your recovery mnemonic in sequence."
	badWordMessage     = "No matching words found in the wordlist!"
)

// userInputMnemonic accepts raw input from the user's terminal
// to get a mnemonic phrase of the given word count.
//
// Only returns words in the BIP39 word list.
func userInputMnemonic(wordCount uint) ([]string, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: failed to hook into terminal interface: %s\n", err)
		fmt.Fprintf(os.Stderr, "WARN: reverting to backup input method\n")
		return userInputMnemonicSimple(wordCount)
	}
	defer func() {
		// Clear any sensitive mnemonic input on the current line from the terminal
		fmt.Print("\r" + eraseLineForward + "\n\n")

		// Bring back the normal terminal APIs
		term.Restore(int(os.Stdin.Fd()), oldState)
	}()

	words := make([]string, wordCount)

	fmt.Print(bold(cyan(inputHeaderMessage + "\r\n")))
	fmt.Print("\r\n")
	fmt.Print(faint("- ENTER/SPACE:    Autocomplete and submit word\r\n"))
	fmt.Print(faint("- TAB:            Autocomplete word without submitting\r\n"))
	fmt.Print(faint("- BACKSPACE:      Revise current word\r\n"))
	fmt.Print(faint("- LEFT ARROW:     Revise previous word\r\n"))
	fmt.Print(faint("- CTRL+C/CTRL+D:  Quit\r\n"))
	fmt.Print("\r\n")

	// Establish vertical space early to allow room for printing error messages
	fmt.Print("\n" + previousLine)

	for i := uint(0); i < wordCount; {
		fmt.Print("\r" + eraseLineForward + bold(cyan(fmt.Sprintf("Word %d >> ", i+1))))

		wordInput := ""
		charBuf := make([]byte, 1)
		for {
			if _, err := os.Stdin.Read(charBuf); err != nil {
				return nil, fmt.Errorf("failed to read from standard input: %w", err)
			}

			// Abort with CTRL+C/CTRL+D
			if charBuf[0] == keyCodeControlC || charBuf[0] == keyCodeControlD {
				return nil, fmt.Errorf("aborted")
			}

			// Print only acceptable chars
			if charBuf[0] >= 'a' && charBuf[0] <= 'z' {
				fmt.Print(string(charBuf))
				wordInput += string(charBuf)
			}

			// backspace
			if string(charBuf) == deleteCode {
				if len(wordInput) > 0 {
					wordInput = wordInput[:len(wordInput)-1]
					fmt.Print(backspaceCode)
				}
			}

			// Left arrow, return to revise previous word index
			if charBuf[0] == keyCodeLeftArrow {
				i -= 1
				break
			}

			// See if the user's input might be a valid BIP39 word.
			searchResult := mnemonic.Search(wordInput)

			// Autocomplete without submitting
			if charBuf[0] == '\t' && len(searchResult.Suffixes) > 0 {
				fmt.Print(searchResult.Suffixes[0])
				wordInput += searchResult.Suffixes[0]
				continue
			}

			// Save the cursor so we can return to it after printing an error message
			// or an autocomplete suggestion.
			fmt.Print(saveCursor)

			// Autocomplete and submit
			if charBuf[0] == '\r' || charBuf[0] == ' ' {
				if len(searchResult.Suffixes) == 0 {
					fmt.Print("\r\n" + red(badWordMessage) + loadCursor)
					continue
				}

				words[i] = wordInput + searchResult.Suffixes[0]
				i += 1
				break
			}

			// Remove any existing phantom autocomplete suggestion text.
			fmt.Print(eraseLineForward)

			// Print a new phantom autocomplete suggestion.
			if len(searchResult.Suffixes) > 0 {
				fmt.Print(faint(searchResult.Suffixes[0]))
			}

			// The user is typing the start of a valid word, or hasn't typed
			// anything at all. Erase the error message if there is one.
			if len(searchResult.Suffixes) > 0 || wordInput == "" {
				fmt.Print("\r\n" + eraseLineForward)
			}

			// No chance this could be a valid word. Print an error message
			// so they know they're barking up the wrong tree.
			if len(searchResult.Suffixes) == 0 && wordInput != "" {
				fmt.Print("\r\n" + red(badWordMessage))
			}

			// Reload the cursor to return to the user's expected typing position.
			fmt.Print(loadCursor)
		}
	}

	return words, nil
}

// A simpler input process, used in cases where the raw terminal input
// manipulation in userInputMnemonic doesn't work for some people.
//
// Only returns words in the BIP39 word list.
func userInputMnemonicSimple(wordCount uint) ([]string, error) {
	words := make([]string, wordCount)
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print(bold(cyan(inputHeaderMessage + "\n\n")))

	// Establish vertical space early to allow room for printing error messages
	fmt.Print("\n" + previousLine)

	for i := uint(0); i < wordCount; {
		fmt.Print(bold(cyan(fmt.Sprintf("Word %d >> ", i+1))))

		if !scanner.Scan() {
			fmt.Printf("\n\n")
			return nil, fmt.Errorf("unexpected EOF on standard input")
		}
		wordInput := strings.ToLower(strings.TrimSpace(scanner.Text()))

		// See if the user's input might be a valid BIP39 word.
		searchResult := mnemonic.Search(wordInput)

		if searchResult.ExactMatch {
			// We have a match! Remove any error message if needed
			fmt.Print(eraseLineForward)
			words[i] = wordInput
			i += 1
		} else {
			// No match, print an error message
			fmt.Print(red(badWordMessage))
		}

		// Up to start of previous input line and wipe previous line from terminal
		fmt.Print(previousLine + eraseLineForward)
	}

	return words, nil
}
