package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"

	"github.com/kklash/mnemonikey"
	"github.com/kklash/wordlist4096"
)

const (
	inputHeaderMessage = "Enter the words of your recovery mnemonic in sequence."
	badWordMessage     = "No matching words found in the wordlist!"
)

func eprint(str string)                 { fmt.Fprint(os.Stderr, str) }
func eprintf(str string, values ...any) { fmt.Fprintf(os.Stderr, str, values...) }
func eprintln(values ...any)            { fmt.Fprintln(os.Stderr, values...) }

// userInputMnemonic accepts raw input from the user's terminal
// to get a mnemonic phrase of the given word count.
//
// Only returns words in the wordlist.
func userInputMnemonic(wordCount uint) ([]string, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		eprintf("WARN: failed to hook into terminal interface: %s\n", err)
		eprintf("WARN: reverting to backup input method\n")
		return userInputMnemonicSimple(wordCount)
	}
	defer func() {
		// Clear any sensitive mnemonic input on the current line from the terminal
		eprint("\r" + eraseLineForward + "\n\n")

		// Bring back the normal terminal APIs
		term.Restore(int(os.Stdin.Fd()), oldState)
	}()

	words := make([]string, wordCount)

	eprint(bold(cyan(inputHeaderMessage + "\r\n")))
	eprint("\r\n")
	eprint(faint("- ENTER/SPACE:    Autocomplete and submit word\r\n"))
	eprint(faint("- TAB:            Autocomplete word without submitting\r\n"))
	eprint(faint("- BACKSPACE:      Revise current word\r\n"))
	eprint(faint("- LEFT ARROW:     Revise previous word\r\n"))
	eprint(faint("- CTRL+C/CTRL+D:  Quit\r\n"))
	eprint("\r\n")

	// Establish vertical space early to allow room for printing error messages
	eprint("\n" + previousLine)

	for i := uint(0); i < wordCount; {
		eprint("\r" + eraseLineForward + bold(cyan(fmt.Sprintf("Word %d >> ", i+1))))

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
				eprint(string(charBuf))
				wordInput += string(charBuf)
			}

			// backspace
			if string(charBuf) == deleteCode {
				if len(wordInput) > 0 {
					wordInput = wordInput[:len(wordInput)-1]
					eprint(backspaceCode)
				}
			}

			// Left arrow, return to revise previous word index
			if charBuf[0] == keyCodeLeftArrow {
				i -= 1
				break
			}

			// See if the user's input might be a valid word in the wordlist.
			searchResult := wordlist4096.Search(wordInput)

			// Autocomplete without submitting
			if charBuf[0] == '\t' && len(searchResult.Suffixes) > 0 {
				eprint(searchResult.Suffixes[0])
				wordInput += searchResult.Suffixes[0]
				continue
			}

			// Save the cursor so we can return to it after printing an error message
			// or an autocomplete suggestion.
			eprint(saveCursor)

			// Autocomplete and submit
			if charBuf[0] == '\r' || charBuf[0] == ' ' {
				if len(searchResult.Suffixes) == 0 {
					eprint("\r\n" + red(badWordMessage) + loadCursor)
					continue
				}
				completedWord := wordInput + searchResult.Suffixes[0]

				// Confirm the mnemonic's version is supported
				if i == 0 {
					if _, err := mnemonikey.ParseVersion(completedWord); err != nil {
						eprint("\r\n" + red(err.Error()) + loadCursor)
						continue
					}
				}

				words[i] = completedWord
				i += 1
				break
			}

			// Remove any existing phantom autocomplete suggestion text.
			eprint(eraseLineForward)

			// Print a new phantom autocomplete suggestion.
			if len(searchResult.Suffixes) > 0 {
				eprint(faint(searchResult.Suffixes[0]))
			}

			// The user is typing the start of a valid word, or hasn't typed
			// anything at all. Erase the error message if there is one.
			if len(searchResult.Suffixes) > 0 || wordInput == "" {
				eprint("\r\n" + eraseLineForward)
			}

			// No chance this could be a valid word. Print an error message
			// so they know they're barking up the wrong tree.
			if len(searchResult.Suffixes) == 0 && wordInput != "" {
				eprint("\r\n" + red(badWordMessage))
			}

			// Reload the cursor to return to the user's expected typing position.
			eprint(loadCursor)
		}
	}

	return words, nil
}

// A simpler input process, used in cases where the raw terminal input
// manipulation in userInputMnemonic doesn't work for some people.
//
// Only returns words in the wordlist.
func userInputMnemonicSimple(wordCount uint) ([]string, error) {
	words := make([]string, wordCount)
	scanner := bufio.NewScanner(os.Stdin)

	eprint(bold(cyan(inputHeaderMessage + "\n\n")))

	// Establish vertical space early to allow room for printing error messages
	eprint("\n" + previousLine)

	for i := uint(0); i < wordCount; {
		eprint(bold(cyan(fmt.Sprintf("Word %d >> ", i+1))))

		if !scanner.Scan() {
			eprintf("\n\n")
			return nil, fmt.Errorf("unexpected EOF on standard input")
		}
		wordInput := strings.ToLower(strings.TrimSpace(scanner.Text()))

		// See if the user's input might be a valid word in the wordlist.
		searchResult := wordlist4096.Search(wordInput)

		if searchResult.ExactMatch {
			// We have a match! Remove any error message if needed
			eprint(eraseLineForward)

			if i == 0 {
				if _, err := mnemonikey.ParseVersion(wordInput); err != nil {
					eprint(red(err.Error()))
					goto next_word
				}
			}

			words[i] = wordInput
			i += 1
		} else {
			// No match, print an error message
			eprint(red(badWordMessage))
		}

		// Up to start of previous input line and wipe previous line from terminal
	next_word:
		eprint(previousLine + eraseLineForward)
	}

	return words, nil
}

var errPasswordConfirmationFailed = errors.New("Passwords do not match. Please try again.")

// userInputPassword accepts a password input from the user's terminal.
func userInputPassword() ([]byte, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	oldState, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		fmt.Println()
		term.Restore(int(os.Stdin.Fd()), oldState)
	}()

	passChan := make(chan []byte)
	errChan := make(chan error, 1)

	go func() {
		eprint(faint("Enter key encryption password: "))
		pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			errChan <- fmt.Errorf("failed to read password: %w", err)
			return
		}

		eprint(faint("\nConfirm key encryption password: "))
		pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			errChan <- fmt.Errorf("failed to confirm password: %w", err)
			return
		}
		if !bytes.Equal(pass1, pass2) {
			errChan <- errPasswordConfirmationFailed
			return
		}
		passChan <- pass1
	}()

	select {
	case <-ctx.Done():
		return nil, errors.New("aborted")

	case err := <-errChan:
		eprintln()
		if errors.Is(err, errPasswordConfirmationFailed) {
			eprintln(red(err.Error()))
			return userInputPassword()
		}
		return nil, err

	case pass := <-passChan:
		if len(pass) == 0 {
			return nil, fmt.Errorf("cannot encrypt keys with an empty password")
		}
		return pass, nil
	}
}
