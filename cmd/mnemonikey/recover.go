package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kklash/mnemonikey"
)

type RecoverOptions struct {
	Name      string
	Email     string
	WordCount uint
}

var RecoverCommand = &Command[RecoverOptions]{
	Name:        "mnemonikey recover",
	Description: "Recover an OpenPGP private key from an existing mnemonic recovery phrase.",
	UsageExamples: []string{
		"mnemonikey recover",
		"mnemonikey recover -name myuser",
		"mnemonikey recover -name myuser -email someone@someplace.com",
		"mnemonikey recover -words 18",
		"mnemonikey recover -name myuser -words 18",
	},
	AddFlags: func(flags *flag.FlagSet, opts *RecoverOptions) {
		flags.StringVar(&opts.Name, "name", DefaultName, "Display name for the PGP key user identifier. (optional)")
		flags.StringVar(&opts.Email, "email", "", "Email for the PGP key user identifier. (optional)")
		flags.UintVar(&opts.WordCount, "words", mnemonikey.MinMnemonicSize, "Number of words in the "+
			"recovery mnemonic. (optional)")
	},
	Execute: func(opts *RecoverOptions, args []string) error {
		return recoverAndPrintKey(opts.Name, opts.Email, opts.WordCount)
	},
}

func recoverAndPrintKey(name, email string, wordCount uint) error {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)

	words, err := userInputMnemonic(wordCount)
	if err != nil {
		return err
	}

	keyPair, err := mnemonikey.RecoverKeyPair(words, name, email, time.Time{})
	if err != nil {
		return fmt.Errorf("failed to re-derive key pair: %w", err)
	}

	pgpArmorKey, err := keyPair.EncodePGPArmor([]byte(nil))
	if err != nil {
		return err
	}

	// TODO print debug data about derived key, Key ID, etc.
	fmt.Printf("Re-derived the following OpenPGP key:\n\n")
	fmt.Println(pgpArmorKey)

	return nil
}

func userInputMnemonic(wordCount uint) ([]string, error) {
	words := make([]string, wordCount)
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("Enter the words of your recovery mnemonic in sequence.\n\n")

	// Establish vertical space early to avoid jitter after the first word.
	fmt.Print("\n\033[F")

	for i := uint(0); i < wordCount; i++ {
		humanIndex := strconv.Itoa(int(i) + 1)
		prompt := fmt.Sprintf("Please enter mnemonic word %s >> ", humanIndex)

		fmt.Print(prompt)
		if !scanner.Scan() {
			fmt.Printf("\n\n")
			return nil, fmt.Errorf("unexpected EOF on standard input")
		}
		wordInput := scanner.Text()

		// Up to start of previous line
		fmt.Print("\033[F")

		// Wipe previous line from terminal
		fmt.Print(strings.Repeat(" ", len(prompt)+len(wordInput)) + "\r")

		words[i] = strings.TrimSpace(wordInput)
	}

	return words, nil
}
