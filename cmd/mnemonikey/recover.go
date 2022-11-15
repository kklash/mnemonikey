package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// TODO calculate from default seed size
const DefaultWordCount = 13

type RecoverOptions struct {
	Name      string
	Email     string
	WordCount uint
}

var RecoverCommand = &Command[RecoverOptions]{
	Name: "mnemonikey recover",
	AddFlags: func(flags *flag.FlagSet, opts *RecoverOptions) {
		flags.StringVar(&opts.Name, "name", DefaultName, "Display name for the PGP key user identifier. "+
			"This must be the same as the name used to originally generate the key.")
		flags.StringVar(&opts.Email, "email", "", "Email for the PGP key user identifier. (optional) "+
			"This must be the same as the email used to originally generate the key.")
		flag.UintVar(&opts.WordCount, "count", DefaultWordCount, "Number of words in the recovery mnemonic. (optional)")
	},
	Execute: func(opts *RecoverOptions, args []string) error {
		return recoverAndPrintKey(opts.Name, opts.Email, opts.WordCount)
	},
}

func recoverAndPrintKey(name, email string, wordCount uint) error {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)

	mnemonic, err := mnemonicInput(wordCount)
	if err != nil {
		return err
	}

	fmt.Println(mnemonic)

	return nil
}

func mnemonicInput(wordCount uint) ([]string, error) {
	mnemonic := make([]string, wordCount)
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

		mnemonic[i] = strings.TrimSpace(wordInput)
	}

	return mnemonic, nil
}
