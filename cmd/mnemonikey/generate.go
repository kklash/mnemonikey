package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kklash/mnemonikey"
)

var DefaultName = "anonymous"

type GenerateOptions struct {
	Name      string
	Email     string
	WordCount uint
	Expiry    string
}

var GenerateCommand = &Command[GenerateOptions]{
	Name:        "mnemonikey generate",
	Description: "Generate a new OpenPGP key and its mnemonic recovery phrase.",
	UsageExamples: []string{
		"mnemonikey generate",
		"mnemonikey generate -name username",
		"mnemonikey generate -name username -email bob@hotmail.com",
		"mnemonikey generate -name username -words 20",
		"mnemonikey generate -expiry 2y",
		"mnemonikey generate -expiry 17w",
		"mnemonikey generate -expiry 1679285000",
	},
	AddFlags: func(flags *flag.FlagSet, opts *GenerateOptions) {
		flags.StringVar(&opts.Name, "name", DefaultName, "Display name for the PGP key user identifier. (optional)")
		flags.StringVar(&opts.Email, "email", "", "Email for the PGP key user identifier. (optional)")
		flags.StringVar(&opts.Expiry, "expiry", "", "Set an expiry period on the generated key.\n"+
			"Can be a number denominated in days (d) weeks (w) months (m) or years (y) relative to the\n"+
			"current time, or an absolute unix timestamp number. (optional)")

		flags.UintVar(
			&opts.WordCount,
			"words",
			mnemonikey.MinMnemonicSize,
			fmt.Sprintf(
				"Number of words in the recovery mnemonic.\nMust be at least %d to be secure. (optional)",
				mnemonikey.MinMnemonicSize,
			),
		)
	},
	Execute: func(opts *GenerateOptions, args []string) error {
		return generateAndPrintKey(opts)
	},
}

func generateAndPrintKey(opts *GenerateOptions) error {
	name := strings.TrimSpace(opts.Name)
	email := strings.TrimSpace(opts.Email)

	var (
		creation = time.Now()
		expiry   time.Time
		err      error
	)

	if opts.Expiry != "" {
		expiry, err = parseExpiry(creation, opts.Expiry)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	if opts.WordCount < mnemonikey.MinMnemonicSize {
		return fmt.Errorf("%w: invalid word count %d", ErrPrintUsage, opts.WordCount)
	}

	seed, err := mnemonikey.GenerateSeed(rand.Reader, opts.WordCount)
	if err != nil {
		return err
	}

	keyPair, err := mnemonikey.NewDeterministicKeyPair(seed, name, email, creation, expiry)
	if err != nil {
		return err
	}

	pgpArmorKey, err := keyPair.EncodePGPArmor([]byte(nil))
	if err != nil {
		return err
	}

	recoveryMnemonic, err := keyPair.EncodeMnemonic()
	if err != nil {
		return err
	}

	fmt.Printf("Generated OpenPGP private key with %d bits of entropy:\n\n%s\n\n\n", seed.EntropyBitCount, pgpArmorKey)

	// TODO print debug info about key
	// TODO print in color

	fmt.Printf("This is the key mnemonic which can be used to recover the private key:\n\n")
	printMnemonic(recoveryMnemonic)
	fmt.Printf("\nSave this phrase in a secure place, preferably offline on paper.\n")
	fmt.Printf("If you do not save it now, you will NEVER see this phrase again.\n\n")

	return nil
}

func printMnemonic(words []string) {
	for i, word := range words {
		humanIndex := strconv.Itoa(i + 1)
		spacing := strings.Repeat(" ", 4-len(humanIndex))
		fmt.Printf("%s:%s%s\n", humanIndex, spacing, word)
	}
}
