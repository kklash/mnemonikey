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
	Common GenerateRecoverOptions
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
		opts.Common.AddFlags(flags)
	},
	Execute: func(opts *GenerateOptions, args []string) error {
		return generateAndPrintKey(opts)
	},
}

func generateAndPrintKey(opts *GenerateOptions) error {
	name := strings.TrimSpace(opts.Common.Name)
	email := strings.TrimSpace(opts.Common.Email)

	var (
		creation = time.Now()
		expiry   time.Time
		err      error
	)

	if opts.Common.Expiry != "" {
		expiry, err = parseExpiry(creation, opts.Common.Expiry)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	if opts.Common.WordCount < mnemonikey.MinMnemonicSize {
		return fmt.Errorf("%w: invalid word count %d", ErrPrintUsage, opts.Common.WordCount)
	}

	seed, err := mnemonikey.GenerateSeed(rand.Reader, opts.Common.WordCount)
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

	fmt.Printf("Generated OpenPGP private key with %d bits of entropy:\n\n", seed.EntropyBitCount)
	fmt.Print(magenta(pgpArmorKey) + "\n\n")

	// TODO print debug info about key

	fmt.Print("This is the mnemonic phrase which can be used to recover the private key:\n\n")
	printMnemonic(recoveryMnemonic)
	fmt.Print("\nSave this phrase in a secure place, preferably offline, on paper.\n\n")
	fmt.Print(
		underline(
			"If you do not save it now, you will " + bold("NEVER") + " see this phrase again.\n\n",
		),
	)

	return nil
}

func printMnemonic(words []string) {
	for i, word := range words {
		humanIndex := strconv.Itoa(i + 1)
		spacing := strings.Repeat(" ", 4-len(humanIndex))
		fmt.Printf("%s:%s%s\n", humanIndex, spacing, bold(magenta((word))))
	}
}
