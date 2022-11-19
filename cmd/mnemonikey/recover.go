package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/kklash/mnemonikey"
)

type RecoverOptions struct {
	Name        string
	Email       string
	WordCount   uint
	Expiry      string
	SimpleInput bool
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
		"mnemonikey recover -expiry 2y",
		"mnemonikey recover -expiry 17w",
		"mnemonikey recover -expiry 1679285000",
		"mnemonikey recover -simple -name myuser",
	},
	AddFlags: func(flags *flag.FlagSet, opts *RecoverOptions) {
		flags.StringVar(&opts.Name, "name", DefaultName, "Display name for the PGP key user identifier. (optional)")
		flags.StringVar(&opts.Email, "email", "", "Email for the PGP key user identifier. (optional)")
		flags.BoolVar(&opts.SimpleInput, "simple", false, "Revert to a simpler terminal input mechanism "+
			"for entering the recovery phrase. Useful if the fancy terminal manipulation used by the default input "+
			"mode doesn't work on your system. (optional)")
		flags.UintVar(&opts.WordCount, "words", mnemonikey.MinMnemonicSize, "Number of words in the "+
			"recovery mnemonic. (optional)")
		flags.StringVar(&opts.Expiry, "expiry", "", "Set an expiry period on the recovered key.\n"+
			"Can be a number denominated in days (d) weeks (w) months (m) or years (y) relative to the\n"+
			"current time, or an absolute unix timestamp number. (optional)")
	},
	Execute: func(opts *RecoverOptions, args []string) error {
		return recoverAndPrintKey(opts)
	},
}

func recoverAndPrintKey(opts *RecoverOptions) error {
	name := strings.TrimSpace(opts.Name)
	email := strings.TrimSpace(opts.Email)

	var (
		expiry time.Time
		err    error
	)
	if opts.Expiry != "" {
		expiry, err = parseExpiry(time.Now(), opts.Expiry)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	var words []string
	if opts.SimpleInput {
		words, err = userInputMnemonicSimple(opts.WordCount)
	} else {
		words, err = userInputMnemonic(opts.WordCount)
	}
	if err != nil {
		return err
	}

	keyPair, err := mnemonikey.RecoverKeyPair(words, name, email, expiry)
	if err != nil {
		return fmt.Errorf("failed to re-derive key pair: %w", err)
	}

	pgpArmorKey, err := keyPair.EncodePGPArmor([]byte(nil))
	if err != nil {
		return err
	}

	// TODO print debug data about derived key, Key ID, etc.
	fmt.Printf("Re-derived the following OpenPGP key:\n\n")
	fmt.Println(bold(magenta(pgpArmorKey)))

	return nil
}
