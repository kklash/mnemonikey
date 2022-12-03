package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kklash/mnemonikey"
)

var DefaultName = "anonymous"

type GenerateOptions struct {
	Common   GenerateRecoverOptions
	WordFile string
}

var GenerateCommand = &Command[GenerateOptions]{
	Name:        "mnemonikey generate",
	Description: "Generate a new OpenPGP key and its mnemonic recovery phrase.",
	UsageExamples: []string{
		"mnemonikey generate",
		"mnemonikey generate -name username",
		"mnemonikey generate -name username -email bob@hotmail.com",
		"mnemonikey generate -name username -only master,encryption",
		"mnemonikey generate -expiry 2y",
		"mnemonikey generate -expiry 17w",
		"mnemonikey generate -expiry 1679285000",
	},
	AddFlags: func(flags *flag.FlagSet, opts *GenerateOptions) {
		opts.Common.AddFlags(flags)

		flags.StringVar(
			&opts.WordFile,
			"word-file",
			"",
			"Write the words of the recovery phrase to this `file` in PLAIN TEXT. Useful for debugging. "+
				"Do not use this if you care about keeping your keys safe. Words will be separated by a "+
				"single space and the file will contain the exact 15 words and nothing else.",
		)
	},
	Execute: func(opts *GenerateOptions, args []string) error {
		return generateAndPrintKey(opts)
	},
}

func generateAndPrintKey(opts *GenerateOptions) error {
	keyOptions := &mnemonikey.KeyOptions{
		Name:  strings.TrimSpace(opts.Common.Name),
		Email: strings.TrimSpace(opts.Common.Email),
	}

	var (
		creation = time.Now()
		err      error
	)

	if opts.Common.Expiry != "" {
		keyOptions.Expiry, err = parseExpiry(creation, opts.Common.Expiry)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	if opts.WordFile != "" {
		if _, err := os.Stat(opts.WordFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("refused to write word-file to %s: file already exists", opts.WordFile)
		}
	}

	outputMasterKey, subkeyTypes, err := opts.Common.DecodeOnlyKeyTypes()
	if err != nil {
		return err
	}
	keyOptions.Subkeys = subkeyTypes

	seed, err := mnemonikey.GenerateSeed(rand.Reader)
	if err != nil {
		return err
	}

	mnk, err := mnemonikey.New(seed, creation, keyOptions)
	if err != nil {
		return err
	}

	var password []byte
	if opts.Common.Encrypt {
		password, err = userInputPassword()
		if err != nil {
			return err
		}
	}

	var pgpArmorKey string
	if outputMasterKey {
		pgpArmorKey, err = mnk.EncodePGPArmor(password)
	} else {
		pgpArmorKey, err = mnk.EncodeSubkeysPGPArmor(password)
	}
	if err != nil {
		return err
	}

	recoveryMnemonic, err := mnk.EncodeMnemonic()
	if err != nil {
		return err
	}

	if opts.WordFile != "" {
		wordFileContent := strings.Join(recoveryMnemonic, " ") + "\n"
		if err := os.WriteFile(opts.WordFile, []byte(wordFileContent), 0600); err != nil {
			return fmt.Errorf("failed to write words to file: %w", err)
		}
	}

	eprintf("Generated OpenPGP private key with %d bits of entropy.\n", mnemonikey.EntropyBitCount)
	eprintf("Key fingerprint: %X\n", mnk.FingerprintV4())
	eprintln(magentaStart)
	fmt.Println(pgpArmorKey)
	eprintln(colorEnd)

	// TODO print debug info about key

	if opts.WordFile == "" {
		eprint("This is the mnemonic phrase which can be used to recover the private key:\n\n")
		printMnemonic(recoveryMnemonic)
		eprint("\nSave this phrase in a secure place, preferably offline, on paper.\n\n")
		eprint(
			underline(
				"If you do not save it now, you will " + bold("NEVER") + " see this phrase again.\n\n",
			),
		)
	}

	return nil
}

func printMnemonic(words []string) {
	for i, word := range words {
		humanIndex := strconv.Itoa(i + 1)
		spacing := strings.Repeat(" ", 4-len(humanIndex))
		eprintf("%s:%s%s\n", humanIndex, spacing, bold(magenta((word))))
	}
}
