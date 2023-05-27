package main

import (
	"crypto/rand"
	"flag"
	"fmt"

	"github.com/kklash/mnemonikey"
)

type ConvertOptions struct {
	CommonOptions
	RecoverConvertOptions
	GenerateConvertOptions

	EncryptPhrase  bool
	OutputWordFile string
}

var ConvertCommand = &Command[ConvertOptions]{
	Name:        "mnemonikey convert",
	Description: "Add, change, or remove an encryption password on an existing mnemonic recovery phrase.",
	UsageExamples: []string{
		"mnemonikey convert",
		"mnemonikey convert -encrypt",
		"mnemonikey convert -simple",
		"mnemonikey convert -word-file /etc/words",
		"mnemonikey convert -word-file /etc/words -out-word-file /etc/new-words",
	},
	AddFlags: func(flags *flag.FlagSet, opts *ConvertOptions) {
		opts.CommonOptions.AddFlags(flags)
		opts.RecoverConvertOptions.AddFlags(flags)
		opts.GenerateConvertOptions.AddFlags(flags)

		flags.BoolVar(
			&opts.EncryptPhrase,
			"encrypt-phrase",
			false,
			"If true, encrypt the recovery phrase with a new password. The resulting phrase will "+
				"require the same password for later recovery. If false, output a plaintext phrase.",
		)
	},
	Execute: func(opts *ConvertOptions, args []string) error {
		return decodeAndConvertPhrase(opts)
	},
}

func decodeAndConvertPhrase(opts *ConvertOptions) (err error) {
	seed, decodedMnemonic, err := decodeMnemonicFromInput(opts.RecoverConvertOptions, opts.Verbose)
	if err != nil {
		return err
	}

	var recoveryMnemonic []string
	if opts.EncryptPhrase {
		phraseEncryptionPassword, err := userInputPassword("Enter phrase encryption password: ", true)
		if err != nil {
			return err
		}
		recoveryMnemonic, err = mnemonikey.EncodeMnemonicEncrypted(
			seed,
			decodedMnemonic.CreationOffset(),
			phraseEncryptionPassword,
			rand.Reader,
		)
		if err != nil {
			return err
		}
	} else {
		recoveryMnemonic, err = mnemonikey.EncodeMnemonicPlaintext(seed, decodedMnemonic.CreationOffset())
		if err != nil {
			return err
		}
	}

	if opts.InputWordFile == "" {
		printMnemonic(recoveryMnemonic)
	} else {
		if err := saveMnemonic(recoveryMnemonic, opts.InputWordFile); err != nil {
			return fmt.Errorf("failed to write words to file: %w", err)
		}
	}

	return nil
}
