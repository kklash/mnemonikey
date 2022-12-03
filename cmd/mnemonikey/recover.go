package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/kklash/mnemonikey"
)

const maxSubkeyIndex uint = 0xFFFF

type RecoverOptions struct {
	Common      GenerateRecoverOptions
	SimpleInput bool

	EncryptionSubkeyIndex     uint
	AuthenticationSubkeyIndex uint
	SigningSubkeyIndex        uint
}

var RecoverCommand = &Command[RecoverOptions]{
	Name:        "mnemonikey recover",
	Description: "Recover an OpenPGP private key from an existing mnemonic recovery phrase.",
	UsageExamples: []string{
		"mnemonikey recover",
		"mnemonikey recover -name myuser",
		"mnemonikey recover -name=myuser -email someone@someplace.com",
		"mnemonikey recover -name myuser -enc-index 3 -auth-index=2",
		"mnemonikey recover -expiry 2y",
		"mnemonikey recover -expiry=17w",
		"mnemonikey recover -expiry 1679285000",
		"mnemonikey recover -simple -name myuser",
	},
	AddFlags: func(flags *flag.FlagSet, opts *RecoverOptions) {
		opts.Common.AddFlags(flags)

		flags.BoolVar(
			&opts.SimpleInput,
			"simple",
			false,
			justifyOptionDescription(
				"Revert to a simpler terminal input mechanism for entering the recovery "+
					"phrase. Useful if the fancy terminal manipulation used by the default "+
					"input mode doesn't work on your system. (optional)",
			),
		)

		flags.UintVar(
			&opts.EncryptionSubkeyIndex,
			"enc-index",
			0,
			justifyOptionDescription("The index of the encryption subkey which will be recovered."),
		)
		flags.UintVar(
			&opts.AuthenticationSubkeyIndex,
			"auth-index",
			0,
			justifyOptionDescription("The index of the authentication subkey which will be recovered."),
		)
		flags.UintVar(
			&opts.SigningSubkeyIndex,
			"sig-index",
			0,
			justifyOptionDescription("The index of the signing subkey which will be recovered."),
		)
	},
	Execute: func(opts *RecoverOptions, args []string) error {
		return recoverAndPrintKey(opts)
	},
}

func recoverAndPrintKey(opts *RecoverOptions) error {
	keyOptions := &mnemonikey.KeyOptions{
		Name:                      strings.TrimSpace(opts.Common.Name),
		Email:                     strings.TrimSpace(opts.Common.Email),
		EncryptionSubkeyIndex:     uint16(opts.EncryptionSubkeyIndex),
		AuthenticationSubkeyIndex: uint16(opts.AuthenticationSubkeyIndex),
		SigningSubkeyIndex:        uint16(opts.SigningSubkeyIndex),
	}

	var err error
	if opts.Common.Expiry != "" {
		keyOptions.Expiry, err = parseExpiry(time.Now(), opts.Common.Expiry)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	if opts.EncryptionSubkeyIndex > maxSubkeyIndex ||
		opts.AuthenticationSubkeyIndex > maxSubkeyIndex ||
		opts.SigningSubkeyIndex > maxSubkeyIndex {
		return fmt.Errorf("invalid subkey index; must be less than or equal to %d", maxSubkeyIndex)
	}

	var words []string
	if opts.SimpleInput {
		words, err = userInputMnemonicSimple(mnemonikey.MnemonicSize)
	} else {
		words, err = userInputMnemonic(mnemonikey.MnemonicSize)
	}
	if err != nil {
		return err
	}

	mnk, err := mnemonikey.Recover(words, keyOptions)
	if err != nil {
		return fmt.Errorf("failed to re-derive PGP keys: %w", err)
	}

	var password []byte
	if opts.Common.Encrypt {
		password, err = userInputPassword()
		if err != nil {
			return err
		}
	}

	pgpArmorKey, err := mnk.EncodePGPArmor(password)
	if err != nil {
		return err
	}

	// TODO print debug data about derived key, Key ID, etc.
	eprintf("Re-derived OpenPGP key with fingerprint %X\n\n", mnk.FingerprintV4())
	eprint(magentaStart)
	fmt.Println(pgpArmorKey)
	eprint(colorEnd)

	return nil
}
