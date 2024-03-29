package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kklash/mnemonikey"
	"github.com/kklash/wordlist4096"
)

const maxSubkeyIndex uint = 0xFFFF

type RecoverOptions struct {
	CommonOptions
	GenerateRecoverOptions
	RecoverConvertOptions

	SelfCert                  bool
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
		"mnemonikey recover -name myuser -only master",
		"mnemonikey recover -name myuser -enc-index 3 -only master,encryption",
		"mnemonikey recover -name myuser -auth-index 12 -only authentication -self-cert=false",
		"mnemonikey recover -ttl 2y",
		"mnemonikey recover -ttl=17w",
		"mnemonikey recover -simple -name myuser",
	},
	AddFlags: func(flags *flag.FlagSet, opts *RecoverOptions) {
		opts.CommonOptions.AddFlags(flags)
		opts.GenerateRecoverOptions.AddFlags(flags)
		opts.RecoverConvertOptions.AddFlags(flags)

		flags.BoolVar(
			&opts.SelfCert,
			"self-cert",
			true,
			"This flag decides if mnemonikey will output the master key's self-certification signature "+
				"or not. Set "+magenta("-self-cert=false")+" if you are importing keys into a keyring which "+
				"already has the master key, to avoid adding extra signatures to the key.",
		)

		flags.UintVar(
			&opts.EncryptionSubkeyIndex,
			"enc-index",
			0,
			"The `index` of the encryption subkey which will be recovered.",
		)
		flags.UintVar(
			&opts.AuthenticationSubkeyIndex,
			"auth-index",
			0,
			"The `index` of the authentication subkey which will be recovered.",
		)
		flags.UintVar(
			&opts.SigningSubkeyIndex,
			"sig-index",
			0,
			"The `index` of the signing subkey which will be recovered.",
		)
	},
	Execute: func(opts *RecoverOptions, args []string) error {
		return recoverAndPrintKey(opts)
	},
}

func decodeMnemonicFromInput(
	opts RecoverConvertOptions,
	verbose bool,
) (*mnemonikey.Seed, *mnemonikey.DecodedMnemonic, error) {
	var (
		words []string
		err   error
	)
	if opts.InputWordFile != "" {
		words, err = readWordFile(opts.InputWordFile)
	} else if opts.SimpleInput {
		words, err = userInputMnemonicSimple()
	} else {
		words, err = userInputMnemonic()
	}
	if err != nil {
		return nil, nil, err
	}

	decodedMnemonic, err := mnemonikey.DecodeMnemonic(words)
	if err != nil {
		return nil, nil, err
	}

	if verbose {
		eprintln("Decoded mnemonic recovery phrase:")
		printDebugInfo(os.Stderr, [][2]string{
			{"version", strconv.Itoa(int(decodedMnemonic.Version))},
			{"era", strconv.Itoa(int(decodedMnemonic.Version.Era()))},
			{"encrypted", fmt.Sprint(decodedMnemonic.Encrypted())},
		})
		eprintln()
	}

	for {
		var phrasePassword []byte
		if decodedMnemonic.Encrypted() {
			phrasePassword, err = userInputPassword("Enter phrase decryption password: ", false)
			if err != nil {
				return nil, nil, err
			}
		}

		// If the phrase is not encrypted, this will still return the correct seed.
		seed, err := decodedMnemonic.DecryptSeed(phrasePassword)
		if errors.Is(err, mnemonikey.ErrMnemonicDecryption) {
			eprintln(red(err.Error()))
			continue
		} else if err != nil {
			return nil, nil, err
		}
		return seed, decodedMnemonic, nil
	}
}

func recoverAndPrintKey(opts *RecoverOptions) error {
	keyOptions := &mnemonikey.KeyOptions{
		Name:                      strings.TrimSpace(opts.Name),
		Email:                     strings.TrimSpace(opts.Email),
		EncryptionSubkeyIndex:     uint16(opts.EncryptionSubkeyIndex),
		AuthenticationSubkeyIndex: uint16(opts.AuthenticationSubkeyIndex),
		SigningSubkeyIndex:        uint16(opts.SigningSubkeyIndex),
	}

	var err error
	if opts.TTL != "" {
		keyOptions.TTL, err = parseTTL(opts.TTL)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	if opts.EncryptionSubkeyIndex > maxSubkeyIndex ||
		opts.AuthenticationSubkeyIndex > maxSubkeyIndex ||
		opts.SigningSubkeyIndex > maxSubkeyIndex {
		return fmt.Errorf("invalid subkey index; must be less than or equal to %d", maxSubkeyIndex)
	}

	outputMasterKey, subkeyTypes, err := opts.DecodeOnlyKeyTypes()
	if err != nil {
		return err
	}
	keyOptions.Subkeys = subkeyTypes

	seed, decodedMnemonic, err := decodeMnemonicFromInput(opts.RecoverConvertOptions, opts.Verbose)
	if err != nil {
		return err
	}

	mnk, err := mnemonikey.New(seed, decodedMnemonic.Creation(), keyOptions)
	if err != nil {
		return fmt.Errorf("failed to re-derive PGP keys: %w", err)
	}

	var password []byte
	if opts.EncryptKeys {
		password, err = userInputPassword("Enter key encryption password: ", true)
		if err != nil {
			return err
		}
	}

	var pgpArmorKey string
	if outputMasterKey {
		pgpArmorKey, err = mnk.EncodePGPArmor(password)
	} else {
		pgpArmorKey, err = mnk.EncodeSubkeysPGPArmor(password, opts.SelfCert)
	}
	if err != nil {
		return err
	}

	if opts.Verbose {
		eprintln("Re-derived OpenPGP key:")
		printKeyDebugInfo(mnk)
		eprintln()
	}

	eprint(magentaStart)
	fmt.Println(pgpArmorKey)
	eprint(colorEnd)

	return nil
}

func readWordFile(fpath string) ([]string, error) {
	file, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	words := []string{}
	for scanner.Scan() {
		word := strings.ToLower(scanner.Text())
		if _, ok := wordlist4096.WordMap[word]; !ok {
			return nil, fmt.Errorf("found word in %s not present in wordlist", fpath)
		}
		words = append(words, word)

		if len(words) > 100 {
			return nil, fmt.Errorf("invalid format for word file")
		}
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("found only no words in word file %s", fpath)
	}

	version, err := mnemonikey.ParseMnemonicVersion(words[0])
	if len(words) != version.MnemonicSize() {
		return nil, fmt.Errorf(
			"found only %d words in word file %s, expected %d words for version %d phrase",
			len(words), fpath, version.MnemonicSize(), version,
		)
	}
	return words, nil
}
