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
	CommonOptions
	GenerateRecoverOptions
	GenerateConvertOptions

	EncryptPhrase bool
	UnsafeEntropy string
}

var GenerateCommand = &Command[GenerateOptions]{
	Name:        "mnemonikey generate",
	Description: "Generate a new OpenPGP key and its mnemonic recovery phrase.",
	UsageExamples: []string{
		"mnemonikey generate",
		"mnemonikey generate -name username",
		"mnemonikey generate -name username -email bob@hotmail.com",
		"mnemonikey generate -name username -only master,encryption",
		"mnemonikey generate -ttl 2y",
		"mnemonikey generate -ttl 17w",
	},
	AddFlags: func(flags *flag.FlagSet, opts *GenerateOptions) {
		opts.CommonOptions.AddFlags(flags)
		opts.GenerateRecoverOptions.AddFlags(flags)
		opts.GenerateConvertOptions.AddFlags(flags)

		flags.BoolVar(
			&opts.EncryptPhrase,
			"encrypt-phrase",
			false,
			"Encrypt the exported recovery phrase with a password. The resulting phrase will "+
				"require the same password for later recovery.",
		)
		flags.StringVar(
			&opts.UnsafeEntropy,
			"unsafe-entropy",
			"",
			bold("(UNSAFE)")+" Generate the key using seed entropy drawn directly from the given `file`. "+
				"Specify '-' to read entropy from standard input. "+bold("You probably shouldn't use this flag."),
		)
	},
	Execute: func(opts *GenerateOptions, args []string) error {
		return generateAndPrintKey(opts)
	},
}

func generateAndPrintKey(opts *GenerateOptions) error {
	keyOptions := &mnemonikey.KeyOptions{
		Name:  strings.TrimSpace(opts.Name),
		Email: strings.TrimSpace(opts.Email),
	}

	var (
		creation = time.Now()
		err      error
	)

	if opts.TTL != "" {
		keyOptions.TTL, err = parseTTL(opts.TTL)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPrintUsage, err)
		}
	}

	outputMasterKey, subkeyTypes, err := opts.DecodeOnlyKeyTypes()
	if err != nil {
		return err
	}
	keyOptions.Subkeys = subkeyTypes

	entropySource := rand.Reader
	if opts.UnsafeEntropy != "" {
		eprintln(
			red(
				bold("WARNING:") + " The -unsafe-entropy option is dangerous and can produce" +
					" weak PGP keys if used incorrectly.",
			),
		)

		if opts.UnsafeEntropy == "-" {
			entropySource = os.Stdin
		} else {
			file, err := os.Open(opts.UnsafeEntropy)
			if err != nil {
				return fmt.Errorf("failed to open entropy source file: %w", err)
			}
			defer file.Close()
			entropySource = file
		}
	}

	seed, err := mnemonikey.GenerateSeed(entropySource)
	if err != nil {
		return err
	}

	mnk, err := mnemonikey.New(seed, creation, keyOptions)
	if err != nil {
		return err
	}

	var pgpEncryptionPassword []byte
	if opts.EncryptKeys {
		pgpEncryptionPassword, err = userInputPassword("Enter key encryption password: ", true)
		if err != nil {
			return err
		}
	}

	var pgpArmorKey string
	if outputMasterKey {
		pgpArmorKey, err = mnk.EncodePGPArmor(pgpEncryptionPassword)
	} else {
		pgpArmorKey, err = mnk.EncodeSubkeysPGPArmor(pgpEncryptionPassword, true)
	}
	if err != nil {
		return err
	}

	var recoveryMnemonic []string
	if opts.EncryptPhrase {
		phraseEncryptionPassword, err := userInputPassword("Enter phrase encryption password: ", true)
		if err != nil {
			return err
		}
		recoveryMnemonic, err = mnk.EncodeMnemonicEncrypted(phraseEncryptionPassword, rand.Reader)
		if err != nil {
			return err
		}
	} else {
		recoveryMnemonic, err = mnk.EncodeMnemonicPlaintext()
		if err != nil {
			return err
		}
	}

	if opts.OutputWordFile != "" {
		if err := saveMnemonic(recoveryMnemonic, opts.OutputWordFile); err != nil {
			return fmt.Errorf("failed to write words to file: %w", err)
		}
	}

	if opts.Verbose {
		eprintf("Generated OpenPGP private key with %d bits of entropy:\n", mnemonikey.EntropyBitCount)
		printKeyDebugInfo(mnk)
		eprintln()
	}

	eprint(magentaStart)
	fmt.Println(pgpArmorKey)
	eprint(colorEnd)

	if opts.OutputWordFile == "" {
		printMnemonic(recoveryMnemonic)
	}

	return nil
}

func printMnemonic(words []string) {
	eprint("\nThis is the mnemonic phrase which can be used to recover the private key:\n\n")

	for i, word := range words {
		humanIndex := strconv.Itoa(i + 1)
		spacing := strings.Repeat(" ", 4-len(humanIndex))
		eprintf("%s:%s%s\n", humanIndex, spacing, bold(magenta((word))))
	}

	eprint("\nSave this phrase in a secure place, preferably offline, on paper.\n\n")
	eprint(
		justifyTerminalWidth(
			0,
			"Once you have saved it, use the 'mnemonikey recover' command "+
				"to verify that you have saved the phrase correctly.\n\n",
		),
	)
	eprint(
		underline(
			"If you do not save it now, you will " + bold("NEVER") + " see this phrase again.\n\n",
		),
	)
}

func saveMnemonic(words []string, wordFile string) error {
	if _, err := os.Stat(wordFile); err == nil {
		return fmt.Errorf("refused to write word-file to %s: file already exists", wordFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to write word-file to %s: path is not accessible: %w", wordFile, err)
	}

	wordFileContent := strings.Join(words, " ") + "\n"
	if err := os.WriteFile(wordFile, []byte(wordFileContent), 0600); err != nil {
		return fmt.Errorf("failed to write words to file: %w", err)
	}
	return nil
}
