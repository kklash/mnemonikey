package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/kklash/mnemonikey"
)

// CommonOptions is a set of options common to every command.
type CommonOptions struct {
	Verbose bool
}

// AddFlags registers the common set of options as command line flags.
func (opts *CommonOptions) AddFlags(flags *flag.FlagSet) {
	flags.BoolVar(
		&opts.Verbose,
		"verbose",
		false,
		"Print extra debugging information to stderr when building keys.",
	)
}

// GenerateRecoverOptions is the set of options common to both recover and generate commands.
type GenerateRecoverOptions struct {
	Name         string
	Email        string
	TTL          string
	EncryptKeys  bool
	OnlyKeyTypes string
}

// AddFlags registers the common set of options as command line flags.
func (opts *GenerateRecoverOptions) AddFlags(flags *flag.FlagSet) {
	flags.StringVar(
		&opts.Name,
		"name",
		DefaultName,
		"Display name for the PGP key user identifier.",
	)

	flags.StringVar(
		&opts.Email,
		"email",
		"",
		"Email for the PGP key user identifier.",
	)

	flags.StringVar(
		&opts.TTL,
		"ttl",
		"",
		"Set a time-to-live validity `period` on the exported key. Can be a number denominated in "+
			"days (d) weeks (w) months (m) or years (y) relative to the key creation time, such as "+
			"\"24d\" or \"2y\" after key creation.",
	)

	flags.BoolVar(
		&opts.EncryptKeys,
		"encrypt-keys",
		false,
		"Encrypt the derived PGP private keys with a password when exporting them.",
	)

	flags.StringVar(
		&opts.OnlyKeyTypes,
		"only",
		"",
		"Only output a subset key containing the given key `types` as PGP packets. A comma-delimited "+
			"list of the following possible values:  master | encryption | signing | authentication",
	)
}

// DecodeOnlyKeyTypes decodes the comma-delimited list of selected key types.
// Returns whether the list includes 'master', and which other subkey types were
// selected. Returns an error if the list includes an unknown string.
func (opts *GenerateRecoverOptions) DecodeOnlyKeyTypes() (
	outputMasterKey bool,
	subkeyTypes []mnemonikey.SubkeyType,
	err error,
) {
	outputMasterKey = true
	if opts.OnlyKeyTypes != "" {
		outputMasterKey = false
		onlyKeyTypes := strings.Split(opts.OnlyKeyTypes, ",")
		subkeyTypes = make([]mnemonikey.SubkeyType, 0, len(onlyKeyTypes))

		for _, keyType := range onlyKeyTypes {
			if keyType == "master" {
				outputMasterKey = true
			} else if keyType == string(mnemonikey.SubkeyTypeEncryption) ||
				keyType == string(mnemonikey.SubkeyTypeAuthentication) ||
				keyType == string(mnemonikey.SubkeyTypeSigning) {
				subkeyTypes = append(subkeyTypes, mnemonikey.SubkeyType(keyType))
			} else {
				err = fmt.Errorf("%w: unknown -only list element %q", ErrPrintUsage, keyType)
				return
			}
		}
	}
	return
}

// RecoverConvertOptions is the set of options common to both recover and convert commands.
type RecoverConvertOptions struct {
	SimpleInput   bool
	InputWordFile string
}

// AddFlags registers the common set of options as command line flags.
func (opts *RecoverConvertOptions) AddFlags(flags *flag.FlagSet) {
	flags.BoolVar(
		&opts.SimpleInput,
		"simple",
		false,
		"Revert to a simpler terminal input mechanism for entering the recovery "+
			"phrase. Useful if the fancy terminal manipulation used by the default "+
			"input mode doesn't work on your system.",
	)

	flags.StringVar(
		&opts.InputWordFile,
		"in-word-file",
		"",
		"Read the words of the mnemonic from this `file`. Words should be separated by whitespace "+
			"and the file should contain the exact words. Useful for debugging.",
	)
}

// GenerateConvertOptions is the set of options common to both generate and convert commands.
type GenerateConvertOptions struct {
	OutputWordFile string
}

// AddFlags registers the common set of options as command line flags.
func (opts *GenerateConvertOptions) AddFlags(flags *flag.FlagSet) {
	flags.StringVar(
		&opts.OutputWordFile,
		"out-word-file",
		"",
		"Write the words of the recovery phrase to this `file` in PLAIN TEXT. Useful for debugging. "+
			"Do not use this if you care about keeping your keys safe. Words will be separated by a "+
			"single space. The file will contain the exact words and nothing else.",
	)
}
