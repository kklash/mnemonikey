package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/kklash/mnemonikey"
)

// GenerateRecoverOptions is the set of options common to both recover and generate commands.
type GenerateRecoverOptions struct {
	Name         string
	Email        string
	Expiry       string
	Encrypt      bool
	OnlyKeyTypes string
}

// AddFlags registers the common set of options as command line flags.
func (opts *GenerateRecoverOptions) AddFlags(flags *flag.FlagSet) {
	flags.StringVar(
		&opts.Name,
		"name",
		DefaultName,
		justifyOptionDescription("Display name for the PGP key user identifier. (optional)"),
	)

	flags.StringVar(
		&opts.Email,
		"email",
		"",
		justifyOptionDescription("Email for the PGP key user identifier. (optional)"),
	)

	flags.StringVar(
		&opts.Expiry,
		"expiry",
		"",
		justifyOptionDescription(
			"Set an expiry `period` on the exported key. Can be a number denominated "+
				"in days (d) weeks (w) months (m) or years (y) relative to the current "+
				"time, such as \"24d\" or \"2y\", or an absolute unix timestamp number. (optional)",
		),
	)

	flags.BoolVar(
		&opts.Encrypt,
		"encrypt",
		false,
		justifyOptionDescription(
			"Encrypt the derived PGP private keys with a password when exporting them. (optional)",
		),
	)

	flags.StringVar(
		&opts.OnlyKeyTypes,
		"only",
		"",
		justifyOptionDescription(
			"Only output a subset of the complete key as PGP packets. A comma-delimited list of "+
				"the following possible values:  master | encryption | signing | authentication",
		),
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
