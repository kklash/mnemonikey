package main

import (
	"flag"
)

// GenerateRecoverOptions is the set of options common to both recover and generate commands.
type GenerateRecoverOptions struct {
	Name    string
	Email   string
	Expiry  string
	Encrypt bool
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
}
