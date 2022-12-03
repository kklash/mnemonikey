package mnemonikey

import "time"

// KeyOptions are a set of optional parameters which can be supplied when generating
// or recovering Mnemonikeys. They affect specific parameters in the output PGP keys
// but are not needed to recover the private keys themselves.
type KeyOptions struct {
	// Name and Email are used to build the user ID for a PGP key.
	Name, Email string

	// Expiry sets when the generated key is supposed to expire.
	Expiry time.Time

	// These are indices which allow the caller to choose a specific subkey to generate.
	// Each subkey at different indices is completely independent of each other - there is
	// no hierarchy.
	EncryptionSubkeyIndex     uint16
	AuthenticationSubkeyIndex uint16
	SigningSubkeyIndex        uint16

	// Subkeys is a list of the types of subkeys to derive. If this list is nil, a full
	// set of three subkeys will be generated for encryption, authentication, and signing.
	Subkeys []SubkeyType
}

// subkeyEnabled returns true if the options indicate the given type of subkey should be generated.
func (opts *KeyOptions) subkeyEnabled(targetType SubkeyType) bool {
	if opts.Subkeys == nil {
		return true
	}

	for _, subkeyType := range opts.Subkeys {
		if subkeyType == targetType {
			return true
		}
	}
	return false
}
