# mnemonikey

_Determinstic backup and recovery of PGP keys using human-readable phrases._

|Generation|Recovery|
|----------|--------|
|![generate](https://user-images.githubusercontent.com/31221309/204209819-815ab01b-cf45-4424-8db9-f1d1f5fd56fb.gif)|![recover](https://user-images.githubusercontent.com/31221309/204209831-2621a840-da98-4e5c-ac28-2837b7098b38.gif)|

Mnemonikey allows you to back up your PGP keys without managing highly sensitive and awkward digital files, without any loss of security.

Mnemonikey determinstically derives a full set of PGP keys based on a secure, randomly generated seed. That seed (and the key creation timestamp) is then re-exported in the form of an English phrase which you can record on paper to fully back up your PGP key. The recovery phrase is encoded similarly to [how Bitcoin wallets are backed up](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), and even uses the same word list for better cross-compatibility (although the number of words in a Mnemonikey recovery phrase is different).

## PGP Key Backup Alternatives

|Backup Format|Secure|Memorizable|Offline|Robust|
|:-----------:|:----:|:---------:|:-----:|:------------------------:|
|Secret Key File on a hard drive or SD card|:heavy_check_mark:|:x:|:x:|:x:|
|[`passphrase2pgp`](https://github.com/skeeto/passphrase2pgp)|:x:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|
|[`paperkey`](https://www.jabberwocky.com/software/paperkey/)|:white_check_mark: *|:x:|:heavy_check_mark:|:heavy_check_mark:|
|**`mnemonikey`**|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|

<sub>\* `paperkey` printouts are only as secure as the printer used to print them</sub>

## Installation

To use the `mnemonikey` command-line interface utility, first [install Golang](https://go.dev/dl), and then run:

```
$ go install github.com/kklash/mnemonikey/cmd/mnemonikey@latest
```

To use `mnemonikey` as a Golang library:
```
$ go get -u github.com/kklash/mnemonikey
```

## Acknowledgements

Thanks to Chris Wellons (@skeeto) and [his awesome tool, `passphrase2pgp`](https://github.com/skeeto/passphrase2pgp) for inspiring me, and serving as a helpful reference for how PGP keys are serialized into packets.

# Specification

Here follows a specification which would allow anyone to re-implement `mnemonikey` in another language.

-------------

## Definitions

| Word | Definition |
|------|------------|
| PGP Key Pair | A pair of PGP keys: the master key for certification, and subkeys for signing, encryption, and authentication. |
| Mnemonikey Epoch | Midnight in UTC time on new year's eve between 2021 and 2022 (AKA `1640995200` in unix time). This is used to identify the absolute time encoded by the key creation offset. |
| Key Creation Offset | The number of seconds after the mnemonikey epoch when the PGP key pair was created. This offset is serialized as a 30-bit number in the backup payload. |
| Seed | A securely-generated random integer, containing at least 128 bits of entropy. |
| Backup Payload | The combination of a seed and key creation offset. Together, they form a backup payload, which can be used to fully recover a PGP key pair |
| Recovery Phrase / Mnemonic Phrase | A sequence of 15 or more english words which encodes the backup payload and checksum. |
| Checksum Generator Polynomial | The CRC-32 IEEE generator polynomial. Used for checksumming the backup payload. $x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1$) |

## Goals

Mnemonikey is primarily concerned with defining two high-level procedures:

- **Key Derivation:** Deterministically deriving a usable PGP key pair from a seed and key creation time.
- **Mnemonic Encoding:** Encoding a seed and key creation time into a mnemonic phrase for later decoding & recovery.

## Dependencies

| Dependency | Usage |
|------------|-------|
|[The BIP39 English Word List](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)|Encodes the backup payload into a form that is easy to write down on paper, or remember mnemonically. Each word is one of 2048 potential words, thus encodes 11 bits of information.|
|[HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)|Stretches the seed into suitable PGP private keys. |
|[ED25519 (EdDSA)](https://ed25519.cr.yp.to/)|Algorithm used for the certification master key, and for the authentication and signing subkeys. Used to create signatures to bind the PGP key pair together.|
|[Curve25519 (ECDH)](https://en.wikipedia.org/wiki/Curve25519)|Generates the encryption subkey.|
|CRC (cyclic redundancy check)|Used to checksum the recovery phrase.|

## Key Derivation

### Inputs

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`seed`| A securely-generated random integer with $n$ bits of entropy. This implies there are $2^n$ possible seeds, in the range $0 <= x < 2^n$. $n$ must be at least 128. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **30-bit** unsigned integer. | YES |
|`name`| A human-readable display name used to build the PGP key's user-identifier string. | NO |
|`email`| An email address used to build the PGP key's user-identifier string. | NO |
|`expiry`| An 32-bit expiry timestamp applied to the output PGP key pair. | NO |
|`password`| A byte-array used to symmetrically encrypt the output PGP key pair. | NO |


### Output

A serialized PGP private key, containing a certification-enabled ED25519 master key, along with properly bound signing, encryption, and authentication subkeys.

- If `password` was provided, the output key pair will be encrypted using OpenPGP's String-to-Key (S2K) protocol.
- If `expiry` was provided, the output key pair will be set to expire at that time.
- If `name` and/or `email` was provided, they form the key's user-identifier (UID).

### Procedure

1. Determine the exact key creation timestamp based on `creationOffset` by interpreting `creationOffset` as the number of seconds after the Mnemonikey Epoch.
    - `creation = creationOffset + 1640995200`
1. Derive the master key and subkeys from the `seed`.
    - Apply `HDKF-Expand` to `seed` using SHA256 with the string `"mnemonikey"` as the _info_ parameter.
    - Read 64 bytes from the output of `HKDF-Expand`.
    - Use the **first** 32 bytes of `HDKF-Expand` as the ED25519 signing and certification master key.
    - Use the **next** 32 bytes of `HDKF-Expand` as the Curve25519 ECDH encryption subkey.
    - Use the **next** 32 bytes of `HDKF-Expand` as the ED25519 authentication subkey.
    - Use the **last** 32 bytes of `HDKF-Expand` as the ED25519 signing subkey.
1. Derive the ED25519 and Curve25519 public keys for the master key and subkeys.
    - The exact cryptographic procedure for public-key derivation and signatures is out-of-scope for this specification. See [the original Curve25519 paper](https://cr.yp.to/ecdh/curve25519-20060209.pdf) and [the original ED25519 paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf) by Daniel Bernstein and friends.
    - Most modern languages will have libraries available to perform this cryptography for you.
1. Build a PGP user ID (UID) string.
    - If `name` is defined, and `email` is not, set `uid = name`.
    - If `email` is defined, and `name` is not, set `uid = email`.
    - If both `name` and `email` are defined, set `uid = name + " <" + email + ">"`.
1. Use the master signing key to create a positive self-certification signature on the master key, committing to `uid` and `creation`.
    - If `expiry` is defined, commit the self-certification signature to that master key expiry time.
    - Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how this signature should be computed.
    - This signature should also commit to the symmetric cipher alogirithm AES-256, and the hash algorithm SHA-256.
    - Call this `certificationSig`.
1. Use the master signing key to create binding signatures on each subkey, committing to `creation`.
    - If `expiry` is defined, commit the binding signatures to that as the subkey expiry time.
    - Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how these signatures should be computed.
    - Call these `encryptionBindSig`, `authenticationBindSig`, and `signingBindSig` for the encryption, authentication, and signing subkeys respectively.
1. Serialize and return the following as OpenPGP packets:
    - [Master private key](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-secret-key-packet-formats)
        - If `password` was provided, encrypt the private key using OpenPGP's String-To-Key algorithm.
    - [`uid` (packet type 13)](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-user-id-packet-tag-13)
    - [`certificationSig`](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-signature-packet-tag-2)
    - [Encryption subkey](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-secret-key-packet-formats)
        - If `password` was provided, encrypt the private key using [OpenPGP's String-To-Key algorithm](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-string-to-key-usage).
    - [`encryptionBindSig`](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-signature-packet-tag-2)
    - [Authentication subkey](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-secret-key-packet-formats)
        - If `password` was provided, encrypt the private key using [OpenPGP's String-To-Key algorithm](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-string-to-key-usage).
    - [`authenticationBindSig`](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-signature-packet-tag-2)
    - [Signing subkey](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-secret-key-packet-formats)
        - If `password` was provided, encrypt the private key using [OpenPGP's String-To-Key algorithm](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-string-to-key-usage).
    - [`signingBindSig`](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-signature-packet-tag-2)

The resulting serialized binary blob is a usable OpenPGP private key, deterministically derived from the seed. It can be encoded to ASCII Armor format as an OpenPGP Private Key block for easy copy-pasting, or imported directly into an OpenPGP implementation like `gpg`.

### PGP Considerations and Parameters

- PGP keys and signature packets must be encoded with the OpenPGP version 4 format.
- Key derivation parameters should be set to SHA-256 and AES-256.
    - SHA-256 and AES-256 are also set as the hash and cipher preferences in the self-certification signature. This is not mandatory, but reduces the risk that software into which the key is imported will use outdated defaults like SHA1 and Tripe-DES, by providing a safe default set of algorithms which is usually available for most software.
- The master key must be configured with Certify flag. Its algorithm must be set to EDDSA (`22`).
- The encryption subkey must be configured with Encrypt-Communications (`0x04`) and Encrypt-Storage (`0x08`) flags. Its algorithm must be set to ECDH (`18`).
- The authentication subkey must be configured with the Authentication (`0x20`) flag. Its algorithm must be set to EDDSA (`22`).
- The signing subkey must be configured with the Signing (`0x02`) flag. Its algorithm must be set to EDDSA (`22`).
- The self-certification signature must use a positive-certification signature type (`0x13`).
- The subkey binding signatures must use type `0x18`.
- Signatures should use SHA256 as the hashing function.
- Signature timestamps should be the same as the key `creation` timestamp to ensure signatures are determinstic, regardless of when keys are recovered.

## Mnemonic Encoding

### Inputs

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`seed`| A securely-generated random integer with $n$ bits of entropy. This implies there are $2^n$ possible seeds, in the range $0 <= x < 2^n$. $n$ must be at least 128, and $n + 37$ should be evenly divisible by 11. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **30-bit** integer. | YES |

### Output

An english phrase of at least 15 words which completely encodes the `seed` and the `creationOffset`.

### Procedure

1. Shift `seed` left by 30 bits and bitwise-OR it with the 30-bit integer `creationOffset`.
    - Call the result `backupPayload`.
    - `backupPayload = (seed << 30) | creationOffset`
1. Serialize the `backupPayload` as a big-endian byte array, with `ceil((n+30) / 8)` bytes.
    - Call the result `backupPayloadBytes`
    - `backupPayloadBytes = backupPayload.to_bytes(ceil((n+30)/8), 'big')`
1. Compute a 7-bit checksum on `backupPayloadBytes` using a cyclic-redundancy-check (CRC).
    - Use the Checksum Generator Polynomial to generate a 32-bit CRC.
    - Take the lowest order 7 bits of the CRC output.
    - `checksum = 0x7F & crc32(backupPayloadBytes)`
    - Example: The 7-bit checksum of `"hello"` in UTF-8 would be `0x7F & crc32([0x68, 0x65, 0x6c, 0x6c, 0x6f]) = 6`
1. Append `checksum` as the lowest order bits of `backupPayload`.
    - `backupPayload = (backupPayload << 7) | checksum`
1. Chunk the backup payload into 11-bit symbols.
    - $n$ should have been selected such that the total number of bits encoded $n + 30 + 7$ is evenly divisible by 11.
    - `[(backupPayload >> (i*11)) & 0x7FF for i in range((n+37) / 11)]`
1. Interpret each 11-bit symbol as a big-endian integer, mapping to the word at that index in the BIP39 word list.
1. Return the resulting list of words.

## Design Motivation

Normally, PGP key backups must be done manually by backing up private key export files, but files can be easily lost, corrupted, or deleted accidentally. Whenever new subkeys are added to the master key, the backup must be updated manually. This is a risky and error-prone practice, as I have personally discovered several times.

Many early users of [Bitcoin](https://bitcoin.org) also learned this lesson in a different context. In 2013, [mnemonic recovery phrases were invented to resolve it](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). They eventually became the norm for Bitcoin wallet backups. The purpose of Mnemonikey is to securely and deterministically generate a PGP key, and export a back up containing the minimum amount of information needed to repeat the key generation process. This backup can be used to recover the PGP key without adverse effects, much in the same way a BIP39 recovery phrase allows the bearer to re-derive the keys in a cryptocurrency wallet.

OpenPGP keys are identified by their fingerprint, which is a hash of the serialized public key, including its creation time. That means in order to make deterministic key backup and recovery possible without invalidating the previous key's signatures, the creation time must either be encoded into the backup, or it must be a static constant used for all keys. We chose to encode the creation time into the backup, because having distinct key creation times is convenient and worth the extra few bits of information lengthening the backup.

We could have expected the user to provide a copy of the original public key when recovering, since an OpenPGP public key packet would also contain the key creation timestamp. This is the approach used by [`paperkey`](https://www.jabberwocky.com/software/paperkey/) However, to the layman it is counterintuitive to require the _public key_ to recover a _private key,_ so instead we keep a minimum of recovery information bundled in the recovery phrase, and restrict the generation process tightly so as to enforce determinism when the key is re-generated later. This choice also simplifies Mnemonikey implementations, because they do not need to be concerned with _parsing_ OpenPGP key packets, only _generating_ them.

ED25519 has a security level of 128 bits. Using more than 128 bits of seed entropy to generate ED25519 keys doesn't add extra security, and would increase the size of the recovery phrase making it more difficult to write down or memorize. Using _less_ than 128 bits of seed entropy would make keys more succeptible to brute-force attacks. Thus, we use 128 bits as the default quantity of entropy needed to create an OpenPGP key.

Key creation times in OpenPGP keys are represented as 32-bit unix timestamps. We can save a bit more space by reducing the size of the key creation timestamp slightly. We don't need a full 32-bits of precision, since a very large chunk of time since the unix epoch on `1970-01-01` has already passed, and Mnemonikey was invented in 2022. If we define our own epoch, we can easily trim down to 30 bits of precision, while retaining perfect second-level accuracy, and supporting key creation times until `2056-01-10`. Hopefully by then, people will have adopted more advanced cryptography tools than PGP.

We could reduce the size of the key creation timestamp much more by sacrificing timestamp granularity. If we were OK with per-day accuracy only, we could reduce the creation offset integer's size to 15-bits of precision, but this comes at the cost of privacy: Keys created with such granularity in their timestamp could be easily identified as having come from Mnemonikey.

Each word in a recovery phrase is one of 2048 ($2^11$) different words, and thus encodes 11 bits of information. To encode a recovery phrase, we need to store both the entropy (128 bits) and the key creation time offset from the epoch (30 bits). $128 + 30 = 158$ and $\frac{158}{11} = 14\frac{4}{11}$. Therefore, the minimum number of words we could use to encode the full backup payload would be 15 words, leaving 7 unused bits.

These last 7 bits can be used for a checksum to ensure Mnemonikey implementations can confirm at a glance whether a user has entered the recovery phrase correctly. Words in a phrase must already be part of the BIP39 wordlist to be valid, but on the off-chance a user enters another valid but incorrect word, the checksum provides error detection with a collision probability of roughly $\frac{1}{128}$. With a word list of 2048 valid words, that means there are only 16 possible collision-causing 1-word substitutions which the user could accidentally perform for each word in the phrase.

## Mnemonic Bit-Map

This diagram demonstrates the bit-level layout of each word in the mnemonic, and how it encodes the backup payload and checksum. Each number from `0` to `a` (10) is an index of each of the 11 bits encoded by a word in the mnemonic.

```
|--------------------------------------- entropy ---------------------------------------|
|------- word 0 ------|------- word 1 ------|------- word 2 ------|------- word 3 ------|
 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a

---------------------------------------- entropy ----------------------------------------
|------- word 4 ------|------- word 5 ------|------- word 6 ------|------- word 7 ------|
 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a

---------------------------------------- entropy ----------------------------------------
|------- word 8 ------|------- word 9 ------|------- word 10 -----|------- word 11------|
 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a

-- entropy ---|-------------------- creation timestamp -------------------|- check-sum -|
|------- word 12 -----|------- word 13 -----|------- word 14 -----|------- word 15 -----|
 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a
```

