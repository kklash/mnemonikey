# mnemonikey

_Determinstic backup and recovery of PGP keys using human-readable phrases._

|Generation|Recovery|
|----------|--------|
|![generate](https://user-images.githubusercontent.com/31221309/203456176-11f3c80e-1095-4f58-adcc-d4a62aa363dd.gif)|![recover](https://user-images.githubusercontent.com/31221309/203456179-b1f87358-6acd-42c3-80da-2d8e8fa9b86b.gif)|

Mnemonikey allows you to back up your PGP keys without managing highly sensitive and awkward digital files, without any loss of security.

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
| PGP Key Pair | A pair of PGP keys: the master key for signing and certification, and the encryption subkey for encrypting and decrypting messages or documents. |
| Mnemonikey Epoch | Midnight in UTC time on new year's eve between 2021 and 2022 (AKA `1640995200` in unix time). This is used to identify the absolute time encoded by the key creation offset. |
| Key Creation Offset | The number of seconds after the mnemonikey epoch when the PGP key pair was created. This offset is serialized as a 30-bit number in the backup payload. |
| Seed | A securely-generated random integer, containing at least 128 bits of entropy. |
| Backup Payload | The combination of a seed and key creation offset. Together, they form a backup payload, which can be used to fully recover a PGP key pair |
| Recovery Phrase / Mnemonic Phrase | A sequence of 15 or more english words which encodes the backup payload and checksum. |
| Checksum Generator Polynomial | The CRC-7-MVB generator polynomial $x^7 +x^6 +x^3 + x + 1$. Used for checksumming the bcakup payload. |

## Goals

Mnemonikey is primarily concerned with defining two high-level procedures:

- **Key Derivation:** Deterministically deriving a usable PGP key pair from a seed and key creation time.
- **Mnemonic Encoding:** Encoding a seed and key creation time into a mnemonic phrase for later decoding & recovery.

## Dependencies

| Dependency | Usage |
|------------|-------|
|[The BIP39 English Word List](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)|Encodes the backup payload into a form that is easy to write down on paper, or remember mnemonically. Each word is one of 2048 potential words, thus encodes 11 bits of information.|
|[HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)|Stretches the seed into suitable PGP private keys. |
|[ED25519 (EdDSA)](https://ed25519.cr.yp.to/)|Algorithm used for the signing+certification master key. Used to create signatures to bind the PGP key pair together.|
|[Curve25519 (ECDH)](https://en.wikipedia.org/wiki/Curve25519)|Generates the encryption subkey.|
|CRC (cyclic redundancy check)|Used to checksum the recovery phrase.|


## Key Derivation

### Inputs

| Input | Description | Required |
|-------|-------------|----------|
|`seed`| A securely-generated random integer with $n$ bits of entropy. This implies there are $2^n$ possible seeds, in the range $0 <= x < 2^n$. $n$ must be at least 128. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **30-bit** unsigned integer. | YES |
|`name`| A human-readable display name used to build the PGP key's user-identifier string. | NO |
|`email`| An email address used to build the PGP key's user-identifier string. | NO |
|`expiry`| An 32-bit expiry timestamp applied to the output PGP key pair. | NO |
|`password`| A byte-array used to symmetrically encrypt the output PGP key pair. | NO |


### Output

A serialized PGP private key, containing a signing+certification-enabled ED25519 master key.

- If `password` was provided, the output key pair will be encrypted using OpenPGP's String-to-Key (S2K) protocol.
- If `expiry` was provided, the output key pair will be set to expire at that time.
- If `name` and/or `email` was provided, they form the key's user-identifier (UID).

### Procedure

1. Determine the exact key creation timestamp based on `creationOffset` by interpreting `creationOffset` as the number of seconds after the Mnemonikey Epoch.
    - `creation = creationOffset + 1640995200`
1. Derive the master key and encryption subkey from the `seed`.
    - Apply `HDKF-Expand` to `seed` using SHA256 with the string `"mnemonikey"` as the _info_ parameter.
    - Read 64 bytes from the output of `HKDF-Expand`.
    - Use the **first** 32 bytes of `HDKF-Expand` as the ED25519 signing and certification master key.
    - Use the **last** 32 bytes of `HDKF-Expand` as the Curve25519 ECDH encryption subkey.
1. Derive the ED25519 and Curve25519 public keys for both master and subkeys.
    - The exact cryptographic procedure for public-key derivation and signatures is out-of-scope for this specification. See [the original Curve25519 paper](https://cr.yp.to/ecdh/curve25519-20060209.pdf) and [the original ED25519 paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf) by Daniel Bernstein and friends.
    - Most modern languages will have libraries available to perform this cryptography for you.
1. Build a PGP user ID (UID) string.
    - If `name` is defined, and `email` is not, set `uid = name`.
    - If `email` is defined, and `name` is not, set `uid = email`.
    - If both `name` and `email` are defined, set `uid = name + " <" + email + ">"`.
1. Use the master signing key to create a positive self-certification signature on the master key, committing to `uid` and `creation`.
    - If `expiry` is defined, commit the self-certification signature to that master key expiry time.
    - Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how this signature should be computed.
    - Call this `cert_sig`.
1. Use the master signing key to create a binding signature on the encryption subkey, committing to `creation`.
    - If `expiry` is defined, commit the binding signature to that as the subkey expiry time.
    - Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how this signature should be computed.
    - Call this `bind_sig`.
1. Serialize and return the following as OpenPGP packets:
    - [Master private key](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-secret-key-packet-formats)
        - If `password` was provided, encrypt the private key using OpenPGP's String-To-Key algorithm.
    - [`uid` (packet type 13)](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-user-id-packet-tag-13)
    - [`cert_sig`](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-signature-packet-tag-2)
    - [Encryption subkey](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-secret-key-packet-formats)
        - If `password` was provided, encrypt the private key using [OpenPGP's String-To-Key algorithm](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-string-to-key-usage).
    - [`bind_sig`](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-signature-packet-tag-2)

The resulting serialized binary blob is a usable OpenPGP private key, deterministically derived from the seed. It can be encoded to ASCII Armor format as an OpenPGP Private Key block for easy copy-pasting, or imported directly into an OpenPGP implementation like `gpg`.

### PGP Considerations and Parameters

- PGP keys and signature packets must be encoded with the OpenPGP version 4 format.
- Key derivation parameters should be set to SHA-256 and AES-256.
- The master key must be configured with Sign + Certify flags. Its algorithm must be set to EDDSA (`22`).
- The encryption subkey must be configured with Encrypt-Communications (`0x04`) Encrypt-Storage (`0x08`) flags. Its algorithm must be set to ECDH (`18`)
- The self-certification signature must use a positive-certification signature type (`0x13`).
- The subkey binding signature must use type `0x18`.
- Signatures should use SHA256 as the hashing function.
- Signature timestamps should be the same as the key `creation` timestamp to ensure signatures are determinstic regardless of when keys are recovered.

## Mnemonic Encoding

### Inputs

| Input | Description | Required |
|-------|-------------|----------|
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
1. Produce a checksum on `backupPayloadBytes` through a cyclic-redundancy-check (CRC) with a 7-bit output.
    - Use the Checksum Generator Polynomial $x^7 +x^6 +x^3 + x + 1$, also known as the CRC-7-MVB polynomial, to generate the checksum.
    - If your CRC implementation outputs numbers larger than 7 bits, make sure to take only the lowest order 7 bits, as the others will not change.
    - `checksum = 0x7F & crc.sum(backupPayloadBytes, poly=0x53)`
    - Example: the CRC-7-MVB checksum of `[0x62, 0x35, 0x43]` (`"b5c"` in UTF-8) is `0`.
1. Append the checksum by bitwise-OR-ing it into the backup payload.
    - `backupPayload = (backupPayload << 7) | checksum`
1. Break up the backup payload into 11-bit symbols.
    - $n$ should have been selected such that the total number of bits encoded $n + 30 + 7$ is evenly divisible by 11.
1. Interpret each 11-bit symbol as a big-endian integer, mapping to the word at that index in the BIP39 word list.
1. Return the resulting list of words.

## Design Motivation

OpenPGP keys are identified by their fingerprint, which is a hash of the serialized public key, including its creation time. That means in order to make deterministic key backup and recovery possible without invalidating the previous key's signatures, the creation time _must_ be encoded into the backup.

_We could also expect the user to provide a copy of the original public key when recovering since a OpenPGP public key packet would also contain the key creation timestamp, but it seemed counterintuitive to require the _public key_ to recover a _private key,_ so instead we keep everything necessary encoded in the recovery phrase._

ED25519 has a security level of 128 bits. Using more than 128 bits of seed entropy to generate ED25519 keys doesn't add extra security, and would increase the size of the recovery phrase making it more difficult to write down or memorize. Using _less_ than 128 bits of seed entropy would make keys more succeptible to brute-force attacks. Thus, we should use 128 bits as the default quantity of entropy needed to create an OpenPGP key.

Each word in a recovery phrase is one of 2048 different words, and thus encodes 11 bits of information. Therefore, the smallest number of words we can use to encode 128 bits of entropy is 12 words.

Key creation times in OpenPGP keys are represented as 32-bit unix timestamps. $128 + 32 = 160$ and $\frac{160}{11} = 14\frac{6}{11}$. Therefore, the minimum number of words we could use to encode a full 32-bit unix timestamp would be 15 words, leaving 5 unused bits.

We can save a bit more space by reducing the size of the key creation timestamp slightly. We don't need a full 32-bits of precision, since a very large chunk of time since the unix epoch on `1970-01-01` has already passed, and Mnemonikey was invented in 2022. If we define our own epoch, we can easily drop to 30 bits of precision, while retaining perfect second-level accuracy, and supporting key creation times until `2056-01-10`. This gives us some additional bits to play with: 7 to be exact. We can use these extra bits for a checksum.

We could reduce the size of the key creation timestamp much more by sacrificing timestamp granularity. If we were OK with per-day accuracy only, we could reduce the creation offset integer's size to 15-bits of precision, but this comes at the cost of privacy: Keys created with such granularity in their timestamp could be easily identified as having come from Mnemonikey.

## Mnemonic Bit-Map

This diagram demonstrates the bit-level layout of each word in the mnemonic, and how it encodes the backup payload and checksum.

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

