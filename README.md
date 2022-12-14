# mnemonikey [![Unit Tests](https://github.com/kklash/mnemonikey/actions/workflows/test.yml/badge.svg)](https://github.com/kklash/mnemonikey/actions/workflows/test.yml)

### _Deterministic backup and recovery of PGP keys using human-readable phrases._

Save your PGP identity as a list of 15 English words. Use these words to recover lost keys or derive new subkeys.

|Generation|Recovery|
|----------|--------|
|![generate](https://user-images.githubusercontent.com/31221309/205517587-b7a063c5-f69b-43ca-abf5-cb4567ded058.gif)|![recover](https://user-images.githubusercontent.com/31221309/205517589-8f6d75b9-473c-4f61-9244-2b01466f0f02.gif)|

Mnemonikey allows you to back up your PGP keys without managing highly sensitive and awkward digital files, without any loss of security.

Mnemonikey deterministically derives a full set of PGP keys based on a secure, randomly generated seed. That seed (and the key creation timestamp) is then re-exported in the form of an **English phrase** which you can record on paper to fully back up your PGP key. The recovery phrase is encoded similarly to [how Bitcoin wallets are backed up](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), and even uses the same word list for better cross-compatibility (although the number of words in a Mnemonikey recovery phrase is different).

# :rotating_light: :warning: WARNING :warning: :rotating_light:

### The Mnemonikey specification is **NOT YET FINALIZED**.

Until this warning is removed, **DO NOT use Mnemonikey to generate PGP keys for real-world use.**

Please see [the discussions board](https://github.com/kklash/mnemonikey/discussions) to help with finalizing the Mnemonikey specification.

## PGP Key Backup Alternatives

|Backup Format|Secure By Default|Memorizable|Offline|Robust|
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

# Specification :scroll:

Here follows a specification which would allow anyone to re-implement `mnemonikey` in another language.

-------------

## Definitions

| Word | Definition |
|------|------------|
| PGP Key Set | A set of four PGP keys: the master key for certification, and three subkeys for signing, encryption, and authentication. |
| Mnemonikey Epoch | Midnight in UTC time on new year's eve between 2021 and 2022 (AKA `1640995200` in unix time). This is used to identify the absolute time encoded by the key creation offset. |
| Key Creation Offset | The number of seconds after the mnemonikey epoch when the PGP key set was created. This offset is serialized as a 30-bit unsigned integer in the backup payload. |
| Seed | A securely-generated random integer, containing 128 bits of entropy. |
| Backup Payload | The combination of a seed and key creation offset. Together, they form a backup payload, which can be used to fully recover a PGP key set. |
| Root Key | A 32-byte pseudo-random key derived from the seed and key creation time. |
| Recovery Phrase / Mnemonic Phrase | A sequence of 15 English words which encodes the backup payload and checksum. |
| Checksum Generator Polynomial | The CRC-32 IEEE generator polynomial. Used for checksumming the backup payload. ( $x^{32} + x^{26} + x^{23} + x^{22} + x^{16} + x^{12} + x^{11} + x^{10} + x^{8} + x^{7} + x^{5} + x^{4} + x^{2} + x + 1$ ) |

## Goals

Mnemonikey is primarily concerned with defining two high-level procedures:

- **Key Derivation:** Deterministically deriving a usable PGP key set from a seed and key creation time.
- **Mnemonic Encoding:** Encoding a seed and key creation time into a mnemonic phrase for later decoding & recovery.

## Dependencies

| Dependency | Usage |
|------------|-------|
|[The BIP39 English Word List](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)|Encodes the backup payload into a form that is easy to write down on paper, or remember mnemonically. Each word is one of 2048 potential words, thus encodes 11 bits of information.|
|[HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)|Stretches the root key into suitable PGP private keys. |
|[ED25519 (EdDSA)](https://ed25519.cr.yp.to/)|Algorithm used for the certification master key, and for the authentication and signing subkeys. Used to create signatures to bind the PGP key set together.|
|[Curve25519 (ECDH)](https://en.wikipedia.org/wiki/Curve25519)|Generates the encryption subkey.|
|[CRC (cyclic redundancy check)](https://en.wikipedia.org/wiki/Cyclic_redundancy_check)|Used for checksumming the backup payload.|
|[Argon2id](https://www.rfc-editor.org/rfc/rfc9106.html)|Memory-hard password hashing algorithm. Used to slow down brute-force attacks on derived keys. Version 1.3 is used.|

## Key Derivation

### Inputs

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`version`| A 2-bit version number. The current latest version number is `0`. | YES |
|`seed`| A securely-generated random integer with 128 bits of entropy. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **30-bit** unsigned integer. | YES |
|`name`| A human-readable display name used to build the PGP key's user-identifier string. | NO |
|`email`| An email address used to build the PGP key's user-identifier string. | NO |
|`ttl`| A time-to-live duration in seconds applied to the output PGP key set. | NO |
|`password`| A byte-array used to symmetrically encrypt the output PGP key set. | NO |
|`encSubkeyIndex`| A 16-bit integer which can be used to derive different encryption subkeys. | NO |
|`authSubkeyIndex`| A 16-bit integer which can be used to derive different authentication subkeys. | NO |
|`sigSubkeyIndex`| A 16-bit integer which can be used to derive different signing subkeys. | NO |

### Output

A serialized PGP private key set, containing a certification-enabled ED25519 master key, along with properly bound signing, encryption, and authentication subkeys.

- If `password` was provided, the output PGP key set's private keys will be encrypted symmetrically using OpenPGP's String-to-Key (S2K) protocol.
- If `ttl` was provided, the output PGP key set's keys will be set to expire at `ttl` seconds after the key creation time.
- If `name` and/or `email` was provided, they form the key's user-identifier (UID).

The keys will have been deterministically generated by the inputs.

### Procedure

1. If the `version` number is greater than `0`, fail with an unsupported version error.
1. Determine the exact key creation timestamp based on `creationOffset` by interpreting `creationOffset` as the number of seconds after the Mnemonikey Epoch.
    - `creation = creationOffset + 1640995200`
1. Derive the _root key_ from `seed` and `creation` using Argon2id.
    - The big-endian serialization of `seed` is used as the Argon2id password parameter:
        - `password = seed.to_bytes(16, 'big')`
    - The big-endian serialization of `creation` is used as the Argon2id salt parameter:
        - `salt = creation.to_bytes(4, 'big')`
    - The remaining Argon2id parameters are `time=4`, `memory=0x80000` (512MB), `threads=2`, and `keyLen=32`
    - `rootKey = argon2id(password, salt, time, memory, threads, keyLen)`
1. Derive the PGP master key and subkeys from `rootKey` using `HDKF-Expand`.
    - To derive the ED25519 master certification key, read 32 bytes from `HDKF-Expand` on `rootKey` using SHA256 with the string `"mnemonikey master key"` as the _info_ parameter.
    - For each of the subkeys, the `HKDF-Expand` _info_ parameter is built as follows:
        - Begin with the string `"mnemonikey TYPE subkey"`, where `TYPE` is replaced by any of `"encryption"`, `"authentication"`, or `"signing"` depending on the type of subkey.
        - Serialize and append a 16-bit big-endian subkey index parameter for the subkey (`encSubkeyIndex` for the encryption subkey, etc).
        - For example, to derive the encryption subkey at index `3`: `info = b"mnemonikey encryption subkey\x00\x03"`
    - To derive the Curve25519 ECDH encryption subkey, read 32 bytes from `HDKF-Expand` on `rootKey` using SHA256, with the _info_ parameter built as described above.
    - To derive the ED25519 authentication subkey, read 32 bytes from `HDKF-Expand` on `rootKey` using SHA256, with the _info_ parameter built as described above.
    - To derive the ED25519 signing subkey, read 32 bytes from `HDKF-Expand` on `rootKey` using SHA256, with the _info_ parameter built as described above.
1. Derive the ED25519 and Curve25519 public keys for the master key and subkeys.
    - The exact cryptographic procedure for public-key derivation and signatures is out-of-scope for this specification. See [the original Curve25519 paper](https://cr.yp.to/ecdh/curve25519-20060209.pdf) and [the original ED25519 paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf) by Daniel Bernstein and friends.
    - Most modern languages will have libraries available to perform this cryptography for you.
1. Build a PGP user ID (UID) string.
    - If `name` is defined, and `email` is not, set `uid = name`.
    - If `email` is defined, and `name` is not, set `uid = email`.
    - If both `name` and `email` are defined, set `uid = name + " <" + email + ">"`.
1. Use the master certification key to create a positive self-certification signature on the master key, committing to `uid` and `creation`.
    - If `ttl` is defined, use it to define the master key expiry time `creation + ttl`, and commit the self-certification signature to that expiry.
    - Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how this signature should be computed.
    - This signature should also commit to the symmetric cipher algorithm AES-256, and the hash algorithm SHA-256, as keyholder preferences.
    - Call this `certificationSig`.
1. Use the master certification key to create binding signatures on each subkey, committing to `creation`.
    - If `ttl` is defined, commit the binding signatures to `creation + ttl` as the subkey expiry time.
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
    - SHA-256 and AES-256 are also set as the hash and cipher preferences in the self-certification signature. This is not mandatory, but reduces the risk that software into which the key is imported will use outdated defaults like SHA1 and Tripe-DES, by providing a safe default set of algorithms which is usually available for most software. To overwrite these default preferences with your own in `gpg`, use `gpg --edit-key` and type `setpref`.
- The master key must be configured with the Certify flag. Its algorithm must be set to EDDSA (`22`).
- The encryption subkey must be configured with Encrypt-Communications (`0x04`) and Encrypt-Storage (`0x08`) flags. Its algorithm must be set to ECDH (`18`).
- The authentication subkey must be configured with the Authentication (`0x20`) flag. Its algorithm must be set to EDDSA (`22`).
- The signing subkey must be configured with the Signing (`0x02`) flag. Its algorithm must be set to EDDSA (`22`).
- The self-certification signature must use a positive-certification signature type (`0x13`).
- The subkey binding signatures must use type `0x18`.
- Signatures should use SHA256 as the hashing function.
- Signature timestamps should be the same as the key `creation` timestamp to ensure signatures are deterministic, regardless of when keys are recovered.
- If the caller wishes to only export a subset of the keys, for example to generate a new subkey and export it without also exposing the master key, the master key can be encoded as a private key stub using the GNU-Dummy S2K extension. No official docs seem to be available for this, however, as it is not an official part of the OpenPGP specification.

## Mnemonic Encoding

### Inputs

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`version`| A 2-bit version number. The current latest version number is `0`. | YES |
|`seed`| A securely-generated random integer with 128 bits of entropy. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **30-bit** integer. | YES |

### Output

An English phrase of 15 words which completely encodes the `version`, `seed`, and `creationOffset`.

### Procedure

1. Initialize an unsigned integer `backupPayload` starting with the 2-bit `version` number.
    - `backupPayload = version`
1. Append the 128-bit integer `seed` to `backupPayload` as the lowest-order bits.
    - `backupPayload = (backupPayload << 128) | seed`
1. Append the 30-bit integer `creationOffset` to `backupPayload` as the lowest-order bits.
    - `backupPayload = (backupPayload << 30) | creationOffset`
1. Serialize the `backupPayload` (now 160-bits long) as a big-endian byte array with length 20.
    - Call the result `backupPayloadBytes`
    - `backupPayloadBytes = backupPayload.to_bytes(20, 'big')`
1. Compute a 5-bit checksum on `backupPayloadBytes` using a cyclic-redundancy-check (CRC).
    - Use the Checksum Generator Polynomial to generate a 32-bit CRC.
    - Take the lowest order 5 bits of the CRC output.
    - `checksum = 0x1F & crc32(backupPayloadBytes)`
    - Example: The 5-bit checksum of `"hey"` in UTF-8 would be `0x1F & crc32([0x68, 0x65, 0x79]) = 16`
1. Append `checksum` to the lowest order bits of `backupPayload`.
    - `backupPayload = (backupPayload << 5) | checksum`
1. Chunk `backupPayload` into 11-bit symbols, with the highest-order bits as the first chunk.
    - `[(backupPayload >> (i*11)) & 0x7FF for i in reversed(range(15))]`
    - Note that the total `backupPayload` bit-length $2 + 128 + 30 + 5 = 165$ is evenly divisible by 11.
1. Interpret each 11-bit symbol as a big-endian integer, mapping to the word at that index in the BIP39 word list.
1. Return the resulting list of words.

To decode a mnemonic phrase into the `version`, `seed`, and `creationOffset`, simply reverse the algorithm. Upon decoding, a Mnemonikey implementation should ensure the checksum is correct and the `version` number is supported.

# Design Motivation :brain:

In this section, we elaborate on the motivation behind the different design choices implied by the above specification.

## Background

Normally, PGP key backups must be done manually by backing up private key export files, but files can be easily lost, corrupted, or deleted accidentally. Whenever new subkeys are added to the master key, the backup must be updated manually. This is a risky and error-prone practice, as I have personally discovered several times.

The [`paperkey`](https://www.jabberwocky.com/software/paperkey/) backup tool is also similarly fragile, as it involves either copying by-hand a large blob of hexadecimal numbers, or printing `paperkey`'s output to paper. Copying by-hand risks errors in duplication, and printing risks exposure of your private key material to a printer, which are not known for prioritizing security in their design: Many printers run outdated firmware, are wide-open by default on wireless networks, and [may cache plaintext copies of the documents they've printed, in memory or on-disk](https://www.cbsnews.com/news/digital-photocopiers-loaded-with-secrets/).

Many early users of [Bitcoin](https://bitcoin.org) also learned this lesson in a different context. In 2013, [mnemonic recovery phrases were invented to resolve it](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). They eventually became the norm for Bitcoin wallet backups.

|Bitcoin Recovery Phrase|`paperkey` Output|
|:-:|:-:|
|<img src="https://user-images.githubusercontent.com/31221309/204943520-481fb5a0-36fe-4329-ac12-dd271b8375aa.jpg">|<img src="https://user-images.githubusercontent.com/31221309/204945149-cce0de55-9a03-4d28-9839-32946be90d9e.png">|

<sub>On the left, a 12-word Bitcoin BIP39 recovery phrase written on paper. On the right, the output of [`paperkey`](https://www.jabberwocky.com/software/paperkey/). Which would you rather use to recover the root of your digital identity?</sub>

## Mission

The purpose of Mnemonikey is to securely and deterministically generate a PGP key, and export a backup which contains the minimum amount of information needed to repeat the key generation process. This backup can be used to recover the PGP key without adverse effects, much in the same way a BIP39 recovery phrase allows the bearer to re-derive the private keys in a cryptocurrency wallet.

## Creation Timestamps

OpenPGP keys are identified by their fingerprint, which is a hash of the serialized public key, including its creation time. That means in order to make deterministic key backup and recovery possible without invalidating the previous key's signatures, the creation time must either be encoded into the backup, or it must be a static constant used for all keys. We chose to encode the creation time into the backup, because having distinct key creation times is convenient and worth the extra few bits of information lengthening the backup.

Key creation times in OpenPGP keys are represented as 32-bit unix timestamps. We can save a bit more space by reducing the size of the key creation timestamp slightly. We don't need a full 32-bits of precision, since a very large chunk of time since the unix epoch on `1970-01-01` has already passed, and Mnemonikey was invented in 2022. If we define our own epoch, we can easily trim down to 30 bits of precision, while retaining perfect second-level accuracy, and supporting key creation times until `2056-01-10`. Hopefully by then, people will have adopted more advanced cryptography tools than PGP. If Mnemonikey is still in use by then, we can simply bump the version number and redefine the creation timestamp encoding rules, for example by defining a new epoch.

We could reduce the size of the key creation timestamp much more by sacrificing timestamp granularity. If we were OK with per-day accuracy only, we could reduce the creation offset integer's size to 15-bits of precision, but this comes at the cost of privacy: Keys created with such granularity in their timestamp could be easily identified as having come from Mnemonikey.

|Timestamp size|Words Needed|Ceiling (1s granularity)|Ceiling (1min granularity)|Ceiling (1h granularity)|Ceiling (1d granularity)|
|:------------:|:----------:|:----------------------:|:------------------------:|:----------------------:|:----------------------:|
|32 bits|15 words|`2158-02-06`|Very High|Very High|Very High|
|31 bits|15 words|`2090-01-18`|`6105-01-23`|Very High|Very High|
|30 bits|15 words|`2056-01-10`|`4063-07-13`|Very High|Very High|
|29 bits|15 words|`2039-01-05`|`3042-10-07`|Very High|Very High|
|28 bits|15 words|`2030-07-04`|`2532-05-20`|Very High|Very High|
|27 bits|15 words|`2026-04-03`|`2277-03-11`|Very High|Very High|
|26 bits|15 words|`2024-02-16`|`2149-08-06`|`9677-09-28`|Very High|
|25 bits|15 words|Too Low|`2085-10-18`|`5849-11-14`|Very High|
|24 bits|14 words|Too Low|`2053-11-24`|`3935-12-09`|Very High|
|23 bits|14 words|Too Low|`2037-12-13`|`2978-12-19`|Very High|
|22 bits|14 words|Too Low|`2029-12-22`|`2500-06-26`|Very High|
|21 bits|14 words|Too Low|`2025-12-27`|`2261-03-30`|`7763-10-22`|
|20 bits|14 words|Too Low|Too Low|`2141-08-15`|`4892-11-25`|
|19 bits|14 words|Too Low|Too Low|`2081-10-23`|`3457-06-14`|
|18 bits|14 words|Too Low|Too Low|`2051-11-27`|`2739-09-23`|
|17 bits|14 words|Too Low|Too Low|`2036-12-13`|`2380-11-11`|
|16 bits|14 words|Too Low|Too Low|`2029-06-23`|`2201-06-07`|
|15 bits|14 words|Too Low|Too Low|`2025-09-27`|`2111-09-19`|
|14 bits|14 words|Too Low|Too Low|Too Low|`2066-11-09`|
|13 bits|13 words|Too Low|Too Low|Too Low|`2044-06-05`|
|12 bits|13 words|Too Low|Too Low|Too Low|`2033-03-19`|
|11 bits|13 words|Too Low|Too Low|Too Low|`2027-08-10`|
|10 bits|13 words|Too Low|Too Low|Too Low|`2024-10-20`|
|9 bits|13 words|Too Low|Too Low|Too Low|Too Low|
|8 bits|13 words|Too Low|Too Low|Too Low|Too Low|

<details>
    <summary><i>Script to generate the above table</i></summary>

```python
#!/usr/bin/env python3

from datetime import datetime

column_names = [
  "Timestamp size",
  "Words Needed",
  "Ceiling (1s granularity)",
  "Ceiling (1min granularity)",
  "Ceiling (1h granularity)",
  "Ceiling (1d granularity)",
]

granularities = [1, 60, 60**2, 60**2 * 24]

epoch = 1640995200

rows = []

for ts_bits in reversed(range(8, 33)):
  n_words = (128 + ts_bits + 2 + 10) // 11

  row = ["%d bits" % ts_bits, "%d words" % n_words]

  for g in granularities:
    try:
      d = datetime.fromtimestamp(epoch + (1 << ts_bits)*g - 1)
      if d.year <= 2023:
        ceiling = "Too Low"
      else:
        ceiling = "`" + str(d.date()) + "`"
    except:
      ceiling = "Very High"
    row.append(ceiling)
  rows.append("|" + '|'.join(row) + "|")

header = "|" + "|".join(column_names) + "|"
delim =  "|" + "|".join([":" + "-" * (len(name)-2) + ":" for name in column_names]) + "|"

print('\n'.join([header, delim] + rows))
```
</details>

We might have chosen to require the user to provide a copy of the original public key when recovering, since an OpenPGP public key packet would also contain the key creation timestamp. This is the approach used by [`paperkey`](https://www.jabberwocky.com/software/paperkey/). However, it may be counterintuitive to the average PGP user to require the _public key_ to recover a _private key,_ so instead we keep a minimum of recovery information bundled in the recovery phrase, and restrict the generation process tightly so as to enforce determinism when the key is re-generated later. This choice also simplifies Mnemonikey implementations, because they do not need to be concerned with _parsing_ OpenPGP key packets, only _generating_ them.

## Curve Choice

We chose ED25519 as the elliptic curve for the output PGP keys because:

- Its keys are very small.
- It has excellent performance.
- It is designed to avoid common security pitfalls in downstream implementations.
- It is designed with 'nothing up my sleeve' parameters to reduce risk of a back-door.
- It is usable for signing, encryption, and authentication with SSH.
- Golang has first-class ED25519 and Curve25519 implementations available.

## Subkey Lifecycle

To allow cycling of subkeys, Mnemonikey can derive each type of subkey at any arbitrary index from 0 to 65535 (`0xFFFF`). Subkeys are always derived in parallel from the root key, and not from one-another. The only way to derive a new subkey is to use the root key, which can only be derived from the seed and creation time embedded in the recovery phrase.

<img src="https://user-images.githubusercontent.com/31221309/209289189-b6a7a536-9f87-4a72-819f-a5e7f8662869.png">

<!-- https://beta.tldraw.com/r/v2_c_8cvIL1LtquLf5X5fXFV8K -->

No subkey has any special preference or power over any other. When generated, any subkeys derived from the same seed will all have the same creation timestamp as the master key.

The master key cannot be used to re-derive any Mnemonikey subkeys, although it could be used to sign new non-deterministically generated subkeys out-of-band and bind them to the same user ID. **We recommend not to do this,** because any subkeys generated outside of Mnemonikey **cannot be re-generated** with the Mnemonikey recovery phrase later.

The normal use of subkeys involves revoking subkeys once they become compromised or outdated. To do this with Mnemonikey, one would revoke their old subkey at index $n$ using a downstream PGP tool (`gpg --edit uid` and type `key n`, and then type `revkey`). Then Mnemonikey can be used to generate a fresh subkey at index $n+1$. This derived subkey should be exported on its own, orphaned from the master key and other subkeys, and imported into the PGP keychain.

### Example

**Derive a new _signing_ subkey at index `1` with the `mnemonikey` CLI, and import it into a GPG keychain which already contains the related master key.**

```cli
$ mnemonikey recover -only signing -sig-index 1 -self-cert=false | gpg --import
```

#### Generate a master key and signing subkey (starts at default index 0).

<img width="700" src="https://user-images.githubusercontent.com/31221309/205466128-53f94d4d-7a6d-445b-8e5e-76001b859b43.gif">

#### Derive the new signing subkey at index 1, and revoke the old one at index 0.

<img width="700" src="https://user-images.githubusercontent.com/31221309/205466129-8f9528e8-0ee8-49ec-9f98-3197d79bc103.gif">

`-self-cert=false` is an optional flag which tells Mnemonikey not to output the master key's self-certification signature on the user ID. This is useful when minting new subkeys, in a situation where you already have the master key stored safely in your keyring. It prevents adding unneeded extra certification signatures to your keychain.

## Security

PGP keys derived by Mnemonikey are entirely determined by the 128 bits of entropy in the seed and the distinguishing (but predictable) key creation timestamp. Argon2id hashes the seed and key creation time into a 256-bit _root key._

Since the seed only bears 128 bits of entropy, and ED25519 private keys are 256-bit integers, there exists the potential for batched brute-force attacks which could yield some successful guesses across a large population of public keys. To mitigate this, we hash the key creation time as well, to add extra uniqueness to each key. The difficulty of the Argon2id password hashing function further reduces the feasibility of brute-force attacks by significantly increasing the time and memory cost of key derivation.

To derive a full set of four OpenPGP keys - the master certification key and the signing/encryption/authentication subkeys - we need a total of $256 \cdot 4 = 1024$ bits of secure key material. For this we use the [HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869) Expand function to expand the uniformly random _root key_ into four 256-bit private keys. Each key including the master certification key is derived flatly from the _root key,_ without any hierarchy.

## Encoding

Each word in a recovery phrase is one of 2048 ( $2^{11}$ ) different words, and thus encodes 11 bits of information. To encode a recovery phrase, we need to store both the entropy (128 bits) and the key creation time offset from the epoch (30 bits). $128 + 30 = 158$ and $\frac{158}{11} = 14\frac{4}{11}$. Therefore, the minimum number of words we could use to encode the full backup payload would be 15 words, leaving 7 unused bits.

These last 7 bits can be used for a **2-bit version number** and **5-bit checksum**.

This diagram demonstrates the **bit-level layout** of each word in the mnemonic, and how it encodes the backup payload and checksum. Each number from `0` to `a` (10) is an index of each of the 11 bits encoded by a word in the mnemonic.

```
version
 |---|----------------------------------- entropy ----------------------------------------
 |------- word 0 ------|------- word 1 ------|------- word 2 ------|------- word 3 ------|
  0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a


 ---------------------------------------- entropy ----------------------------------------
 |------- word 4 ------|------- word 5 ------|------- word 6 ------|------- word 7 ------|
  0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a


 ---------------------------------------- entropy ----------------------------------------
 |------- word 8 ------|------- word 9 ------|------- word 10 -----|------- word 11------|
  0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a


 ---- entropy -----|-------------------- creation timestamp -------------------|check-sum|
 |------- word 12 -----|------- word 13 -----|------- word 14 -----|------- word 15 -----|
  0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a 0 1 2 3 4 5 6 7 8 9 a
```

## Version Number

The version number tells Mnemonikey implementations how to decode the recovery phrase and derive the PGP keys from the backup payload. The version number may be incremented in the future, for example to fix a critical bug, support post-quantum key algorithms, or define a new key creation time epoch.

## Checksum

Words in a recovery phrase must already be members of the BIP39 wordlist to be considered valid, but on the off-chance a user enters another valid but incorrect word, a 5-bit checksum will provide error detection with a collision probability of roughly $\frac{1}{32}$. With a word list of 2048 valid words, that means there are only 64 possible collision-causing 1-word substitutions which the user could accidentally perform for each word in the phrase.

We chose to use 32-bit [cyclic-redundancy-checks](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) (CRC-32) with the IEEE generator polynomial as our checksum, because of its speed and ubiquitous availability. There are cross-compatible implementations available in the standard libraries of most programming languages, and numerous test vectors available should anyone need to re-implement it.

## Acknowledgments

Thanks to Chris Wellons (@skeeto) and [his awesome tool, `passphrase2pgp`](https://github.com/skeeto/passphrase2pgp) for inspiring me, and serving as a helpful reference for how PGP keys are serialized into packets.

Thanks to fellow PGP nerd Ryan Zimmerman (@ryanzim) for jamming with me to draft the specification.

## Donations

If you're interested in supporting development of this package, show your love by dropping me some bitcoins!

### `bc1qhct3hwt5pjmu75d2fldwd477vhwmthuqvmh03s`
