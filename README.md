# mnemonikey [![Unit Tests](https://github.com/kklash/mnemonikey/actions/workflows/test.yml/badge.svg)](https://github.com/kklash/mnemonikey/actions/workflows/test.yml)

### _Deterministic backup and recovery of PGP keys using human-readable phrases._

Save your PGP identity as a list of English words. Use these words to recover lost keys or derive new subkeys.

|Generation|Recovery|
|----------|--------|
|![generate](https://user-images.githubusercontent.com/31221309/215003912-3fce306d-1aca-442d-9dc5-63659f51fb46.gif)|![recover](https://user-images.githubusercontent.com/31221309/215003915-d05fa870-01c1-424a-a976-97a69c3e08c9.gif)|

Mnemonikey allows you to back up your PGP keys without managing highly sensitive and awkward digital files, without any loss of security.

Mnemonikey deterministically derives a full set of PGP keys based on a secure, randomly generated seed. That seed (and the key creation timestamp) is then re-exported in the form of an **English phrase** which you can record on paper to fully back up your PGP key. The recovery phrase is encoded similarly to [how Bitcoin wallets are backed up](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

# :rotating_light: :warning: WARNING :warning: :rotating_light:

### The Mnemonikey specification is **NOT YET FINALIZED**.

Until this warning is removed, **DO NOT use Mnemonikey to generate PGP keys for real-world use.**

Please see [the discussions board](https://github.com/kklash/mnemonikey/discussions) to help with finalizing the Mnemonikey specification.

## Features

- Keys are derived from a seed and creation time using modern, secure algorithms (Argon2id and HKDF).
- Recovery phrases include a version number to guarantee forwards-compatibility and long-term safety of your backup.
- Phrases are encoded with [a custom high-density wordlist](https://github.com/kklash/wordlist4096) with stronger guarantees than BIP39.
- Phrases include a checksum to confirm you entered the phrase correctly.
- Supports encrypted phrases. You can change or remove the password at any time by [converting phrases](#mnemonikey-convert).
- Easily auditable small code footprint: only \~4,000 lines of my source code (plus official Golang libraries).
- [Reproducible builds](#reproducible-builds) for security guarantees.
- [Supports subkey cycling](#subkey-lifecycle).
- Fancy colored terminal output (Let's be honest, this is the most important feature :sunglasses: ).

## PGP Key Backup Alternatives

|Backup Format|Secure By Default|Memorizable|Offline|Robust|
|:-----------:|:----:|:---------:|:-----:|:------------------------:|
|Secret Key File on a hard drive or SD card|:heavy_check_mark:|:x:|:x:|:x:|
|[`passphrase2pgp`](https://github.com/skeeto/passphrase2pgp)|:x:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|
|[`paperkey`](https://www.jabberwocky.com/software/paperkey/)|:white_check_mark: *|:x:|:heavy_check_mark:|:heavy_check_mark:|
|[`trezor-agent`](https://github.com/romanz/trezor-agent) <sub>(plus a hardware wallet)</sub> |:heavy_check_mark:|:white_check_mark: \*\*|:heavy_check_mark:|:heavy_check_mark:|
|**`mnemonikey`**|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|

<sub>\* `paperkey` printouts are only as secure as the printer used to print them.</sub>

<sub>\*\* `trezor-gpg` requires manual backup of the key creation timestamp.</sub>

## Installation

To use the `mnemonikey` command-line interface utility, first [install Golang](https://go.dev/dl), and then run:

```
$ go install github.com/kklash/mnemonikey/cmd/mnemonikey@latest
```

To use `mnemonikey` as a Golang library:
```
$ go get -u github.com/kklash/mnemonikey
```

API documentation for the Mnemonikey library is [available on `pkg.go.dev`](https://pkg.go.dev/github.com/kklash/mnemonikey).

## Saving the Source

In case this repository of Mnemonikey is ever taken down, it would be wise to also save a copy of the Mnemonikey source code to ensure you can recover your keys. The easiest way to do this is to:

1. [Install Golang](https://go.dev/dl)
1. Download a copy of this repository
1. Download all dependencies into the repo folder locally
1. Archive the whole directory and store it somewhere safe.

```
git clone https://github.com/kklash/mnemonikey.git
cd mnemonikey
go mod vendor
cd ..
zip -r mnemonikey{.zip,}
cp mnemonikey.zip /path/to/safe/location
```

Alternatively you could:

- Download a copy of [this repository](https://github.com/kklash/mnemonikey/archive/refs/heads/main.zip) and of [the `wordlist4096` repository](https://github.com/kklash/wordlist4096/archive/refs/heads/main.zip).
- Fork this repository and [`wordlist4096`](https://github.com/kklash/wordlist4096).
- Create another implementation of the Mnemonikey specification in another language - I'd be flattered!

### Reproducible Builds

You can compile [reproducible builds](https://reproducible-builds.org/) of the `mnemonikey` CLI tool for all platforms by executing the [`repro-build.sh` script](./repro-build.sh). The resulting binaries will be exactly the same file as those built by anyone else using the same `go` compiler version to build the same source code - even when cross-compiling across platforms.

Note that these reproducible builds are compiled with [CGO](https://go.dev/blog/cgo) disabled, meaning they will be slightly less performant than a build with CGO enabled would be. Mnemonikey is not a performance-critical application, so most users will not notice any difference. It is, however, a _security-critical_ application. A maliciously built version of `mnemonikey` could expose a user's PGP key, or generate weak keys which an attacker could predict.

With a small primary codebase and only a couple of dependencies, anyone can quickly audit Mnemonikey's codebase and dependencies for malicious interference or supply chain attacks. Once the source code is confirmed to be secure, a reproducibly compiled binary offers the guarantee that, _[as long as the compiler is sound](https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf),_ so too is the binary. Thus, any user can verify the distributed builds of `mnemonikey` were compiled honestly, using the same source code, without relying on the integrity of the maintainer of this repository ([me](https://github.com/kklash)).

## Background

Traditionally, PGP key backups are done manually by backing up private key export files. Files can be easily lost, corrupted, or deleted accidentally. Whenever new subkeys are added to the master key, the backup must be updated manually. This is a risky and error-prone practice, as I have personally discovered several times.

The [`paperkey`](https://www.jabberwocky.com/software/paperkey/) backup tool is also similarly fragile, as it involves either copying by-hand a large blob of hexadecimal numbers, or printing `paperkey`'s output to paper. Copying by-hand risks errors in duplication, and printing risks exposure of your private key material to a printer, which are not known for prioritizing security. Many printers run outdated firmware, are wide-open by default on wireless networks, and [may cache plaintext copies of the documents they've printed, in memory or on-disk](https://www.cbsnews.com/news/digital-photocopiers-loaded-with-secrets/).

Many early users of [Bitcoin](https://bitcoin.org) also learned this lesson in a different context. In 2013, [mnemonic recovery phrases were standardized to resolve it](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). They eventually became the norm for Bitcoin wallet backups. Almost every Bitcoin wallet in popular use today exports keys in the form of a mnemonic recovery phrase.

|Bitcoin Recovery Phrase|`paperkey` Output|
|:-:|:-:|
|<img src="https://user-images.githubusercontent.com/31221309/204943520-481fb5a0-36fe-4329-ac12-dd271b8375aa.jpg">|<img src="https://user-images.githubusercontent.com/31221309/204945149-cce0de55-9a03-4d28-9839-32946be90d9e.png">|

<sub>On the left, a 12-word Bitcoin BIP39 recovery phrase written on paper. On the right, the output of [`paperkey`](https://www.jabberwocky.com/software/paperkey/). Which would you rather use to recover the root of your digital identity?</sub>

## Usage

The `mnemonikey` CLI tool has several subcommands. Each subcommand has its own sets of command-line options.

<img src="https://github.com/kklash/mnemonikey/assets/31221309/9fa8a5ea-2477-4a25-a981-6ccd4d0ddaf1">

<!-- https://github.com/kklash/mnemonikey/files/11667171/mnemonikey-flow.tldr.zip -->

The above chart illustrates the role of each Mnemonikey command by showing the flow from initial key generation through recovery and phrase conversion.

Below are additional details on each individual command.

### `mnemonikey generate`

Generates a fresh seed and derives a set of PGP keys therefrom. Invoking `mnemonikey generate` will write an ASCII-armor encoded set of freshly-generated PGP private keys to standard output, and will export a plaintext recovery phrase to standard error. This phrase can be used to fully recover the exact same PGP key.\*

<sub>\* There may be slight differences between original and recovered keys if different flags are given when using the `recover` subcommand later. For instance, one might supply a different user ID, or define a different key expiry (TTL). If these mismatches occur, they are little more than a minor annoyance. In most cases, PGP client software will simply merge two such PGP keys, e.g. by keeping both user IDs on the key, when importing them.</sub>

Note that the PGP key is derived from the seed, but this process cannot be reversed; One cannot convert a PGP key back into a Mnemonikey recovery phrase. This means that the recovery phrase is only available once, upon calling `mnemonikey generate`. As such, it is imperative to write down the recovery phrase immediately.

Additional flags for the `generate` subcommand include options to define the user ID (`-name` and `-email`), set key expiry (`-ttl`), or enable encryption either of the keys (`-encrypt-keys`) or of the recovery phrase (`-encrypt-phrase`).

For full details of all available options, see the output of `mnemonikey generate -h` or `mnemonikey generate --help`.

### `mnemonikey recover`

Recovers a set of PGP keys from an existing recovery phrase. Invoking `mnemonikey recover` will prompt the user to enter the recovery phrase into an interactive terminal prompt. By default, the prompt supports auto-complete of words. Autocomplete suggestions can be accepted by pressing Tab, and words can be submitted by pressing Enter or Space. Incorrectly submitted words can be revised by hitting the left arrow key.

The `recover` subcommand processes the seed and creation time embedded in the recovery phrase, and re-derives PGP keys therefrom.

Recovery phrases are designed for long term storage and future-proofing. [The recovery phrase contains a version number](#version-numbers) which allows future versions of Mnemonikey to identify the exact algorithm used to derive the keys. This means that even if Mnemonikey is upgraded in the future to introduce new recovery phrase formats, an old existing phrase will always derive the same PGP keys, and one need not worry about finding an old out-of-date version of Mnemonikey.

[Each recovery phrase contains a checksum](#checksum) which will help identify any errors made during entry. To ensure the phrase is written down correctly, it is wise to attempt a recovery immediately from the saved phrase after generating a fresh key.

Note that while recovering, a user will need to provide the `-name` and `-email` parameters anew to construct the user ID on the recovered key, as these identifiers are not embedded in the recovery phrase.

When recovering a key, one can tell `mnemonikey` to derive keys at different indices than the keys output by `mnemonikey generate`. This allows cycling of subkeys. [See the Subkey Lifecycle section below for more info.](#subkey-lifecycle)

For full details of all available options, see the output of `mnemonikey recover -h` or `mnemonikey recover --help`.

### `mnemonikey convert`

Converts a recovery phrase from one format to another. Mnemonikey supports [encrypted recovery phrases](#encrypted-phrases) which allow the holder to protect their seed with a custom password. This password can be changed, removed, or added, by using the `mnemonikey convert` subcommand to convert an old phrase into a new one.

For example, one can use `mnemonikey convert` to convert a plaintext recovery phrase into one which is encrypted with a password, or the reverse. It can also decrypt an encrypted recovery phrase and output the equivalent plaintext recovery phrase. Or it can convert an encrypted recovery phrase into another encrypted phrase with a different password. Each format of the phrase embeds the same seed and creation timestamp, and thus will derive the same PGP keys.

Converting a phrase to add or change a password **does not invalidate any previous phrases.** Any existing encrypted or plaintext recovery phrases will still be perfectly usable as they previously were. If one of your recovery phrases may have been exposed, you should immediately endorse a new PGP key and revoke the one whose seed may have been exposed. See the [Encrypted Phrases](#encrypted-phrases) section for more info.

For full details of all available options, see the output of `mnemonikey convert -h` or `mnemonikey convert --help`.


# Design Motivation :brain:

In this section, we elaborate on the motivation behind the different design choices implied by the [Mnemonikey Specification](#specification-scroll).

## Mission

The purpose of Mnemonikey is to securely and deterministically derive a PGP key, and export a backup which contains the minimum amount of information needed to repeat the key derivation process. This backup can be used to recover the PGP key without adverse effects, much in the same way a BIP39 recovery phrase allows the bearer to re-derive the private keys in a cryptocurrency wallet.

## Creation Timestamps

OpenPGP keys are identified by their fingerprint, which is a hash of the serialized public key, including its creation time. That means in order to make deterministic key backup and recovery possible without invalidating the previous key's signatures, the creation time must either be encoded into the backup, or it must be a static constant used for all keys. We chose to encode the creation time into the backup, because having distinct key creation times is convenient and worth the extra few bits of information lengthening the backup.

Key creation times in OpenPGP keys are represented as 32-bit unix timestamps. We can save a bit more space by reducing the size of the key creation timestamp slightly. We don't need a full 32-bits of precision, since a very large chunk of time since the unix epoch on `1970-01-01` has already passed, and Mnemonikey was invented in 2023. If we define our own epoch, we can easily trim down to 31 bits of precision, while retaining perfect second-level accuracy, and supporting key creation times until `2091-01-18`. Hopefully by then, people will have adopted more advanced cryptography tools than PGP. If Mnemonikey is still in use by then, we can simply bump the version number and redefine the creation timestamp encoding rules, for example by defining a new epoch.

We could reduce the size of the key creation timestamp much more by sacrificing timestamp granularity. If we were OK with per-day accuracy only, we could reduce the creation offset integer's size to 15-bits of precision, but this comes at the cost of privacy: Keys created with such granularity in their timestamp could be easily identified as having come from Mnemonikey.

|Timestamp size|Words Needed|Ceiling (1s granularity)|Ceiling (1min granularity)|Ceiling (1h granularity)|Ceiling (1d granularity)|
|:------------:|:----------:|:----------------------:|:------------------------:|:----------------------:|:----------------------:|
|32 bits|14 words|`2159-02-06`|Very High|Very High|Very High|
|31 bits|14 words|`2091-01-18`|`6106-01-23`|Very High|Very High|
|30 bits|14 words|`2057-01-09`|`4064-07-12`|Very High|Very High|
|29 bits|14 words|`2040-01-05`|`3043-10-07`|Very High|Very High|
|28 bits|14 words|`2031-07-04`|`2533-05-20`|Very High|Very High|
|27 bits|14 words|`2027-04-03`|`2278-03-11`|Very High|Very High|
|26 bits|14 words|`2025-02-15`|`2150-08-06`|`9678-09-28`|Very High|
|25 bits|14 words|`2024-01-24`|`2086-10-18`|`5850-11-14`|Very High|
|24 bits|13 words|Too Low|`2054-11-24`|`3936-12-08`|Very High|
|23 bits|13 words|Too Low|`2038-12-13`|`2979-12-19`|Very High|
|22 bits|13 words|Too Low|`2030-12-22`|`2501-06-26`|Very High|
|21 bits|13 words|Too Low|`2026-12-27`|`2262-03-30`|`7764-10-21`|
|20 bits|13 words|Too Low|`2024-12-28`|`2142-08-15`|`4893-11-25`|
|19 bits|13 words|Too Low|Too Low|`2082-10-23`|`3458-06-14`|
|18 bits|13 words|Too Low|Too Low|`2052-11-26`|`2740-09-22`|
|17 bits|13 words|Too Low|Too Low|`2037-12-13`|`2381-11-11`|
|16 bits|13 words|Too Low|Too Low|`2030-06-23`|`2202-06-07`|
|15 bits|13 words|Too Low|Too Low|`2026-09-27`|`2112-09-18`|
|14 bits|13 words|Too Low|Too Low|`2024-11-13`|`2067-11-09`|
|13 bits|13 words|Too Low|Too Low|Too Low|`2045-06-05`|
|12 bits|12 words|Too Low|Too Low|Too Low|`2034-03-19`|
|11 bits|12 words|Too Low|Too Low|Too Low|`2028-08-09`|
|10 bits|12 words|Too Low|Too Low|Too Low|`2025-10-20`|
|9 bits|12 words|Too Low|Too Low|Too Low|`2024-05-26`|
|8 bits|12 words|Too Low|Too Low|Too Low|Too Low|

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

epoch = 1672531200

rows = []

for ts_bits in reversed(range(8, 33)):
  n_words = (128 + ts_bits + 4 + 11) // 12

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

Below is a flow chart illustrating how individual PGP keys are derived from the seed and key creation timestamp.

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

<img width="700" src="https://github.com/kklash/mnemonikey/assets/31221309/6b5c4de0-0898-4829-b751-dcea5a6560cc">

#### Derive the new signing subkey at index 1, and revoke the old one at index 0.

<img width="700" src="https://github.com/kklash/mnemonikey/assets/31221309/6420d764-7ba3-42ac-994d-e31317598057">

`-self-cert=false` is an optional flag which tells Mnemonikey not to output the master key's self-certification signature on the user ID. This is useful when minting new subkeys, in a situation where one already has the master key stored safely in a PGP keyring. It prevents adding unneeded extra certification signatures to the keychain.

## Security

PGP keys derived by Mnemonikey are entirely determined by the 128 bits of entropy in the seed and the distinguishing (but predictable) key creation timestamp. Argon2id hashes the seed and key creation time into a 256-bit _root key._

Since the seed only bears 128 bits of entropy, and ED25519 private keys are 256-bit integers, there exists the potential for batched brute-force attacks which could yield some successful guesses across a large population of public keys. To mitigate this, we hash the key creation time as well, to add extra uniqueness to each key. The difficulty of the Argon2id password hashing function further reduces the feasibility of brute-force attacks by significantly increasing the time and memory cost of key derivation.

To derive a full set of four OpenPGP keys - the master certification key and the signing/encryption/authentication subkeys - we need a total of $256 \cdot 4 = 1024$ bits of secure key material. For this we use the [HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869) Expand function to expand the uniformly random _root key_ into four 256-bit private keys. Each key including the master certification key is derived flatly from the _root key,_ without any hierarchy.

### Encrypted Phrases

Encrypted phrases offer additional protection from accidental exposure or theft of a recovery phrase.

We could have chosen to follow the classic BIP39 mechanism of password-derived keys, where keys would be derived by hashing a user-specified password with the seed entropy. In this paradigm, a 'plaintext' phrase would be a recovery phrase plus an empty password. Using any other password would derive a completely different PGP key set. This allows one recovery phrase to be used to derive multiple PGP key sets, by using multiple unique derivation passwords. Each particular output PGP key set would be _tightly bound_ to the password and seed entropy which derived it.

This approach has some flaws. Notably, it doesn't work very well for our specific domain of PGP keys. Unlike with Bitcoin wallets, most people only ever need one PGP master key. Having the ability to derive more PGP master keys by changing the derivation password can actually be counterintuitive. Most people are used to password-based logins, which either succeed or fail. In a BIP39-like derivation scheme, any password is allowed, and the user would have to check the output PGP key fingerprint to ensure they used the correct password and derived the expected keys. Having worked on a cryptocurrency wallet myself in the past, I am intimately familiar with the confusion this causes for non-expert users.

Furthermore, a BIP39-like derivation scheme doesn't allow _changing passwords,_ and is not cross-compatible with plaintext backups. If you create a PGP key set which is derived from a specific seed and password, the keys _can only ever be recovered with that same seed and password._ If you ever want to change the password - or remove it entirely - you're out of luck and would have to take enormous effort to swap your whole digital identity to a whole new PGP key derived from your _new_ password.

Rather than binding a password tightly to the PGP key, _encrypted phrases_ on the other hand, are more like a layer of protection _on top_ of a plaintext recovery phrase. With encrypted phrases, a user can decide at any point to re-export their recovery phrase with a new password. They can update their paper backups to use this new phrase encrypted with the new password, but keep the same resulting PGP key set. Similarly, someone with a plaintext recovery phrase could at any point choose to update their recovery phrase with password-protection (and vice-versa).

Using encrypted phrases does have a small drawback: We must now include a `salt` value in the backup payload, to ensure the same password does not always hash to the same encryption key, thus reducing the feasibility of pre-computation attacks. This increases the size of the recovery phrase, but the additional flexibility is well worth it.

We also further salt the password hash with the key creation time, to further distinguish the seed encryption keys of different users.

**The encryption on a recovery phrase is not meant to protect a publicly available phrase for a long period of time, but to protect a physically secure phrase for a short period of time.** It is suitable only to give a victim enough time to endorse a new freshly generated PGP key and revoke her old exposed PGP key. This must be done before an attacker can brute-force the password. It is *not* intended to protect the seed while it is exposed publicly on some insecure platform for long stretches of time - e.g. stored in Google Docs or DropBox. To achieve security in that scenario, a suitably (read: ridiculously) strong password with at least 128 bits of entropy should be used.

19 bits of salt was determined to be the best trade-off between brevity and security. A shorter salt is acceptable. Most likely, if your recovery phrase is exposed, you will probably know about it. E.g. [your safety deposit box was broken into](https://www.latimes.com/california/story/2021-06-09/fbi-beverly-hills-safe-deposit-boxes-forfeiture-cash-jewelry), or [someone accidentally published a picture of your recovery phrase online](https://twitter.com/lopp/status/1604599964713328640)). It will presumably be rare and challenging for an adversary to acquire your encrypted recovery phrase. This contrasts with salted password hashes, which are commonly stored in bulk on networked cloud databases, and are frequently leaked. As such the size of the salt is less critical.

To give the decoder some indication of whether the password was correct or not, we also want some kind of checksum on the decrypted seed or on the encryption key.

Using an _actual checksum_ - like CRC-32, which we use for the mnemonic phrase - might leak data about the seed or its encryption key. Instead we simply derive one extra byte from Argon2id when hashing the user's password, and use a few bits from that as the checksum. This way, the checksum is still derived from the password and salt, but doesn't leak any information about the seed, nor about the key used to decrypt the seed.

## Encoding

Each word in a recovery phrase is one of 4096 ( $2^{12}$ ) different words, and thus encodes 12 bits of information. To encode a plaintext recovery phrase, at minimum we need to store both the entropy (128 bits) and the key creation time offset from the epoch (31 bits).

$128 + 31 = 159$ and $\frac{159}{12} = 13\frac{3}{12}$. Therefore, the minimum number of words we could use to encode the full backup payload would be 14 words, leaving 9 unused bits. These last 9 bits can be used for a **4-bit version number** and **5-bit checksum**.

For encrypted recovery phrases, we must also encode a `salt` value and a small checksum (`encSeedVerify`) in addition to the other fields. If we allot the same 5-bit checksum size for `encSeedVerify` as for the phrase checksum itself, we can now choose for `salt` a bit-size which is some multiple of $12n + 7$. So we could choose 7 bits, 19 bits, 31 bits, etc. For a balance of security and brevity, we selected 19 bits.

This diagram demonstrates the **bit-level layout** of each word in a plaintext mnemonic recovery phrase, and how it encodes the backup payload and checksum. Each number from `0` to `b` (11) is an index of each of the 12 bits encoded by a word in the mnemonic.

```
|-- version --|------------------------------------ seed -------------------------------------
|------------------ word 0 -------------------|------------------- word 1 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


-------------------------------------------- seed --------------------------------------------
|------------------ word 2 -------------------|------------------- word 3 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


-------------------------------------------- seed --------------------------------------------
|------------------ word 4 -------------------|------------------- word 5 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


-------------------------------------------- seed --------------------------------------------
|------------------ word 6 -------------------|------------------- word 7 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


-------------------------------------------- seed --------------------------------------------
|------------------ word 8 -------------------|------------------- word 9 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


-------------------- seed --------------------|--------------- creationOffset ----------------
|------------------ word 10 ------------------|------------------- word 11 ------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


----------------------------- creationOffset -----------------------------|---- checksum ----|
|------------------ word 12 ------------------|------------------- word 13 ------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b
```

|Field|Size|
|:-:|:-:|
|`version`|4 bits|
|`seed`|128 bits|
|`creationOffset`|31 bits|
|`checksum`|5 bits|
|---|---|
|**Total**|168 bits|
|**Words Needed**|$\frac{168}{12}=14$|

This is an equivalent diagram and table showing the encoding layout of an encrypted phrase.

```
|-- version --|----------------------------------- encSeed -----------------------------------
|------------------ word 0 -------------------|------------------- word 1 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


------------------------------------------ encSeed -------------------------------------------
|------------------ word 2 -------------------|------------------- word 3 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


------------------------------------------ encSeed -------------------------------------------
|------------------ word 4 -------------------|------------------- word 5 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


------------------------------------------ encSeed -------------------------------------------
|------------------ word 6 -------------------|------------------- word 7 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


------------------------------------------ encSeed -------------------------------------------
|------------------ word 8 -------------------|------------------- word 9 -------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


------------------- encSeed ------------------|-------------------- salt ---------------------
|------------------ word 10 ------------------|------------------- word 11 ------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


---------- salt ----------|-- encSeedVerify --|--------------- creationOffset ----------------
|------------------ word 12 ------------------|------------------- word 13 ------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b


---------------------------- creationOffset ------------------------------|---- checksum ----|
|------------------ word 12 ------------------|------------------- word 13 ------------------|
0   1   2   3   4   5   6   7   8   9   a   b   0   1   2   3   4   5   6   7   8   9   a   b
```

|Field|Size|
|:-:|:-:|
|`version`|4 bits|
|`encSeed`|128 bits|
|`salt`|19 bits|
|`encSeedVerify`|5 bits|
|`creationOffset`|31 bits|
|`checksum`|5 bits|
|---|---|
|**Total**|192 bits|
|**Words Needed**|$\frac{192}{12}=16$|


## Wordlist

To read more about the wordlist used to encode the Mnemonikey recovery phrases, [check out the separate `wordlist4096` repository](https://github.com/kklash/wordlist4096).

## Version Numbers

The version numbers embedded in mnemonic recovery phrases tell Mnemonikey implementations how to decode a recovery phrase and derive the PGP keys from the backup payload. The version number may be incremented in the future - for example, to fix a critical bug, support post-quantum key algorithms, or define a new key creation time epoch.

The `era` number is distinct from the mnemonic `version` number.

- Era numbers describe _how to derive PGP keys from a seed and creation time._
- Version numbers describe _how to decode a recovery phrase into a seed and creation time._

Version numbers map many-to-one into era numbers, so that a decoder can know which procedure to use to recover a PGP key set after decoding.

The current latest era number is `0`.

The only two version numbers which currently exist are `0` (denoting a standard plaintext recovery phrase) and `1` (denoting an encrypted recovery phrase). Both of these versions imply era `0`.

Version numbers within an Era are cross-compatible: You can convert between recovery phrases in the same era without losing compatibility or changing the resulting PGP key set derived from the seed.

Era numbers are not cross-compatible. If we change the procedure for recovering a PGP key set, this will fundamentally change the resulting PGP key set that we derive. As such, a key generated with a specific era can never be converted to a different era - although it could be converted between recovery phrase versions within its own era.

## Checksum

Words in a recovery phrase must already be members of the wordlist to be considered valid, but on the off-chance a user enters another valid but incorrect word, a 5-bit checksum will provide error detection with a collision probability of roughly $\frac{1}{32}$. With a word list of 4096 valid words, that means there are 128 possible collision-causing 1-word substitutions which the user could accidentally perform for each word in the phrase.

We chose to use 32-bit [cyclic-redundancy-checks](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) (CRC-32) with the IEEE generator polynomial as our checksum, because of its speed and ubiquitous availability. There are cross-compatible implementations available in the standard libraries of most programming languages, and numerous test vectors available should anyone need to re-implement it.


# Specification :scroll:

Here follows a detailed technical specification of Mnemonikey's key derivation and encoding algorithms.

-------------

## Goals

Mnemonikey is primarily concerned with defining two high-level procedures:

- **Key Derivation:** Deterministically deriving a usable PGP key set from a seed and key creation time.
- **Mnemonic Encoding:** Encoding a seed and key creation time into a mnemonic phrase for later decoding & recovery.

## Definitions

| Word | Definition |
|------|------------|
| PGP Key Set | A set of four PGP keys: the master key for certification, and three subkeys for signing, encryption, and authentication. |
| Mnemonikey Epoch | Midnight in UTC time on new year's eve between 2022 and 2023 (AKA `1672531200` in unix time). This is used to identify the absolute time encoded by the key creation offset. |
| Key Creation Offset | The number of seconds after the Mnemonikey Epoch when the PGP key set was created. This offset is serialized as a 31-bit unsigned integer in the backup payload. |
| Seed | A securely-generated random integer, containing 128 bits of entropy. |
| Backup Payload | The combination of a seed and key creation offset. Together, they form a backup payload, which can be used to fully recover a PGP key set. |
| Root Key | A 32-byte pseudo-random key derived from the seed and key creation time. |
| Recovery Phrase / Mnemonic Phrase | A sequence of English words which encodes the backup payload and checksum. |
| Checksum Generator Polynomial | The CRC-32 IEEE generator polynomial. Used for checksumming the backup payload. ( $x^{32} + x^{26} + x^{23} + x^{22} + x^{16} + x^{12} + x^{11} + x^{10} + x^{8} + x^{7} + x^{5} + x^{4} + x^{2} + x + 1$ ) |

## Dependencies

| Dependency | Usage |
|------------|-------|
|[`wordlist4096`](https://github.com/kklash/wordlist4096)|An English word list for mnemonic encoding. Encodes the backup payload into a form that is easy to write down on paper, or remember mnemonically. Each word is one of 4096 potential words, thus encodes 12 bits of information.|
|[HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)|Stretches the root key into suitable PGP private keys. |
|[ED25519 (EdDSA)](https://ed25519.cr.yp.to/)|Algorithm used for the certification master key, and for the authentication and signing subkeys. Used to create signatures to bind the PGP key set together.|
|[Curve25519 (ECDH)](https://en.wikipedia.org/wiki/Curve25519)|Generates the encryption subkey.|
|[CRC (cyclic redundancy check)](https://en.wikipedia.org/wiki/Cyclic_redundancy_check)|Used for checksumming the backup payload.|
|[Argon2id](https://www.rfc-editor.org/rfc/rfc9106.html)|Memory-hard password hashing algorithm. Used to slow down brute-force attacks on derived keys. Version 1.3 is used.|

## Standards

Before diving into the exact specification for derivation and encoding, we must first agree on some notation and common standards which will be used when handling data.

### Fixed Bit Sizes

All serializable integer values have fixed sizes which indicate the maximum number of bits which can be used to represent them in memory. Usually these sizes are specified explicitly.

Sometimes we explicitly cast unsigned integers to fixed-size types for clarity. For example, extracting the least-significant 4 bits of a number and casting it as a fixed-size 4-bit integer:

```python
uint4(n & 0xF)
```

### Concatenation

When operating on unsigned integers, the `||` operator denotes bitwise concatenation. Explicitly:

```python
x || y = (x << y.bitSize()) | y
```

...where `bitSize()` is a method which returns the fixed bit-size of `y`. The fixed bit-size of an integer is always explicitly given in this specification, _unless_ the number is the result of concatenation.

After concatenation, the fixed bit size of a concatenated number is the sum of the bit lengths of its composite numbers `x` and `y`.

```python
(x || y).bitSize() = x.bitSize() + y.bitSize()
```

### Serialization

When serializing fixed-size integers to byte arrays, **big-endian representations are always used.** If there is any unused space left over in a serialized byte array, these unused bits are always left as the most significant bits, and are set to zero.

For example, a 32-bit unsigned integer representing the number `1592` would be represented in binary as:

```
00000000000000000000011000111000
```

This would serialize as the following byte array:

```python
[0x00, 0x00, 0x06, 0x1C]
```

The serialization process will be denoted by invoking a `bytes()` function on the integer value. E.g.

```python
bytes(uint32(1592)) = [0x00, 0x00, 0x06, 0x1C]
```

The reverse deserialization process - decoding an integer from a byte array - will be denoted by invoking a `uint()` function on the byte array value:

```python
uint([0x00, 0x00, 0x06, 0x1C]) = uint32(1592)
```

The fixed-size of the resulting unsigned integer will be 8 times the length of the serialized byte array.

## Key Derivation

The key derivation process deterministically constructs PGP keys from input seed data.

### Inputs

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`era`| An integer enum for versioning. The era describes how the inputs should be derived into keys. The current latest era number is `0`. New era numbers may be defined in the future which change the inner workings of Mnemonikey PGP key derivation. | YES |
|`seed`| A securely-generated random unsigned integer with 128 bits of entropy. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **31-bit** unsigned integer. | YES |
|`name`| A human-readable display name used to build the PGP key's user-identifier string. | NO |
|`email`| An email address used to build the PGP key's user-identifier string. | NO |
|`ttl`| A time-to-live duration in seconds applied to the output PGP key set. | NO |
|`password`| A byte-array used to symmetrically encrypt the output PGP key set. | NO |
|`encSubkeyIndex`| A 16-bit integer which can be used to derive different encryption subkeys. | NO |
|`authSubkeyIndex`| A 16-bit integer which can be used to derive different authentication subkeys. | NO |
|`sigSubkeyIndex`| A 16-bit integer which can be used to derive different signing subkeys. | NO |

### Output

A serialized PGP private key set, containing a certification-enabled ED25519 master key, along with properly bound signing, encryption, and authentication subkeys.

If `password` was provided, the output PGP key set's private keys will be encrypted symmetrically using OpenPGP's String-to-Key (S2K) protocol.

If `ttl` was provided, the output PGP key set's keys will be set to expire at `ttl` seconds after the key creation time.

If `name` and/or `email` was provided, they form the key's user-identifier (UID).

The keys will have been deterministically generated by the inputs. Repeating the same process with the same inputs will yield the exact same serialized PGP keys.

### Procedure

1. If the `era` number is greater than `0`, fail with an unsupported version error.
2. Determine the exact key creation timestamp based on `creationOffset` by interpreting `creationOffset` as the number of seconds after the Mnemonikey Epoch.

    ```python
    creation = creationOffset + 1672531200
    ```

3. Derive the _root key_ from `seed` and `creation` using Argon2id.

    The big-endian serialization of `seed` is used as the Argon2id password parameter:

    ```python
    password = bytes(seed)
    ```

    The big-endian serialization of `creation` is used as the Argon2id salt parameter:

    ```python
    salt = bytes(creation)
    ```

    The remaining Argon2id parameters are `time=4`, `memory=0x80000` (512MB), `threads=2`, and `keyLen=32`.

    ```python
    rootKey = argon2id(password, salt, time, memory, threads, keyLen)
    ```

4. Derive the PGP master key and subkeys from `rootKey` using `HKDF-Expand`.

    To derive the ED25519 master certification key, read 32 bytes from `HKDF-Expand` on `rootKey` using SHA256, with the string `"mnemonikey master key"` as the _info_ parameter.

    For each of the subkeys, the `HKDF-Expand` _info_ parameter is built as follows:

    - Begin with the string `"mnemonikey TYPE subkey"`, where `TYPE` is replaced by any of `"encryption"`, `"authentication"`, or `"signing"` depending on the type of subkey.
    - Serialize and append a 16-bit big-endian subkey index parameter for the subkey. Use `encSubkeyIndex` for the encryption subkey, `authSubkeyIndex` for the authentication subkey, etc.

    <br>

    > Example: To derive the encryption subkey at index `3`
    >
    > ```python
    > info = b"mnemonikey encryption subkey\x00\x03"
    > ```

    To derive the Curve25519 ECDH encryption subkey, read 32 bytes from `HKDF-Expand` on `rootKey` using SHA256, with the _info_ parameter built as described above.

    To derive the ED25519 authentication subkey, read 32 bytes from `HKDF-Expand` on `rootKey` using SHA256, with the _info_ parameter built as described above.

    To derive the ED25519 signing subkey, read 32 bytes from `HKDF-Expand` on `rootKey` using SHA256, with the _info_ parameter built as described above.

5. Compute the ED25519 and Curve25519 public keys for the master key and subkeys.

    The exact cryptographic procedure for public-key derivation and signatures is out-of-scope for this specification. See [the original Curve25519 paper](https://cr.yp.to/ecdh/curve25519-20060209.pdf) and [the original ED25519 paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf) by Daniel Bernstein and friends.

    Most modern languages will have libraries available to perform this cryptography for you.

6. Build a PGP user ID (UID) string.

    If `name` is defined, and `email` is not, use `name` as the user ID.

    ```python
    uid = name
    ```

    If `email` is defined, and `name` is not, use `email` as the user ID.

    ```python
    uid = email
    ```

    If both `name` and `email` are defined, combine both with the email inside angle brackets to form the user ID.

    ```python
    uid = name + " <" + email + ">"
    ```

7. Use the master certification key to create a positive self-certification signature on the master key, committing to `uid` and `creation`.

    If `ttl` is defined, use it to define the master key expiry time `creation + ttl`, and commit the self-certification signature to that expiry. This signature should also commit to the symmetric cipher algorithm AES-256, and the hash algorithm SHA-256, as keyholder preferences.

    Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how this signature should be computed.

    Call this `certificationSig`.

8. Use the master certification key to create binding signatures on each subkey, committing to `creation`.

    If `ttl` is defined, commit the binding signatures to `creation + ttl` as the subkey expiry time.

    Refer to [the OpenPGP packet format specification](https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures) to see how these signatures should be computed.

    Call these `encryptionBindSig`, `authenticationBindSig`, and `signingBindSig` for the encryption, authentication, and signing subkeys respectively.

9. Serialize and return the following as OpenPGP packets:
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

There are two flavors of mnemonic encoding: _plaintext_ and _encrypted_.

- Plaintext mnemonic recovery phrases contain everything needed to re-derive PGP keys from scratch - specifically, the plaintext `seed`, the `creationOffset`, and a version number which maps to the `era`. They should be used if highly secure physical storage is available for the paper backup, or if you intend to memorize the resulting phrase.
- Encrypted mnemonic recovery phrases contain the same plaintext version number and `creationOffset`, but use symmetric AES encryption with a small salt to protect the seed from physical theft. To decrypt the seed, the user must know a password which is defined at backup-creation time. Decryption keys are derived by hashing the password, the salt, and the creation time with Argon2id.

These two formats have slightly different encoding and decoding procedures.

### Inputs

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`seed`| A securely-generated random unsigned integer with 128 bits of entropy. | YES |
|`creationOffset`| The number of seconds after the Mnemonikey Epoch when the key was created. Represented by a **31-bit** unsigned integer. | YES |

For encrypted phrases, the following extra parameters are required:

| Input | Description | Required |
|:-----:|:-----------:|:--------:|
|`password`| A user-supplied encryption passphrase. | Only for encrypted phrases |
|`salt`| A random 19-bit number used to salt the encryption process. | Only for encrypted phrases |

### Output

An English phrase of words which completely encodes the `seed`, and `creationOffset`, as well as a version number to tell the decoder how to process the encoded material.

Plaintext phrases will be 14 words long and will contain the plaintext `seed`.

Encrypted phrases will be 16 words long, and the `seed` contained therein will have been encrypted with a key derived from the `password`, `salt`, and `creationOffset`.

### Procedure

1. Set the 4-bit `version` number.
    - For plaintext recovery phrases, `version = uint4(0)`.
    - For encrypted recovery phrases, `version = uint4(1)`.

> ### If exporting an encrypted mnemonic recovery phrase
>
> Derive an encryption key and checksum byte from the `password` using Argon2id.
>
> The salt parameter for Argon2id is the 19-bit `salt` input value, with the `creationOffset` appended as the least significant bits. This combined 50-bit integer is then big-endian serialized to 7 bytes and used as the Argon2id salt.
>
> ```python
> encSeedSalt = bytes(salt || creationOffset)
> ```
>
> The remaining Argon2id parameters are `time=4`, `memory=0x80000` (512MB), `threads=2`, and `keyLen=17`.
>
> Run Argon2id on these parameters and call the result `encSeedKey`.
>
> ```python
> encSeedKey = argon2id(password, encSeedSalt, time, memory, threads, keyLen)
> ```
>
> Encrypt the big-endian serialization of `seed` with AES-128-ECB using the first 16 bytes of `encSeedKey` as the key. Interpret this encrypted seed as an unsigned integer. Call this `encSeed`.
>
> ```python
> encSeed = uint(aes128ecb(bytes(seed), encSeedKey[:16]))
> ```
>
> Extract the least significant 5 bits of `encSeedKey[16]`. These trailing bits of `encSeedKey` will be used as a checksum to later provide an accuracy-check on the password upon decryption. Call this `encSeedVerify`.
>
> ```python
> encSeedVerify = uint5(encSeedKey[16] & 0x1F)
> ```
>
> For the remainder of the process, use the concatenation of `encSeed`, `salt`, and `encSeedVerify` in place of the plaintext `seed`:
>
> ```python
> seed = encSeed || salt || encSeedVerify
> ```

2. Construct the base payload by bitwise-concatenating the `version`, `seed`, and `creationOffset`.

    ```python
    payload = version || seed || creationOffset
    ```

    `payload` will thus be a 163 bit integer if `seed` is plaintext, or 187 bits if `seed` is encrypted. The most significant bits of `payload` will be the most significant bits of the version number. The least significant bits of `payload` will be the least significant bits of the `creationOffset`.

3. Encode this payload into a byte array. This byte array will have length 21 if the `seed` is plaintext, or length 24 if the `seed` is encrypted.

    ```python
    payloadBytes = bytes(payload)
    ```

    **The most significant 5 bits of `payloadBytes` will always be zero, owing to the fixed sizes of the integers involved.**

4. Compute a 5-bit checksum on `payloadBytes` using a cyclic-redundancy-check (CRC), using the 32-bit Checksum Generator Polynomial. Use only the 5 least significant bits of the CRC output.

```python
checksum = uint5(crc32(payloadBytes) & 0x1F)
```

> Example: The 5-bit checksum of the string `"hey"` in UTF-8 would be `crc32([0x68, 0x65, 0x79]) & 0x1F = 16`

5. Append the checksum to the payload.

    ```python
    payload = payload || checksum
    ```

    Note that in either plaintext or encrypted cases, the bit-length of `payload` will now be evenly divisible by 12.

6. Chunk `payload` into 12-bit unsigned integers, with the most significant bits as the first chunk. This will result in an array of 14 integers for plaintext recovery phrases, or an array of 16 integers for encrypted phrases.

    ```python
    nWords = 14 if version == 0 else 16
    indices = [uint12((backupPayload >> (i*12)) & 0xFFF) for i in reversed(range(nWords))]
    ```

7. Interpret each 12-bit integer as an index mapping to the word at that index in the [4096-word long mnemonic encoding wordlist](https://github.com/kklash/wordlist4096).

    ```python
    words = [wordlist[n] for n in indices]
    ```

8. Return the resulting list of words.


### Decoding

To decode a mnemonic phrase into the `version`, `seed`, and `creationOffset`, simply reverse the encoding algorithm. Upon decoding, a Mnemonikey implementation should ensure:

- No words are accepted unless present in the wordlist
- The checksum is correct
- The `version` number is supported
- The word count is appropriate for the version number embedded in the first word.

If a decoder detects an encrypted phrase:

- Decoders should check that the password given by the user hashes to produce an encryption key which shares the same 5 `encSeedVerify` checksum bits.
- Decoders may end up accepting invalid passwords with a $\frac{1}{2^5}$ probability, due to the limited 5-bit size of the `encSeedVerify` checksum bits.

## Acknowledgments

Thanks to Chris Wellons ([@skeeto](https://github.com/skeeto)) and [his awesome tool, `passphrase2pgp`](https://github.com/skeeto/passphrase2pgp) for inspiring me, and serving as a helpful reference for how PGP keys are serialized into packets.

Thanks to fellow PGP nerd Ryan Zimmerman ([@ryanzim](https://github.com/ryanzim)) for jamming with me to draft the specification.

## Donations

If you're interested in supporting development of this package, show your love by dropping me some bitcoins!

### `bc1qhct3hwt5pjmu75d2fldwd477vhwmthuqvmh03s`
