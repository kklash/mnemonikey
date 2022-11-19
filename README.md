# mnemonikey

_Determinstic backup and recovery of PGP keys using human-readable phrases._

|Generation|Recovery|
|----------|--------|
|![generate](https://user-images.githubusercontent.com/31221309/202872648-77a7320a-b324-464a-84b1-767724f20b59.gif)|![recover](https://user-images.githubusercontent.com/31221309/202872652-62a68338-686f-4fff-aafa-a05818b394b3.gif)|


Mnemonikey allows you to back up your PGP keys without managing highly sensitive and awkward digital files, and without any loss of security.

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
