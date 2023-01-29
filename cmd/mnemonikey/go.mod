module github.com/kklash/mnemonikey/cmd/mnemonikey

go 1.19

replace github.com/kklash/mnemonikey => ../..

require (
	github.com/kklash/mnemonikey v0.0.0-00010101000000-000000000000
	github.com/kklash/wordlist4096 v0.0.0-20230128235818-1dcc136efd79
	golang.org/x/term v0.3.0
)

require (
	golang.org/x/crypto v0.4.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
)
