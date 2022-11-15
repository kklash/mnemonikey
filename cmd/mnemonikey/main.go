package main

import (
	"errors"
	"fmt"
	"os"
)

type RootOptions struct {
}

var subcommands = map[string]Runner{
	"generate": GenerateCommand,
	"recover":  RecoverCommand,
}

var RootCommand = &Command[RootOptions]{
	Name: "mnemonikey",
	Execute: func(_ *RootOptions, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("%w: missing subcommand", ErrPrintUsage)
		}

		if args[0] == "help" {
			return ErrPrintUsageGraceful
		}
		subcmd, ok := subcommands[args[0]]
		if !ok {
			return fmt.Errorf("%w: unknown subcommand %q", ErrPrintUsage, args[0])
		}
		return subcmd.Run(args[1:])
	},
}

func main() {
	err := RootCommand.Run(os.Args[1:])
	if err != nil && !errors.Is(err, ErrPrintUsageGraceful) {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
}
