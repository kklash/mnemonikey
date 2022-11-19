package main

import (
	"errors"
	"flag"
	"fmt"
)

var (
	ErrPrintUsage         = errors.New("incorrect usage")
	ErrPrintUsageGraceful = errors.New("incorrect usage")
)

type Runner interface {
	Run(args []string) error
}

type Command[Options any] struct {
	Name          string
	Description   string
	UsageExamples []string
	AddFlags      func(*flag.FlagSet, *Options)
	Execute       func(flagInput *Options, positionalArgs []string) error
}

func (cmd *Command[Options]) Run(args []string) error {
	flags := flag.NewFlagSet(cmd.Name, flag.ExitOnError)

	var input Options
	if cmd.AddFlags != nil {
		cmd.AddFlags(flags, &input)
	}

	flags.Usage = func() {
		out := flags.Output()
		fmt.Fprintf(out, "%s\n\n", cmd.Name)
		if cmd.Description != "" {
			fmt.Fprintf(out, "%s\n\n", justifyTerminalWidth(2, cmd.Description))
		}
		if len(cmd.UsageExamples) > 0 {
			fmt.Fprintf(out, "Usage:\n")
			for _, line := range cmd.UsageExamples {
				fmt.Fprintf(out, "  %s\n", line)
			}
			fmt.Fprintf(out, "\n")
		}

		var hasFlags bool
		flags.VisitAll(func(_ *flag.Flag) { hasFlags = true })
		if hasFlags {
			fmt.Fprintf(out, "Options:\n")
			flags.PrintDefaults()
			fmt.Println()
		}
	}

	if len(args) == 1 && args[0] == "help" {
		flags.Usage()
		return nil
	}

	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := cmd.Execute(&input, flags.Args()); err != nil {
		if errors.Is(err, ErrPrintUsage) {
			flags.Usage()

			// avoid multiple parent Commands printing usage messages too
			return errors.New(err.Error())
		}
		return err
	}
	return nil
}
