package main

import (
	"errors"
	"flag"
)

var (
	ErrPrintUsage         = errors.New("incorrect usage")
	ErrPrintUsageGraceful = errors.New("incorrect usage")
)

type Runner interface {
	Run(args []string) error
}

type Command[Options any] struct {
	Name     string
	AddFlags func(*flag.FlagSet, *Options)
	Execute  func(flagInput *Options, positionalArgs []string) error
}

func (cmd *Command[Options]) Run(args []string) error {
	flags := flag.NewFlagSet(cmd.Name, flag.ExitOnError)
	var input Options
	if cmd.AddFlags != nil {
		cmd.AddFlags(flags, &input)
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := cmd.Execute(&input, flags.Args()); err != nil {
		if errors.Is(err, ErrPrintUsage) {
			flags.Usage()
		}
		return err
	}
	return nil
}
