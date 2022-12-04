package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidDuration = errors.New("invalid duration parameter")

var durationUnits = map[string]time.Duration{
	"d": time.Hour * 24,
	"w": time.Hour * 24 * 7,
	"m": time.Hour * 24 * 365 / 12,
	"y": time.Hour * 24 * 365,
}

func parseTTL(input string) (time.Duration, error) {
	badInputErr := fmt.Errorf("%w: %q", ErrInvalidDuration, input)

	if len(input) == 0 {
		return 0, badInputErr
	}

	unit, ok := durationUnits[strings.ToLower(input[len(input)-1:])]
	if !ok {
		return 0, badInputErr
	}

	quantity, err := strconv.ParseUint(input[:len(input)-1], 10, 64)
	if err != nil {
		return 0, badInputErr
	}

	return time.Duration(quantity) * unit, nil
}
