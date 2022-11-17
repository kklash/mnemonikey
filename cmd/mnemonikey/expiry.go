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

func parseExpiry(now time.Time, input string) (time.Time, error) {
	badInputErr := fmt.Errorf("%w: %q", ErrInvalidDuration, input)

	if len(input) == 0 {
		return time.Time{}, badInputErr
	}

	unit, ok := durationUnits[strings.ToLower(input[len(input)-1:])]
	if !ok {
		// If no suffix provided, interpret input as an absolute unix timestamp
		timestamp, err := strconv.ParseUint(input, 10, 64)
		if err != nil {
			return time.Time{}, err
		}

		return time.Unix(int64(timestamp), 0), nil
	}

	quantity, err := strconv.ParseUint(input[:len(input)-1], 10, 64)
	if err != nil {
		return time.Time{}, badInputErr
	}

	return now.Add(time.Duration(quantity) * unit), nil
}
