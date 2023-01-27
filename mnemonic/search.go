package mnemonic

import (
	"strings"
)

// SearchResult is returned by the Search function. It indicates the suffixes
// which could complete the input query to make it a valid word in the wordlist,
// including the empty string if an exact match was found.
type SearchResult struct {
	// ExactMatch is true if the input query is a valid word in the wordlist.
	// Indicates that the first element of the Suffixes field will be the empty string.
	//
	// Note that finding an exact match does not necessarily mean it is the only
	// possible word. Some words are prefixes of others ("car" and "cargo").
	ExactMatch bool

	// Suffixes is a set of suffix strings which can be appended to the original
	// input query to make it a valid word in the wordlist.
	Suffixes []string
}

// Search runs a binary search on the wordlist to find any words which match
// the given input query string. This is useful for autocomplete and error correction.
//
// The input query must be in lower case to return any results.
func Search(query string) *SearchResult {
	result := &SearchResult{Suffixes: []string{}}
	if query == "" {
		return result
	}

	back := -1
	front := len(WordList)
	cursor := (front + back) / 2

	for {
		if strings.HasPrefix(WordList[cursor], query) {
			if query == WordList[cursor] {
				result.ExactMatch = true
			}

			beginIndex := 0
			endIndex := 0

			// Find prefix matching words before the cursor
			for beginIndex = cursor - 1; ; beginIndex-- {
				if beginIndex < 0 || !strings.HasPrefix(WordList[beginIndex], query) {
					beginIndex += 1
					break
				}
				if query == WordList[beginIndex] {
					result.ExactMatch = true
				}
			}

			// Find prefix matching words after the cursor
			for endIndex = cursor + 1; ; endIndex++ {
				if endIndex >= len(WordList) || !strings.HasPrefix(WordList[endIndex], query) {
					endIndex -= 1
					break
				}
				if query == WordList[endIndex] {
					result.ExactMatch = true
				}
			}

			result.Suffixes = make([]string, 1+endIndex-beginIndex)
			for j := range result.Suffixes {
				result.Suffixes[j] = strings.TrimPrefix(WordList[beginIndex+j], query)
			}
			return result
		}

		if query < WordList[cursor] {
			front = cursor
		} else {
			back = cursor
		}

		cursor = (front + back) / 2

		if cursor == front || cursor == back {
			return result
		}
	}
}
