package main

import (
	"testing"
)

func TestCensor(t *testing.T) {

	badWords := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	cases := []struct {
		input    string
		expected string
	}{
		{
			input:    " ",
			expected: " ",
		},
		{
			input:    "  hello  kerfuffle",
			expected: "  hello  ****",
		},
		{
			input:    "  hello  world Sharbert!  ",
			expected: "  hello  world Sharbert!  ",
		},
		{
			input:    "  HellO  World  Fornax",
			expected: "  HellO  World  ****",
		},
	}

	for _, c := range cases {
		actual := getCleanedBody(c.input, badWords)
		if actual != c.expected {
			t.Errorf("Expected: '%v'. Got '%v'", c.expected, actual)
			continue
		}
	}
}
